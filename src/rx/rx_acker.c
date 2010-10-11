#include <afsconfig.h>
#include <afs/param.h>

#include <stddef.h>

#include <rx/rx.h>
#include <assert.h>

#ifdef RX_ENABLE_LOCKS
extern afs_kmutex_t rx_refcnt_mutex;

struct ackEntry {
    struct opr_queue qheader;
    struct rx_call *call;
    struct rx_packet *packet;
};

struct xmitQueue {
    struct opr_queue queue;
    afs_kmutex_t mutex;
    afs_kcondvar_t condvar;
};

struct freePacketQueue {
    struct rx_queue queue;
    afs_kmutex_t mutex;
};

struct freeEntryQueue {
    struct opr_queue queue;
    afs_kmutex_t mutex;
};

struct xmitQueue ackerXmitQueue;
struct freePacketQueue ackerFreePacketQueue;
struct freeEntryQueue ackerFreeEntryQueue;

void 
rxi_InitAckQueue(void) {
    MUTEX_INIT(&ackerFreePacketQueue.mutex, "free ack packet queue",
	       MUTEX_DEFAULT, 0);
    queue_Init(&ackerFreePacketQueue.queue);
    MUTEX_INIT(&ackerFreeEntryQueue.mutex, "free ack entry queue",
	       MUTEX_DEFAULT, 0);
    opr_queue_Init(&ackerFreeEntryQueue.queue);
    MUTEX_INIT(&ackerXmitQueue.mutex, "ack transmit queue",
	       MUTEX_DEFAULT, 0);
    CV_INIT(&ackerXmitQueue.condvar, "ack transmit queue",
	    CV_DEFAULT, 0);
    opr_queue_Init(&ackerXmitQueue.queue);
}

void *
rxi_ProcessAckQueue(void *args) {
    struct ackEntry *entry;

    MUTEX_ENTER(&ackerXmitQueue.mutex);

    while (1) {
    	while (!opr_queue_IsEmpty(&ackerXmitQueue.queue)) {
	    entry = opr_queue_First(&ackerXmitQueue.queue,
				    struct ackEntry, qheader);
	    opr_queue_Remove(&entry->qheader);
	    MUTEX_EXIT(&ackerXmitQueue.mutex);

/*	    printf("Sending ack with sequence %d (packet %p)\n",
		   entry->packet->header.seq,
		   entry->packet); */

	    rxi_SendPacket(entry->call, entry->call->conn, entry->packet, 0);

	    MUTEX_ENTER(&ackerFreePacketQueue.mutex);
	    queue_Append(&ackerFreePacketQueue.queue, entry->packet);
	    MUTEX_EXIT(&ackerFreePacketQueue.mutex);

	    entry->packet->flags &= ~RX_PKTFLAG_XMIT_PENDING;

	    entry->packet = NULL; /* Disposed of it above */

	    /* Release any call reference counts that we claimed */
	    MUTEX_ENTER(&rx_refcnt_mutex);
	    CALL_RELE(entry->call, RX_CALL_REFCOUNT_ACK);
	    MUTEX_EXIT(&rx_refcnt_mutex);

	    entry->call = NULL;

	    MUTEX_ENTER(&ackerFreeEntryQueue.mutex);
	    opr_queue_Append(&ackerFreeEntryQueue.queue, &entry->qheader);
	    MUTEX_EXIT(&ackerFreeEntryQueue.mutex);
	
	    MUTEX_ENTER(&ackerXmitQueue.mutex);
	}
	CV_WAIT(&ackerXmitQueue.condvar, &ackerXmitQueue.mutex);
    }
    return NULL;
}

static void
rxi_AddAckToQueue(struct rx_call *call, struct rx_packet *packet) {
    struct ackEntry *entry = NULL;

    MUTEX_ENTER(&ackerFreeEntryQueue.mutex);
    if (!opr_queue_IsEmpty(&ackerFreeEntryQueue.queue)) {
	entry = opr_queue_First(&ackerFreeEntryQueue.queue,
				struct ackEntry, qheader);
	opr_queue_Remove(&entry->qheader);
    }
    MUTEX_EXIT(&ackerFreeEntryQueue.mutex);

    if (!entry)
	entry = rxi_Alloc(sizeof(struct ackEntry));

    MUTEX_ENTER(&rx_refcnt_mutex);
    CALL_HOLD(call, RX_CALL_REFCOUNT_ACK);
    MUTEX_EXIT(&rx_refcnt_mutex);

    entry->call = call;
    entry->packet = packet;

    entry->packet->flags |= RX_PKTFLAG_XMIT_PENDING;

    MUTEX_ENTER(&ackerXmitQueue.mutex);
    opr_queue_Append(&ackerXmitQueue.queue, &entry->qheader);
    CV_BROADCAST(&ackerXmitQueue.condvar);
    MUTEX_EXIT(&ackerXmitQueue.mutex);
}
#endif

struct rx_packet *
rxi_GetAckPacket(struct rx_packet *optionalPacket) {

#ifdef RX_ENABLE_LOCKS
    struct rx_packet *p = NULL;

    MUTEX_ENTER(&ackerFreePacketQueue.mutex);
    if (!queue_IsEmpty(&ackerFreePacketQueue.queue)) {
	p = queue_First(&ackerFreePacketQueue.queue, rx_packet);
	queue_Remove(p);
    }
    MUTEX_EXIT(&ackerFreePacketQueue.mutex);
    if (!p) 
	p = rxi_AllocPacket(RX_PACKET_CLASS_SPECIAL);
    else {
/*	printf("Got packet %p from free queue\n", p); */
	rx_computelen(p, p->length);
    }

    return p;
#else
    if (optionalPacket) {
	rx_computelen(optionalPacket, optionalPacket->length);
	return optionalPacket;
    }

    return rxi_AllocPacket(RX_PACKET_CLASS_SPECIAL);
#endif
}

void
rxi_FreeAckPacket(struct rx_packet *packet,
		  struct rx_packet *optionalPacket)
{
#ifdef RX_ENABLE_LOCKS
    if (!packet->flags & RX_PKTFLAG_XMIT_PENDING) { 
    	MUTEX_ENTER(&ackerFreePacketQueue.mutex);
    	queue_Append(&ackerFreePacketQueue.queue, packet);
    	MUTEX_EXIT(&ackerFreePacketQueue.mutex);
    }
#else
    if (packet != optionalPacket)
	rxi_FreePacket(packet);
#endif
}

void
rxi_TransmitAck(struct rx_call *call, struct rx_packet *packet, int istack)
{
#ifdef RX_ENABLE_LOCKS
    int reason;

    packet->header.userStatus = call->localStatus;
    RXS_SendPacket(call->conn->securityObject, call, packet);
    rxevent_Cancel(call->delayedAckEvent, call, RX_CALL_REFCOUNT_DELAY);

    rxi_AddAckToQueue(call, packet);

    reason = ((struct rx_ackPacket *)rx_DataOf(packet))->reason;
    if (reason == RX_ACK_PING ||
	(packet->length 
	     <= rx_AckDataSize(call->rwind) + 4 * sizeof(afs_int32)))
    {
	call->conn->lastSendTime = call->lastSendTime = clock_Sec();
	if (reason != RX_ACK_PING && reason != RX_ACK_PING_RESPONSE)
	    call->lastSendData = call->lastSendTime;
    }
#else
    rxi_Send(call, packet, istack);
#endif
}

