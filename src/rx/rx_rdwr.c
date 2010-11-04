 /*
  * Copyright 2000, International Business Machines Corporation and others.
  * All Rights Reserved.
  *
  * This software has been released under the terms of the IBM Public
  * License.  For details, see the LICENSE file in the top-level source
  * directory or online at http://www.openafs.org/dl/license10.html
  */

#include <afsconfig.h>
#ifdef KERNEL
#include "afs/param.h"
#else
#include <afs/param.h>
#endif


#ifdef KERNEL
#ifndef UKERNEL
#ifdef RX_KERNEL_TRACE
#include "rx_kcommon.h"
#endif
#if defined(AFS_DARWIN_ENV) || defined(AFS_XBSD_ENV)
#include "afs/sysincludes.h"
#else
#include "h/types.h"
#include "h/time.h"
#include "h/stat.h"
#if defined(AFS_AIX_ENV) || defined(AFS_AUX_ENV) || defined(AFS_SUN5_ENV)
#include "h/systm.h"
#endif
#ifdef	AFS_OSF_ENV
#include <net/net_globals.h>
#endif /* AFS_OSF_ENV */
#ifdef AFS_LINUX20_ENV
#include "h/socket.h"
#endif
#include "netinet/in.h"
#if defined(AFS_SGI_ENV)
#include "afs/sysincludes.h"
#endif
#endif
#include "afs/afs_args.h"
#include "afs/afs_osi.h"
#if	(defined(AFS_AUX_ENV) || defined(AFS_AIX_ENV))
#include "h/systm.h"
#endif
#else /* !UKERNEL */
#include "afs/sysincludes.h"
#endif /* !UKERNEL */
#ifdef RXDEBUG
#undef RXDEBUG			/* turn off debugging */
#endif /* RXDEBUG */

#include "rx_kmutex.h"
#include "rx/rx_kernel.h"
#include "rx/rx_clock.h"
#include "rx/rx_queue.h"
#include "rx/rx.h"
#include "rx/rx_globals.h"
#include "afs/lock.h"
#include "afsint.h"
#ifdef  AFS_OSF_ENV
#undef kmem_alloc
#undef kmem_free
#undef mem_alloc
#undef mem_free
#endif /* AFS_OSF_ENV */
#else /* KERNEL */
# include <sys/types.h>
#ifdef AFS_NT40_ENV
# include <winsock2.h>
#else /* !AFS_NT40_ENV */
# include <sys/socket.h>
# include <sys/file.h>
# include <netdb.h>
# include <netinet/in.h>
# include <sys/stat.h>
# include <sys/time.h>
#endif /* !AFS_NT40_ENV */
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
# include "rx_user.h"
# include "rx_clock.h"
# include "rx_queue.h"
# include "rx.h"
# include "rx_globals.h"
#endif /* KERNEL */

#ifdef RX_LOCKS_DB
/* rxdb_fileID is used to identify the lock location, along with line#. */
static int rxdb_fileID = RXDB_FILE_RX_RDWR;
#endif /* RX_LOCKS_DB */

/* Free any packets from the last call to ReadvProc/WritevProc */
static_inline void
rxi_call_clearIovec(struct rx_call_service *callSvc) {
    if (queue_IsNotEmpty(&callSvc->iovq)) {
#ifdef RXDEBUG_PACKET
        callSvc->iovqc -=
#endif /* RXDEBUG_PACKET */
            rxi_FreePackets(0, &callSvc->iovq);
    }
}

/* rxi_ReadProc -- internal version.
 *
 * LOCKS USED -- called at netpri
 *
 * Called only from the service thread
 */
int
rxi_ReadProc(struct rx_call *call, char *buf,
	     int nbytes)
{
    struct rx_call_service *callSvc = &call->service;
    struct rx_packet *cp = callSvc->currentPacket;
    struct rx_packet *rp;
    int requestCount;
    unsigned int t;

    requestCount = nbytes;

    rxi_call_clearIovec(callSvc);

    do {
	if (callSvc->nLeft == 0) {
	    /* Get next packet */
	    MUTEX_ENTER(&call->lock);
	    for (;;) {
		if (call->error || (call->mode != RX_MODE_RECEIVING)) {
		    if (call->error) {
                        call->mode = RX_MODE_ERROR;
			MUTEX_EXIT(&call->lock);
			return 0;
		    }
		    if (call->mode == RX_MODE_SENDING) {
                        MUTEX_EXIT(&call->lock);
			rxi_FlushWrite(call);
                        MUTEX_ENTER(&call->lock);
			continue;
		    }
		}
		if (queue_IsNotEmpty(&call->receiveBuffer)) {
		    afs_int32 error;
		    struct rx_connection *conn = call->conn;
    		    rp = queue_First(&call->receiveBuffer, rx_packet);

		    queue_Remove(rp);
#ifdef RX_TRACK_PACKETS
		    rp->flags &= ~RX_PKTFLAG_RQ;
#endif
#ifdef RXDEBUG_PACKET
                    call->rqc--;
#endif /* RXDEBUG_PACKET */

		    /* RXS_CheckPacket called to undo RXS_PreparePacket's
		     * work.  It may reduce the length of the packet by up
		     * to conn->maxTrailerSize, to reflect the length of the
		     * data + the header. */
		    if ((error 
			= RXS_CheckPacket(conn->securityObject, call, rp))) {
			/* Used to merely shut down the call, but now we
			 * shut down the whole connection since this may
			 * indicate an attempt to hijack it */

			MUTEX_EXIT(&call->lock);
			rxi_ConnectionError(conn, error);
			MUTEX_ENTER(&conn->conn_data_lock);
			rp = rxi_SendConnectionAbort(conn, rp, 0, 0);
			MUTEX_EXIT(&conn->conn_data_lock);
			rxi_FreePacket(rp);

			return 0;
		    }
		    cp = callSvc->currentPacket = rp;
#ifdef RX_TRACK_PACKETS
		    callSvc->currentPacket->flags |= RX_PKTFLAG_CP;
#endif
		    callSvc->curvec = 1;	/* 0th vec is always header */
		    /* begin at the beginning [ more or less ], continue
		     * on until the end, then stop. */
		    callSvc->curpos = (char *)cp->wirevec[1].iov_base
			              + call->conn->securityHeaderSize;
		    callSvc->curlen = cp->wirevec[1].iov_len
			    	      - call->conn->securityHeaderSize;

		    /* Notice that this code works correctly if the data
		     * size is 0 (which it may be--no reply arguments from
		     * server, for example).  This relies heavily on the
		     * fact that the code below immediately frees the packet
		     * (no yields, etc.).  If it didn't, this would be a
		     * problem because a value of zero for call->nLeft
		     * normally means that there is no read packet */
		    callSvc->nLeft = cp->length;
		    hadd32(call->bytesRcvd, cp->length);

	     	    break;
		}

                /*
                 * If we reach this point either we have no packets in the
                 * receive queue or the next packet in the queue is not the
                 * one we are looking for.  There is nothing else for us to
                 * do but wait for another packet to arrive.
                 */

		/* Are there ever going to be any more packets? */
		if (call->flags & RX_CALL_RECEIVE_DONE) {
		    MUTEX_EXIT(&call->lock);
		    return requestCount - nbytes;
		}
		/* Wait for in-sequence packet */
		call->flags |= RX_CALL_READER_WAIT;
		clock_NewTime();
		call->startWait = clock_Sec();
		while (call->flags & RX_CALL_READER_WAIT) {
#ifdef	RX_ENABLE_LOCKS
		    CV_WAIT(&call->cv_rq, &call->lock);
#else
		    osi_rxSleep(&call->rq);
#endif
		}
                cp = callSvc->currentPacket;

		call->startWait = 0;
#ifdef RX_ENABLE_LOCKS
		if (call->error) {
		    MUTEX_EXIT(&call->lock);
		    return 0;
		}
#endif /* RX_ENABLE_LOCKS */
	    }
	    MUTEX_EXIT(&call->lock);
	} else
	    /* osi_Assert(cp); */
	    /* MTUXXX  this should be replaced by some error-recovery code before shipping */
	    /* yes, the following block is allowed to be the ELSE clause (or not) */
	    /* It's possible for call->nLeft to be smaller than any particular
	     * iov_len.  Usually, recvmsg doesn't change the iov_len, since it
	     * reflects the size of the buffer.  We have to keep track of the
	     * number of bytes read in the length field of the packet struct.  On
	     * the final portion of a received packet, it's almost certain that
	     * call->nLeft will be smaller than the final buffer. */
	    while (nbytes && cp) {
		t = MIN((int)callSvc->curlen, nbytes);
		t = MIN(t, (int)callSvc->nLeft);
		memcpy(buf, callSvc->curpos, t);
		buf += t;
		nbytes -= t;
		callSvc->curpos += t;
		callSvc->curlen -= t;
		callSvc->nLeft -= t;

		if (!callSvc->nLeft) {
		    /* out of packet.  Get another one. */
#ifdef RX_TRACK_PACKETS
		    callSvc->currentPacket->flags &= ~RX_PKTFLAG_CP;
#endif
		    rxi_FreePacket(cp);
		    cp = callSvc->currentPacket = NULL;
		} else if (!callSvc->curlen) {
		    /* need to get another struct iov */
		    if (++callSvc->curvec >= cp->niovecs) {
			/* current packet is exhausted, get ready for another */
			/* don't worry about curvec and stuff, they get set somewhere else */
#ifdef RX_TRACK_PACKETS
			callSvc->currentPacket->flags &= ~RX_PKTFLAG_CP;
#endif
			rxi_FreePacket(cp);
			cp = callSvc->currentPacket = NULL;
			callSvc->nLeft = 0;
		    } else {
			callSvc->curpos =
			    (char *)cp->wirevec[callSvc->curvec].iov_base;
			callSvc->curlen = cp->wirevec[callSvc->curvec].iov_len;
		    }
		}
	    }
	if (!nbytes) {
	    /* user buffer is full, return */
	    return requestCount;
	}

    } while (nbytes);

    return requestCount;
}

/* Called only from the service thread */
int
rx_ReadProc(struct rx_call *call, char *buf, int nbytes)
{
    struct rx_call_service *callSvc = &call->service;
    int bytes;
    int tcurlen;
    int tnLeft;
    char *tcurpos;
    SPLVAR;

    rxi_call_clearIovec(callSvc);

    /*
     * Most common case, all of the data is in the current iovec.
     * We are relying on nLeft being zero unless the call is in receive mode.
     */
    tcurlen = callSvc->curlen;
    tnLeft = callSvc->nLeft;
    if (!call->error && tcurlen > nbytes && tnLeft > nbytes) {
	tcurpos = callSvc->curpos;
        memcpy(buf, tcurpos, nbytes);

	callSvc->curpos = tcurpos + nbytes;
	callSvc->curlen = tcurlen - nbytes;
	callSvc->nLeft = tnLeft - nbytes;

        if (!callSvc->nLeft && callSvc->currentPacket != NULL) {
            /* out of packet.  Get another one. */
            rxi_FreePacket(callSvc->currentPacket);
            callSvc->currentPacket = NULL;
        }
	return nbytes;
    }

    NETPRI;
    bytes = rxi_ReadProc(call, buf, nbytes);
    USERPRI;
    return bytes;
}

/* Optimization for unmarshalling 32 bit integers */
int
rx_ReadProc32(struct rx_call *call, afs_int32 * value)
{
    struct rx_call_service *callSvc = &call->service;
    int bytes;
    int tcurlen;
    int tnLeft;
    char *tcurpos;
    SPLVAR;

    rxi_call_clearIovec(callSvc);

    /*
     * Most common case, all of the data is in the current iovec.
     * We are relying on nLeft being zero unless the call is in receive mode.
     */
    tcurlen = callSvc->curlen;
    tnLeft = callSvc->nLeft;
    if (!call->error && tcurlen >= sizeof(afs_int32)
	&& tnLeft >= sizeof(afs_int32)) {
	tcurpos = callSvc->curpos;

        memcpy((char *)value, tcurpos, sizeof(afs_int32));

        callSvc->curpos = tcurpos + sizeof(afs_int32);
	callSvc->curlen = (u_short)(tcurlen - sizeof(afs_int32));
	callSvc->nLeft = (u_short)(tnLeft - sizeof(afs_int32));
        if (!callSvc->nLeft && callSvc->currentPacket != NULL) {
            /* out of packet.  Get another one. */
            rxi_FreePacket(callSvc->currentPacket);
            callSvc->currentPacket = NULL;
        }
	return sizeof(afs_int32);
    }

    NETPRI;
    bytes = rxi_ReadProc(call, (char *)value, sizeof(afs_int32));
    USERPRI;

    return bytes;
}

/* rxi_FillReadVec
 *
 * Uses packets in the receive queue to fill in as much of the
 * current iovec as possible. Does not block if it runs out
 * of packets to complete the iovec. Return true if an ack packet
 * was sent, otherwise return false */
void
rxi_FillReadVec(struct rx_call *call, afs_uint32 serial)
{
    struct rx_call_service *callSvc = &call->service;
    unsigned int t;
    struct rx_packet *rp;
    struct rx_packet *curp;
    struct iovec *call_iov;
    struct iovec *cur_iov = NULL;

    curp = callSvc->currentPacket;
    if (curp) {
	cur_iov = &curp->wirevec[callSvc->curvec];
    }
    call_iov = &call->iov[call->iovNext];

    while (!call->error && call->iovNBytes && call->iovNext < call->iovMax) {
	if (callSvc->nLeft == 0) {
	    /* Get next packet */
	    if (queue_IsNotEmpty(&call->receiveBuffer)) {
		afs_int32 error;
		struct rx_connection *conn = call->conn;
    		 
		rp = queue_First(&call->receiveBuffer, rx_packet);
		queue_Remove(rp);
#ifdef RX_TRACK_PACKETS
		rp->flags &= ~RX_PKTFLAG_RQ;
#endif
#ifdef RXDEBUG_PACKET
                call->rqc--;
#endif /* RXDEBUG_PACKET */

		/* RXS_CheckPacket called to undo RXS_PreparePacket's
		 * work.  It may reduce the length of the packet by up
		 * to conn->maxTrailerSize, to reflect the length of the
		 * data + the header. */
		if ((error =
		    RXS_CheckPacket(conn->securityObject, call, rp))) {
		    /* Used to merely shut down the call, but now we
		     * shut down the whole connection since this may
		     * indicate an attempt to hijack it */

		    MUTEX_EXIT(&call->lock);
		    rxi_ConnectionError(conn, error);
		    MUTEX_ENTER(&conn->conn_data_lock);
		    rp = rxi_SendConnectionAbort(conn, rp, 0, 0);
		    MUTEX_EXIT(&conn->conn_data_lock);
		    rxi_FreePacket(rp);
		    MUTEX_ENTER(&call->lock);

		    return;
		}

		curp = callSvc->currentPacket = rp;
#ifdef RX_TRACK_PACKETS
		callSvc->currentPacket->flags |= RX_PKTFLAG_CP;
#endif
		callSvc->curvec = 1;	/* 0th vec is always header */
		cur_iov = &curp->wirevec[1];
		/* begin at the beginning [ more or less ], continue
		 * on until the end, then stop. */
		callSvc->curpos = (char *)curp->wirevec[1].iov_base
			       + call->conn->securityHeaderSize;
		callSvc->curlen = curp->wirevec[1].iov_len
			       - call->conn->securityHeaderSize;

		/* Notice that this code works correctly if the data
		 * size is 0 (which it may be--no reply arguments from
		 * server, for example).  This relies heavily on the
		 * fact that the code below immediately frees the packet
		 * (no yields, etc.).  If it didn't, this would be a
		 * problem because a value of zero for call->nLeft
		 * normally means that there is no read packet */
		callSvc->nLeft = curp->length;
		hadd32(call->bytesRcvd, curp->length);

		continue;
	    }
	    break;
	}

	/* It's possible for call->nLeft to be smaller than any particular
	 * iov_len.  Usually, recvmsg doesn't change the iov_len, since it
	 * reflects the size of the buffer.  We have to keep track of the
	 * number of bytes read in the length field of the packet struct.  On
	 * the final portion of a received packet, it's almost certain that
	 * call->nLeft will be smaller than the final buffer. */
	while (call->iovNBytes && call->iovNext < call->iovMax && curp) {

	    t = MIN((int)callSvc->curlen, call->iovNBytes);
	    t = MIN(t, (int)callSvc->nLeft);
	    call_iov->iov_base = callSvc->curpos;
	    call_iov->iov_len = t;
	    call_iov++;
	    call->iovNext++;
	    call->iovNBytes -= t;
	    callSvc->curpos += t;
	    callSvc->curlen -= t;
	    callSvc->nLeft -= t;

	    if (!callSvc->nLeft) {
		/* out of packet.  Get another one. */
#ifdef RX_TRACK_PACKETS
                curp->flags &= ~RX_PKTFLAG_CP;
                curp->flags |= RX_PKTFLAG_IOVQ;
#endif
		queue_Append(&callSvc->iovq, curp);
#ifdef RXDEBUG_PACKET
                callSvc->iovqc++;
#endif /* RXDEBUG_PACKET */
		curp = callSvc->currentPacket = NULL;
	    } else if (!callSvc->curlen) {
		/* need to get another struct iov */
		if (++callSvc->curvec >= curp->niovecs) {
		    /* current packet is exhausted, get ready for another */
		    /* don't worry about curvec and stuff, they get set somewhere else */
#ifdef RX_TRACK_PACKETS
		    curp->flags &= ~RX_PKTFLAG_CP;
		    curp->flags |= RX_PKTFLAG_IOVQ;
#endif
		    queue_Append(&callSvc->iovq, curp);
#ifdef RXDEBUG_PACKET
                    callSvc->iovqc++;
#endif /* RXDEBUG_PACKET */
		    curp = callSvc->currentPacket = NULL;
		    callSvc->nLeft = 0;
		} else {
		    cur_iov++;
		    callSvc->curpos = (char *)cur_iov->iov_base;
		    callSvc->curlen = cur_iov->iov_len;
		}
	    }
	}
    }

    return;
}


/* rxi_ReadvProc -- internal version.
 *
 * Fills in an iovec with pointers to the packet buffers. All packets
 * except the last packet (new current packet) are moved to the iovq
 * while the application is processing the data.
 *
 * LOCKS USED -- called at netpri.
 */
int
rxi_ReadvProc(struct rx_call *call, struct iovec *iov, int *nio, int maxio,
	      int nbytes)
{
    int bytes;

    rxi_call_clearIovec(&call->service);

    if (call->mode == RX_MODE_SENDING) {
	rxi_FlushWrite(call);
    }

    MUTEX_ENTER(&call->lock);
    if (call->error)
        goto error;

    call->iovNBytes = nbytes;
    call->iovMax = maxio;
    call->iovNext = 0;
    call->iov = iov;
    rxi_FillReadVec(call, 0);

    /* if we need more data then sleep until the receive thread has
     * filled in the rest. */
    while (!call->error && call->iovNBytes && call->iovNext < call->iovMax
	   && !(call->flags & RX_CALL_RECEIVE_DONE)) {
	call->flags |= RX_CALL_READER_WAIT;
	clock_NewTime();
	call->startWait = clock_Sec();
	while (call->flags & RX_CALL_READER_WAIT) {
#ifdef	RX_ENABLE_LOCKS
	    CV_WAIT(&call->cv_rq, &call->lock);
#else
	    osi_rxSleep(&call->rq);
#endif
	}
	call->startWait = 0;
	rxi_FillReadVec(call, 0);
    }

    if (call->error)
        goto error;

    call->iov = NULL;
    *nio = call->iovNext;
    bytes = nbytes - call->iovNBytes;
    MUTEX_EXIT(&call->lock);
    return bytes;

  error:
    MUTEX_EXIT(&call->lock);
    call->mode = RX_MODE_ERROR;
    return 0;
}

int
rx_ReadvProc(struct rx_call *call, struct iovec *iov, int *nio, int maxio,
	     int nbytes)
{
    int bytes;
    SPLVAR;

    NETPRI;
    bytes = rxi_ReadvProc(call, iov, nio, maxio, nbytes);
    USERPRI;
    return bytes;
}

/* rxi_WriteProc -- internal version.
 *
 * LOCKS USED -- called at netpri
 */

int
rxi_WriteProc(struct rx_call *call, char *buf,
	      int nbytes)
{
    struct rx_call_service *callSvc = &call->service;
    struct rx_connection *conn = call->conn;
    struct rx_packet *cp = callSvc->currentPacket;
    unsigned int t;
    int requestCount = nbytes;

    rxi_call_clearIovec(callSvc);

    if (call->mode != RX_MODE_SENDING) {
	if ((conn->type == RX_SERVER_CONNECTION)
	    && (call->mode == RX_MODE_RECEIVING)) {
	    call->mode = RX_MODE_SENDING;
	    if (cp) {
#ifdef RX_TRACK_PACKETS
		cp->flags &= ~RX_PKTFLAG_CP;
#endif
		rxi_FreePacket(cp);
		cp = callSvc->currentPacket = NULL;
		callSvc->nLeft = 0;
		callSvc->nFree = 0;
	    }
	} else {
	    return 0;
	}
    }

    /* Loop condition is checked at end, so that a write of 0 bytes
     * will force a packet to be created--specially for the case where
     * there are 0 bytes on the stream, but we must send a packet
     * anyway. */
    do {
	if (callSvc->nFree == 0) {
	    MUTEX_ENTER(&call->lock);
#ifdef AFS_GLOBAL_RXLOCK_KERNEL
            rxi_WaitforTQBusy(call);
#endif /* AFS_GLOBAL_RXLOCK_KERNEL */
            cp = callSvc->currentPacket;
            if (call->error)
                call->mode = RX_MODE_ERROR;
	    if (!call->error && cp) {
#ifdef RX_TRACK_PACKETS
                cp->flags &= ~RX_PKTFLAG_CP;
#endif
		callSvc->currentPacket = NULL;
		clock_NewTime();	/* Bogus:  need new time package */
		/* The 0, below, specifies that it is not the last packet:
		 * there will be others. PrepareSendPacket may
		 * alter the packet length by up to
		 * conn->securityMaxTrailerSize */
		hadd32(call->bytesSent, cp->length);
		rxi_PrepareSendPacket(call, cp, 0);
#ifdef RX_TRACK_PACKETS
		cp->flags |= RX_PKTFLAG_TQ;
#endif
		queue_Append(&call->tq, cp);
		opr_queue_Append(&call->tq_noack, &cp->noAckEntry);
#ifdef RXDEBUG_PACKET
                call->tqc++;
#endif /* RXDEBUG_PACKET */
                cp = (struct rx_packet *)0;
		if (!
		    (call->
		     flags & (RX_CALL_FAST_RECOVER |
			      RX_CALL_FAST_RECOVER_WAIT))) {
		    rxi_Start(0, call, 0, 0);
		}
	    } else if (cp) {
#ifdef RX_TRACK_PACKETS
		cp->flags &= ~RX_PKTFLAG_CP;
#endif
		rxi_FreePacket(cp);
		cp = callSvc->currentPacket = NULL;
	    }
	    /* Wait for transmit window to open up */
	    while (!call->error
		   && call->tnext + 1 > call->tfirst + (2 * call->twind)) {
		clock_NewTime();
		call->startWait = clock_Sec();

#ifdef	RX_ENABLE_LOCKS
		CV_WAIT(&call->cv_twind, &call->lock);
#else
		call->flags |= RX_CALL_WAIT_WINDOW_ALLOC;
		osi_rxSleep(&call->twind);
#endif

		call->startWait = 0;
#ifdef RX_ENABLE_LOCKS
		if (call->error) {
                    call->mode = RX_MODE_ERROR;
		    MUTEX_EXIT(&call->lock);
		    return 0;
		}
#endif /* RX_ENABLE_LOCKS */
	    }
	    if ((cp = rxi_AllocSendPacket(call, nbytes))) {
#ifdef RX_TRACK_PACKETS
		cp->flags |= RX_PKTFLAG_CP;
#endif
		callSvc->currentPacket = cp;
		callSvc->nFree = cp->length;
		callSvc->curvec = 1;	/* 0th vec is always header */
		/* begin at the beginning [ more or less ], continue
		 * on until the end, then stop. */
		callSvc->curpos =
		    (char *)cp->wirevec[1].iov_base +
		    call->conn->securityHeaderSize;
		callSvc->curlen =
		    cp->wirevec[1].iov_len - call->conn->securityHeaderSize;
	    }
	    if (call->error) {
                call->mode = RX_MODE_ERROR;
		if (cp) {
#ifdef RX_TRACK_PACKETS
		    cp->flags &= ~RX_PKTFLAG_CP;
#endif
		    rxi_FreePacket(cp);
		    callSvc->currentPacket = NULL;
		}
		MUTEX_EXIT(&call->lock);
		return 0;
	    }
	    MUTEX_EXIT(&call->lock);
	}

	if (cp && (int)callSvc->nFree < nbytes) {
	    /* Try to extend the current buffer */
	    int len, mud;
	    len = cp->length;
	    mud = rx_MaxUserDataSize(call);
	    if (mud > len) {
		int want;
		want = MIN(nbytes - (int)callSvc->nFree, mud - len);
		rxi_AllocDataBuf(cp, want, RX_PACKET_CLASS_SEND_CBUF);
		if (cp->length > (unsigned)mud)
		    cp->length = mud;
		callSvc->nFree += (cp->length - len);
	    }
	}

	/* If the remaining bytes fit in the buffer, then store them
	 * and return.  Don't ship a buffer that's full immediately to
	 * the peer--we don't know if it's the last buffer yet */

	if (!cp) {
	    callSvc->nFree = 0;
	}

	while (nbytes && callSvc->nFree) {

	    t = MIN((int)callSvc->curlen, nbytes);
	    t = MIN((int)callSvc->nFree, t);
	    memcpy(callSvc->curpos, buf, t);
	    buf += t;
	    nbytes -= t;
	    callSvc->curpos += t;
	    callSvc->curlen -= (u_short)t;
	    callSvc->nFree -= (u_short)t;

	    if (!callSvc->curlen) {
		/* need to get another struct iov */
		if (++callSvc->curvec >= cp->niovecs) {
		    /* current packet is full, extend or send it */
		    callSvc->nFree = 0;
		} else {
		    callSvc->curpos
			= (char *)cp->wirevec[callSvc->curvec].iov_base;
		    callSvc->curlen = cp->wirevec[callSvc->curvec].iov_len;
		}
	    }
	}			/* while bytes to send and room to send them */

	/* might be out of space now */
	if (!nbytes) {
	    return requestCount;
	} else;			/* more data to send, so get another packet and keep going */
    } while (nbytes);

    return requestCount - nbytes;
}

int
rx_WriteProc(struct rx_call *call, char *buf, int nbytes)
{
    struct rx_call_service *callSvc = &call->service;
    int bytes;
    int tcurlen;
    int tnFree;
    char *tcurpos;
    SPLVAR;

    /* Free any packets from the last call to ReadvProc/WritevProc */
    if (queue_IsNotEmpty(&callSvc->iovq)) {
#ifdef RXDEBUG_PACKET
        callSvc->iovqc -=
#endif /* RXDEBUG_PACKET */
            rxi_FreePackets(0, &callSvc->iovq);
    }

    /*
     * Most common case: all of the data fits in the current iovec.
     * We are relying on nFree being zero unless the call is in send mode.
     */
    tcurlen = (int)callSvc->curlen;
    tnFree = (int)callSvc->nFree;
    if (!call->error && tcurlen >= nbytes && tnFree >= nbytes) {
	tcurpos = callSvc->curpos;

	memcpy(tcurpos, buf, nbytes);
	callSvc->curpos = tcurpos + nbytes;
	callSvc->curlen = (u_short)(tcurlen - nbytes);
	callSvc->nFree = (u_short)(tnFree - nbytes);
	return nbytes;
    }

    NETPRI;
    bytes = rxi_WriteProc(call, buf, nbytes);
    USERPRI;
    return bytes;
}

/* Optimization for marshalling 32 bit arguments */
int
rx_WriteProc32(struct rx_call *call, afs_int32 * value)
{
    struct rx_call_service *callSvc = &call->service;
    int bytes;
    int tcurlen;
    int tnFree;
    char *tcurpos;
    SPLVAR;

    rxi_call_clearIovec(callSvc);

    /*
     * Most common case: all of the data fits in the current iovec.
     * We are relying on nFree being zero unless the call is in send mode.
     */
    tcurlen = callSvc->curlen;
    tnFree = callSvc->nFree;
    if (!call->error && tcurlen >= sizeof(afs_int32)
	&& tnFree >= sizeof(afs_int32)) {
	tcurpos = callSvc->curpos;

	if (!((size_t)tcurpos & (sizeof(afs_int32) - 1))) {
	    *((afs_int32 *) (tcurpos)) = *value;
	} else {
	    memcpy(tcurpos, (char *)value, sizeof(afs_int32));
	}
	callSvc->curpos = tcurpos + sizeof(afs_int32);
	callSvc->curlen = (u_short)(tcurlen - sizeof(afs_int32));
	callSvc->nFree = (u_short)(tnFree - sizeof(afs_int32));
	return sizeof(afs_int32);
    }

    NETPRI;
    bytes = rxi_WriteProc(call, (char *)value, sizeof(afs_int32));
    USERPRI;
    return bytes;
}

/* rxi_WritevAlloc -- internal version.
 *
 * Fill in an iovec to point to data in packet buffers. The application
 * calls rxi_WritevProc when the buffers are full.
 *
 * LOCKS USED -- called at netpri.
 */

int
rxi_WritevAlloc(struct rx_call *call, struct iovec *iov, int *nio, int maxio,
		int nbytes)
{
    struct rx_call_service *callSvc = &call->service;
    struct rx_connection *conn = call->conn;
    struct rx_packet *cp = callSvc->currentPacket;
    int requestCount;
    int nextio;
    /* Temporary values, real work is done in rxi_WritevProc */
    int tnFree;
    unsigned int tcurvec;
    char *tcurpos;
    int tcurlen;

    requestCount = nbytes;
    nextio = 0;

    /* Free any packets from the last call to ReadvProc/WritevProc */
    if (queue_IsNotEmpty(&callSvc->iovq)) {
#ifdef RXDEBUG_PACKET
        callSvc->iovqc -=
#endif /* RXDEBUG_PACKET */
            rxi_FreePackets(0, &callSvc->iovq);
    }

    if (call->mode != RX_MODE_SENDING) {
	if ((conn->type == RX_SERVER_CONNECTION)
	    && (call->mode == RX_MODE_RECEIVING)) {
	    call->mode = RX_MODE_SENDING;
	    if (cp) {
#ifdef RX_TRACK_PACKETS
		cp->flags &= ~RX_PKTFLAG_CP;
#endif
		rxi_FreePacket(cp);
		cp = callSvc->currentPacket = NULL;
		callSvc->nLeft = 0;
		callSvc->nFree = 0;
	    }
	} else {
	    return 0;
	}
    }

    /* Set up the iovec to point to data in packet buffers. */
    tnFree = callSvc->nFree;
    tcurvec = callSvc->curvec;
    tcurpos = callSvc->curpos;
    tcurlen = callSvc->curlen;
    do {
	int t;

	if (tnFree == 0) {
	    /* current packet is full, allocate a new one */
	    MUTEX_ENTER(&call->lock);
	    cp = rxi_AllocSendPacket(call, nbytes);
	    MUTEX_EXIT(&call->lock);
	    if (cp == NULL) {
		/* out of space, return what we have */
		*nio = nextio;
		return requestCount - nbytes;
	    }
#ifdef RX_TRACK_PACKETS
	    cp->flags |= RX_PKTFLAG_IOVQ;
#endif
	    queue_Append(&callSvc->iovq, cp);
#ifdef RXDEBUG_PACKET
            callSvc->iovqc++;
#endif /* RXDEBUG_PACKET */
	    tnFree = cp->length;
	    tcurvec = 1;
	    tcurpos =
		(char *)cp->wirevec[1].iov_base +
		call->conn->securityHeaderSize;
	    tcurlen = cp->wirevec[1].iov_len - call->conn->securityHeaderSize;
	}

	if (tnFree < nbytes) {
	    /* try to extend the current packet */
	    int len, mud;
	    len = cp->length;
	    mud = rx_MaxUserDataSize(call);
	    if (mud > len) {
		int want;
		want = MIN(nbytes - tnFree, mud - len);
		rxi_AllocDataBuf(cp, want, RX_PACKET_CLASS_SEND_CBUF);
		if (cp->length > (unsigned)mud)
		    cp->length = mud;
		tnFree += (cp->length - len);
		if (cp == callSvc->currentPacket) {
		    callSvc->nFree += (cp->length - len);
		}
	    }
	}

	/* fill in the next entry in the iovec */
	t = MIN(tcurlen, nbytes);
	t = MIN(tnFree, t);
	iov[nextio].iov_base = tcurpos;
	iov[nextio].iov_len = t;
	nbytes -= t;
	tcurpos += t;
	tcurlen -= t;
	tnFree -= t;
	nextio++;

	if (!tcurlen) {
	    /* need to get another struct iov */
	    if (++tcurvec >= cp->niovecs) {
		/* current packet is full, extend it or move on to next packet */
		tnFree = 0;
	    } else {
		tcurpos = (char *)cp->wirevec[tcurvec].iov_base;
		tcurlen = cp->wirevec[tcurvec].iov_len;
	    }
	}
    } while (nbytes && nextio < maxio);
    *nio = nextio;
    return requestCount - nbytes;
}

int
rx_WritevAlloc(struct rx_call *call, struct iovec *iov, int *nio, int maxio,
	       int nbytes)
{
    int bytes;
    SPLVAR;

    NETPRI;
    bytes = rxi_WritevAlloc(call, iov, nio, maxio, nbytes);
    USERPRI;
    return bytes;
}

/* rxi_WritevProc -- internal version.
 *
 * Send buffers allocated in rxi_WritevAlloc.
 *
 * LOCKS USED -- called at netpri.
 */
int
rxi_WritevProc(struct rx_call *call, struct iovec *iov, int nio, int nbytes)
{
    struct rx_call_service *callSvc = &call->service;
    struct rx_packet *cp = NULL;
    struct rx_packet *p, *np;
    int nextio;
    int requestCount;
    struct rx_queue tmpq;
#ifdef RXDEBUG_PACKET
    u_short tmpqc;
#endif

    requestCount = nbytes;
    nextio = 0;

    MUTEX_ENTER(&call->lock);
    if (call->error) {
        call->mode = RX_MODE_ERROR;
    } else if (call->mode != RX_MODE_SENDING) {
	call->error = RX_PROTOCOL_ERROR;
    }
#ifdef AFS_GLOBAL_RXLOCK_KERNEL
    rxi_WaitforTQBusy(call);
#endif /* AFS_GLOBAL_RXLOCK_KERNEL */
    cp = callSvc->currentPacket;

    if (call->error) {
        call->mode = RX_MODE_ERROR;
	MUTEX_EXIT(&call->lock);
	if (cp) {
#ifdef RX_TRACK_PACKETS
            cp->flags &= ~RX_PKTFLAG_CP;
            cp->flags |= RX_PKTFLAG_IOVQ;
#endif
	    queue_Prepend(&callSvc->iovq, cp);
#ifdef RXDEBUG_PACKET
            callSvc->iovqc++;
#endif /* RXDEBUG_PACKET */
	    callSvc->currentPacket = NULL;
	}
#ifdef RXDEBUG_PACKET
        callSvc->iovqc -=
#endif /* RXDEBUG_PACKET */
            rxi_FreePackets(0, &callSvc->iovq);
	return 0;
    }

    /* Loop through the I/O vector adjusting packet pointers.
     * Place full packets back onto the iovq once they are ready
     * to send. Set RX_PROTOCOL_ERROR if any problems are found in
     * the iovec. We put the loop condition at the end to ensure that
     * a zero length write will push a short packet. */
    nextio = 0;
    queue_Init(&tmpq);
#ifdef RXDEBUG_PACKET
    tmpqc = 0;
#endif /* RXDEBUG_PACKET */
    do {
	if (callSvc->nFree == 0 && cp) {
	    clock_NewTime();	/* Bogus:  need new time package */
	    /* The 0, below, specifies that it is not the last packet:
	     * there will be others. PrepareSendPacket may
	     * alter the packet length by up to
	     * conn->securityMaxTrailerSize */
	    hadd32(call->bytesSent, cp->length);
	    rxi_PrepareSendPacket(call, cp, 0);
	    queue_Append(&tmpq, cp);
#ifdef RXDEBUG_PACKET
            tmpqc++;
#endif /* RXDEBUG_PACKET */
            cp = callSvc->currentPacket = NULL;

	    /* The head of the iovq is now the current packet */
	    if (nbytes) {
		if (queue_IsEmpty(&callSvc->iovq)) {
                    MUTEX_EXIT(&call->lock);
		    call->error = RX_PROTOCOL_ERROR;
#ifdef RXDEBUG_PACKET
                    tmpqc -=
#endif /* RXDEBUG_PACKET */
                        rxi_FreePackets(0, &tmpq);
		    return 0;
		}
		cp = queue_First(&callSvc->iovq, rx_packet);
		queue_Remove(cp);
#ifdef RX_TRACK_PACKETS
                cp->flags &= ~RX_PKTFLAG_IOVQ;
#endif
#ifdef RXDEBUG_PACKET
                callSvc->iovqc--;
#endif /* RXDEBUG_PACKET */
#ifdef RX_TRACK_PACKETS
                cp->flags |= RX_PKTFLAG_CP;
#endif
		callSvc->currentPacket = cp;
		callSvc->nFree = cp->length;
		callSvc->curvec = 1;
		callSvc->curpos =
		    (char *)cp->wirevec[1].iov_base +
		    call->conn->securityHeaderSize;
		callSvc->curlen =
		    cp->wirevec[1].iov_len - call->conn->securityHeaderSize;
	    }
	}

	if (nbytes) {
	    /* The next iovec should point to the current position */
	    if (iov[nextio].iov_base != callSvc->curpos
		|| iov[nextio].iov_len > (int)callSvc->curlen) {
		call->error = RX_PROTOCOL_ERROR;
                MUTEX_EXIT(&call->lock);
		if (cp) {
#ifdef RX_TRACK_PACKETS
		    cp->flags &= ~RX_PKTFLAG_CP;
#endif
                    queue_Prepend(&tmpq, cp);
#ifdef RXDEBUG_PACKET
                    tmpqc++;
#endif /* RXDEBUG_PACKET */
                    cp = callSvc->currentPacket = NULL;
		}
#ifdef RXDEBUG_PACKET
                tmpqc -=
#endif /* RXDEBUG_PACKET */
                    rxi_FreePackets(0, &tmpq);
		return 0;
	    }
	    nbytes -= iov[nextio].iov_len;
	    callSvc->curpos += iov[nextio].iov_len;
	    callSvc->curlen -= iov[nextio].iov_len;
	    callSvc->nFree -= iov[nextio].iov_len;
	    nextio++;
	    if (callSvc->curlen == 0) {
		if (++callSvc->curvec > cp->niovecs) {
		    callSvc->nFree = 0;
		} else {
		    callSvc->curpos 
			= (char *)cp->wirevec[callSvc->curvec].iov_base;
		    callSvc->curlen = cp->wirevec[callSvc->curvec].iov_len;
		}
	    }
	}
    } while (nbytes && nextio < nio);

    /* Move the packets from the temporary queue onto the transmit queue.
     * We may end up with more than call->twind packets on the queue. */

    for (queue_Scan(&tmpq, p, np, rx_packet))
    {
#ifdef RX_TRACK_PACKETS
        p->flags |= RX_PKTFLAG_TQ;
#endif
	opr_queue_Append(&call->tq_noack, &p->noAckEntry);
    }


    if (call->error)
        call->mode = RX_MODE_ERROR;

    queue_SpliceAppend(&call->tq, &tmpq);

    if (!(call->flags & (RX_CALL_FAST_RECOVER | RX_CALL_FAST_RECOVER_WAIT))) {
	rxi_Start(0, call, 0, 0);
    }

    /* Wait for the length of the transmit queue to fall below call->twind */
    while (!call->error && call->tnext + 1 > call->tfirst + (2 * call->twind)) {
	clock_NewTime();
	call->startWait = clock_Sec();
#ifdef	RX_ENABLE_LOCKS
	CV_WAIT(&call->cv_twind, &call->lock);
#else
	call->flags |= RX_CALL_WAIT_WINDOW_ALLOC;
	osi_rxSleep(&call->twind);
#endif
	call->startWait = 0;
    }

    if (call->error) {
        call->mode = RX_MODE_ERROR;
        callSvc->currentPacket = NULL;
        MUTEX_EXIT(&call->lock);
	if (cp) {
#ifdef RX_TRACK_PACKETS
	    cp->flags &= ~RX_PKTFLAG_CP;
#endif
	    rxi_FreePacket(cp);
	}
	return 0;
    }
    MUTEX_EXIT(&call->lock);

    return requestCount - nbytes;
}

int
rx_WritevProc(struct rx_call *call, struct iovec *iov, int nio, int nbytes)
{
    int bytes;
    SPLVAR;

    NETPRI;
    bytes = rxi_WritevProc(call, iov, nio, nbytes);
    USERPRI;
    return bytes;
}

/* Flush any buffered data to the stream, switch to read mode
 * (clients) or to EOF mode (servers)
 *
 * LOCKS HELD: called at netpri.
 */
void
rxi_FlushWrite(struct rx_call *call)
{
    struct rx_call_service *callSvc = &call->service;
    struct rx_packet *cp = NULL;

    /* Free any packets from the last call to ReadvProc/WritevProc */
    if (queue_IsNotEmpty(&callSvc->iovq)) {
#ifdef RXDEBUG_PACKET
        callSvc->iovqc -=
#endif /* RXDEBUG_PACKET */
            rxi_FreePackets(0, &callSvc->iovq);
    }

    if (call->mode == RX_MODE_SENDING) {

	call->mode =
	    (call->conn->type ==
	     RX_CLIENT_CONNECTION ? RX_MODE_RECEIVING : RX_MODE_EOF);

#ifdef RX_KERNEL_TRACE
	{
	    int glockOwner = ISAFS_GLOCK();
	    if (!glockOwner)
		AFS_GLOCK();
	    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE, ICL_TYPE_STRING,
		       __FILE__, ICL_TYPE_INT32, __LINE__, ICL_TYPE_POINTER,
		       call);
	    if (!glockOwner)
		AFS_GUNLOCK();
	}
#endif

        MUTEX_ENTER(&call->lock);
#ifdef AFS_GLOBAL_RXLOCK_KERNEL
        rxi_WaitforTQBusy(call);
#endif /* AFS_GLOBAL_RXLOCK_KERNEL */
        if (call->error)
            call->mode = RX_MODE_ERROR;

        cp = callSvc->currentPacket;

	if (cp) {
	    /* cp->length is only supposed to be the user's data */
	    /* cp->length was already set to (then-current)
	     * MaxUserDataSize or less. */
#ifdef RX_TRACK_PACKETS
	    cp->flags &= ~RX_PKTFLAG_CP;
#endif
	    cp->length -= callSvc->nFree;
	    callSvc->currentPacket = NULL;
	    callSvc->nFree = 0;
	} else {
	    cp = rxi_AllocSendPacket(call, 0);
	    if (!cp) {
		/* Mode can no longer be MODE_SENDING */
		return;
	    }
	    cp->length = 0;
	    cp->niovecs = 2;	/* header + space for rxkad stuff */
	    callSvc->nFree = 0;
	}

	/* The 1 specifies that this is the last packet */
	hadd32(call->bytesSent, cp->length);
	rxi_PrepareSendPacket(call, cp, 1);
#ifdef RX_TRACK_PACKETS
	cp->flags |= RX_PKTFLAG_TQ;
#endif
	queue_Append(&call->tq, cp);
	opr_queue_Append(&call->tq_noack, &cp->noAckEntry);
#ifdef RXDEBUG_PACKET
        call->tqc++;
#endif /* RXDEBUG_PACKET */
	if (!
	    (call->
	     flags & (RX_CALL_FAST_RECOVER | RX_CALL_FAST_RECOVER_WAIT))) {
	    rxi_Start(0, call, 0, 0);
	}
        MUTEX_EXIT(&call->lock);
    }
}

/* Flush any buffered data to the stream, switch to read mode
 * (clients) or to EOF mode (servers) */
void
rx_FlushWrite(struct rx_call *call)
{
    SPLVAR;
    NETPRI;
    rxi_FlushWrite(call);
    USERPRI;
}
