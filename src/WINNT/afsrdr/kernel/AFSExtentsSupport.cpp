/*
 * Copyright (c) 2008 Kernel Drivers, LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice,
 *   this list of conditions and the following disclaimer in the
 *   documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Kernel Drivers, LLC nor the names of its
 *   contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission from Kernel Drivers, LLC.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

//
// File: AFSCommSupport.cpp
//
#include "AFSCommon.h"

#define AFS_MAX_FCBS_TO_DROP 10

static AFSExtent *ExtentFor( PLIST_ENTRY le, ULONG SkipList );
static AFSExtent *NextExtent( AFSExtent *Extent, ULONG SkipList );
static ULONG ExtentsMasks[AFS_NUM_EXTENT_LISTS] = AFS_EXTENTS_MASKS;
static VOID VerifyExtentsLists(AFSFcb *Fcb);
static AFSExtent *DirtyExtentFor(PLIST_ENTRY le);

LIST_ENTRY *
AFSEntryForOffset( IN AFSFcb *Fcb, 
                   IN PLARGE_INTEGER Offset);

VOID
AFSReferenceExtents( IN AFSFcb *Fcb)
{
    AFSNonPagedFcb    *pNPFcb = Fcb->NPFcb;

    //
    // Protect with resource SHARED - no problems with multiple
    // operations doing this but we need to appear to be atomic from
    // the point of view of a dereference
    //

    AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSReferenceExtents Acquiring Fcb extent lock %08lX SHARED %08lX\n",
                  &pNPFcb->Specific.File.ExtentsResource,
                  PsGetCurrentThread());

    AFSAcquireShared( &pNPFcb->Specific.File.ExtentsResource, TRUE );

    AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSReferenceExtents Clearing ExtentsNotBusy event for %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                  &Fcb->DirEntry->DirectoryEntry.FileName,
                  Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                  Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                  Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                  Fcb->DirEntry->DirectoryEntry.FileId.Unique);

    InterlockedIncrement( &pNPFcb->Specific.File.ExtentsRefCount );
    KeClearEvent( &pNPFcb->Specific.File.ExtentsNotBusy );

    AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );
}

VOID
AFSDereferenceExtents( IN AFSFcb *Fcb)
{
    AFSNonPagedFcb *pNPFcb = Fcb->NPFcb;
    LONG            i;

    //
    // Grab resource Shared and decrement. If we were zero then
    // Increment and do it again with the lock Ex (guarantees only one
    // 1->0 transition)
    //
    //
    // We cannot have the lock SHARED at this point
    //
    ASSERT(ExIsResourceAcquiredExclusiveLite( &pNPFcb->Specific.File.ExtentsResource) ||
           !ExIsResourceAcquiredExclusive( &pNPFcb->Specific.File.ExtentsResource) );

    AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSDereferenceExtents Acquiring Fcb extent lock %08lX SHARED %08lX\n",
                  &pNPFcb->Specific.File.ExtentsResource,
                  PsGetCurrentThread());

    AFSAcquireShared (&pNPFcb->Specific.File.ExtentsResource, TRUE );

    i = InterlockedDecrement( &pNPFcb->Specific.File.ExtentsRefCount );

    AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSDereferenceExtents ExtentsRefCount %d (1) for %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                  pNPFcb->Specific.File.ExtentsRefCount,
                  &Fcb->DirEntry->DirectoryEntry.FileName,
                  Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                  Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                  Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                  Fcb->DirEntry->DirectoryEntry.FileId.Unique);

    if (0 != i) 
    {
        //
        // All done
        //
        AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );

        return;
    }

    InterlockedIncrement( &pNPFcb->Specific.File.ExtentsRefCount );

    AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );

    AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSDereferenceExtents Acquiring Fcb extent lock %08lX EXCL %08lX\n",
                  &pNPFcb->Specific.File.ExtentsResource,
                  PsGetCurrentThread());

    AFSAcquireExcl( &pNPFcb->Specific.File.ExtentsResource, TRUE );

    i = InterlockedDecrement( &pNPFcb->Specific.File.ExtentsRefCount );

    AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSDereferenceExtents ExtentsRefCount %d (2) for %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                  pNPFcb->Specific.File.ExtentsRefCount,
                  &Fcb->DirEntry->DirectoryEntry.FileName,
                  Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                  Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                  Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                  Fcb->DirEntry->DirectoryEntry.FileId.Unique);

    if (0 != i) 
    {
        //
        // All done
        //
        AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );
        return;
    }

    KeQueryTickCount( &Fcb->Specific.File.LastExtentAccess);

    AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSDereferenceExtents Setting ExtentsNotBusy event for %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                  &Fcb->DirEntry->DirectoryEntry.FileName,
                  Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                  Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                  Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                  Fcb->DirEntry->DirectoryEntry.FileId.Unique);

    KeSetEvent( &pNPFcb->Specific.File.ExtentsNotBusy,
                0,
                FALSE );

    AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );
}

//
// Returns with Extents lock EX and noone using them.
//

VOID 
AFSLockForExtentsTrim( IN AFSFcb *Fcb)
{
    NTSTATUS          ntStatus;
    AFSNonPagedFcb *pNPFcb = Fcb->NPFcb;

    while (TRUE) 
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSLockForExtentsTrim Waiting for ExtentsNotBusy event for %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique);

        ntStatus = KeWaitForSingleObject( &pNPFcb->Specific.File.ExtentsNotBusy,
                                          Executive,
                                          KernelMode,
                                          FALSE,
                                          NULL);
        
        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSLockForExtentsTrim ExtentsNotBusy event for %wZ FID %08lX-%08lX-%08lX-%08lX SET\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique);
        
        if (!NT_SUCCESS(ntStatus)) 
        {
            //
            // try again
            //
            continue;
        }

        //
        // Lock resource EX and look again
        //

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSLockForExtentsTrim Acquiring Fcb extent lock %08lX EXCL %08lX\n",
                      &pNPFcb->Specific.File.ExtentsResource,
                      PsGetCurrentThread());

        AFSAcquireExcl( &pNPFcb->Specific.File.ExtentsResource, TRUE );

        if (KeReadStateEvent( &pNPFcb->Specific.File.ExtentsNotBusy )) 
        {

            return;
        }

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSLockForExtentsTrim Retrying wait for ExtentsNotBusy event for %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique);

        //
        // Try again
        //

        AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );
    }
}

//
// return FALSE *or* with Extents lock EX and noone using them
//
BOOLEAN 
AFSLockForExtentsTrimNoWait( IN AFSFcb *Fcb)
{
    AFSNonPagedFcb *pNPFcb = Fcb->NPFcb;

    if (!KeReadStateEvent( &pNPFcb->Specific.File.ExtentsNotBusy )) 
    {
        //
        // Someone using them
        //
        return FALSE;
    }

    AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSLockForExtentsTrimNoWait Attempting to acquiring Fcb extent lock %08lX EXCL %08lX\n",
                  &pNPFcb->Specific.File.ExtentsResource,
                  PsGetCurrentThread());

    if (!AFSAcquireExcl( &pNPFcb->Specific.File.ExtentsResource, FALSE ))
    {
        //
        // Couldn't lock immediately
        //

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSLockForExtentsTrimNoWait Refused to wait for Fcb extent lock %08lX EXCL %08lX\n",
                      &pNPFcb->Specific.File.ExtentsResource,
                      PsGetCurrentThread());

        return FALSE;
    }

    if (!KeReadStateEvent( &pNPFcb->Specific.File.ExtentsNotBusy )) 
    {
        //
        // Drop lock and say no
        //
        
        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSLockForExtentsTrimNoWait Releasing Fcb extent lock %08lX EXCL %08lX\n",
                      &pNPFcb->Specific.File.ExtentsResource,
                      PsGetCurrentThread());

        AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );
        
        return FALSE;
    }

    AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSLockForExtentsTrimNoWait ExtentsNotBusy %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                  &Fcb->DirEntry->DirectoryEntry.FileName,
                  Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                  Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                  Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                  Fcb->DirEntry->DirectoryEntry.FileId.Unique);

    return TRUE;
}
//
// Pull all the extents away from the FCB.
//
NTSTATUS AFSTearDownFcbExtents( IN AFSFcb *Fcb ) 
{
    AFSNonPagedFcb      *pNPFcb = Fcb->NPFcb;
    LIST_ENTRY          *le;
    AFSExtent           *pEntry;
    ULONG                ulCount = 0, ulReleaseCount = 0, ulProcessCount = 0;
    size_t               sz;
    AFSReleaseExtentsCB *pRelease = NULL;
    BOOLEAN              locked = FALSE;
    NTSTATUS             ntStatus;
    ULONGLONG            hExtentProcessId = 0;

    __Enter
    {

        //
        // Grab a process context if we don't have one
        //

        if( Fcb->Specific.File.ExtentProcessId != 0)
        {

            hExtentProcessId = Fcb->Specific.File.ExtentProcessId;
        }
        else
        {

            hExtentProcessId = (ULONGLONG)PsGetCurrentProcessId();
        }

        //
        // Ensure that no one is working with the extents and grab the
        // lock
        //

        AFSLockForExtentsTrim( Fcb );

        locked = TRUE;

#if AFS_VALIDATE_EXTENTS        
        VerifyExtentsLists(Fcb);
#endif

        le = Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST].Flink;

        while (le != &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST]) 
        {
            ulCount ++;
            le = le->Flink;
        }

        if (0 == ulCount)
        {
            try_return ( ntStatus = STATUS_SUCCESS);
        }

        //
        // Release a max of 100 extents at a time
        //

        sz = sizeof( AFSReleaseExtentsCB ) + (AFS_MAXIMUM_EXTENT_RELEASE_COUNT * sizeof ( AFSFileExtentCB ));

        pRelease = (AFSReleaseExtentsCB*) ExAllocatePoolWithTag( NonPagedPool,
                                                                 sz,
                                                                 AFS_EXTENT_RELEASE_TAG);
        if (NULL == pRelease) 
        {

            try_return ( ntStatus = STATUS_INSUFFICIENT_RESOURCES );
        }

        le = Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST].Flink;

        while( ulReleaseCount < ulCount)
        {

            RtlZeroMemory( pRelease,
                           sizeof( AFSReleaseExtentsCB ) + 
                                        (AFS_MAXIMUM_EXTENT_RELEASE_COUNT * sizeof ( AFSFileExtentCB )));

            if( ulCount - ulReleaseCount <= AFS_MAXIMUM_EXTENT_RELEASE_COUNT)
            {
                ulProcessCount = ulCount - ulReleaseCount;
            }
            else
            {
                ulProcessCount = AFS_MAXIMUM_EXTENT_RELEASE_COUNT;
            }

            pRelease->Flags = AFS_EXTENT_FLAG_RELEASE;
            pRelease->ExtentCount = ulProcessCount;
            
            ulProcessCount = 0;
            while (ulProcessCount < pRelease->ExtentCount) 
            {
                pEntry = ExtentFor( le, AFS_EXTENTS_LIST );
            
                pRelease->FileExtents[ulProcessCount].Flags = AFS_EXTENT_FLAG_RELEASE;
                
                if( BooleanFlagOn( pEntry->Flags, AFS_EXTENT_DIRTY))
                {

                    AFSAcquireExcl( &pNPFcb->Specific.File.DirtyExtentsListLock,
                                    TRUE);

                    if( BooleanFlagOn( pEntry->Flags, AFS_EXTENT_DIRTY))
                    {

                        LONG dirtyCount;

                        RemoveEntryList( &pEntry->DirtyList);

                        pRelease->FileExtents[ulProcessCount].Flags |= AFS_EXTENT_FLAG_DIRTY;

                        dirtyCount = InterlockedDecrement( &Fcb->Specific.File.ExtentsDirtyCount);

                        ASSERT( dirtyCount >= 0);

                    }

                    AFSReleaseResource( &pNPFcb->Specific.File.DirtyExtentsListLock);

                }

                pRelease->FileExtents[ulProcessCount].Length = pEntry->Size;
                pRelease->FileExtents[ulProcessCount].CacheOffset = pEntry->CacheOffset;
                pRelease->FileExtents[ulProcessCount].FileOffset = pEntry->FileOffset;

                AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSTearDownFcbExtents Releasing extent for %wZ FID %08lX-%08lX-%08lX-%08lX Offset %I64X Len %08lX Flags %lX\n",
                              &Fcb->DirEntry->DirectoryEntry.FileName,
                              Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                              Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                              Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                              Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                              pEntry->FileOffset.QuadPart,
                              pEntry->Size,
                              pRelease->FileExtents[ulProcessCount].Flags);

                ulProcessCount ++;
                le = le->Flink;
                ExFreePoolWithTag( pEntry, AFS_EXTENT_TAG );
                AFSAllocationMemoryLevel -= sizeof( AFSExtent);

                InterlockedDecrement( &Fcb->Specific.File.ExtentCount);
            }

            //
            // Send the request down.  We cannot send this down
            // asynchronously - if we did that we could requeast them
            // back before the service got this request and then this
            // request would be a corruption.
            //

            sz = sizeof( AFSReleaseExtentsCB ) + (ulProcessCount * sizeof ( AFSFileExtentCB ));

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSTearDownFcbExtents Sending AFS_REQUEST_TYPE_RELEASE_FILE_EXTENTS for file %wZ FID %08lX-%08lX-%08lX-%08lX PID %I64X Count %lX\n",
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          hExtentProcessId,
                          ulProcessCount);

            ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_RELEASE_FILE_EXTENTS,
                                          AFS_REQUEST_FLAG_SYNCHRONOUS,
                                          hExtentProcessId,
                                          NULL,
                                          &Fcb->DirEntry->DirectoryEntry.FileId,
                                          pRelease,
                                          sz,
                                          NULL,
                                          NULL);

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSTearDownFcbExtents AFS_REQUEST_TYPE_RELEASE_FILE_EXTENTS for file %wZ FID %08lX-%08lX-%08lX-%08lX PID %I64X Completed %lX\n",
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          hExtentProcessId,
                          ntStatus);

            ASSERT( STATUS_SUCCESS == ntStatus || STATUS_DEVICE_NOT_READY == ntStatus );

            ulReleaseCount += ulProcessCount;
        }

        //
        // Reinitialize the skip lists
        //

        ASSERT( Fcb->Specific.File.ExtentCount == 0);

        for (ULONG i = 0; i < AFS_NUM_EXTENT_LISTS; i++) 
        {
            InitializeListHead(&Fcb->Specific.File.ExtentsLists[i]);
        }

        //
        // Reinitialize the dirty list as well
        //

        AFSAcquireExcl( &pNPFcb->Specific.File.DirtyExtentsListLock,
                        TRUE);

        ASSERT( Fcb->Specific.File.ExtentsDirtyCount == 0);

        InitializeListHead( &Fcb->NPFcb->Specific.File.DirtyExtentsList);

        AFSReleaseResource( &pNPFcb->Specific.File.DirtyExtentsListLock);

        Fcb->NPFcb->Specific.File.ExtentsRequestStatus = STATUS_SUCCESS;

        AFSReleaseResource( &Fcb->NPFcb->Specific.File.ExtentsResource );
        locked = FALSE;

        //
        // The server promises us to never fail these operations, but check
        //
        ASSERT(NT_SUCCESS(ntStatus) || STATUS_DEVICE_NOT_READY == ntStatus );

        AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSTearDownFcbExtents Completed for file %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      ntStatus);        
      try_exit:


        if (locked)
        {
            AFSReleaseResource( &Fcb->NPFcb->Specific.File.ExtentsResource );
        }

        if (pRelease) {
            ExFreePoolWithTag( pRelease, AFS_EXTENT_RELEASE_TAG );
        }
    }

    return ntStatus;
}

static PAFSExtent
ExtentForOffsetInList( IN AFSFcb *Fcb, 
                       IN LIST_ENTRY *List,
                       IN ULONG ListNumber,
                       IN PLARGE_INTEGER Offset)
{
    //
    // Return the extent that maps the offset, that 
    //   - Contains the offset
    //   - or is immediately ahead of the offset (in this list) 
    //   - otherwise return NULL.
    //

    PLIST_ENTRY  pLe = List;
    AFSExtent   *pPrevious = NULL;

    ASSERT( ExIsResourceAcquiredLite( &Fcb->NPFcb->Specific.File.ExtentsResource ));

    while (pLe != &Fcb->Specific.File.ExtentsLists[ListNumber])
    {
        AFSExtent *entry;
        
        entry = ExtentFor( pLe, ListNumber );

        if (Offset->QuadPart < entry->FileOffset.QuadPart) 
        {
            //
            // Offset is ahead of entry.  Return previous
            //
            return pPrevious;
        }

        if (Offset->QuadPart >= (entry->FileOffset.QuadPart + entry->Size)) 
        {
            //
            // We start after this extent - carry on round
            //
            pPrevious = entry;
            pLe = pLe->Flink;
            continue;
        }

        //
        // Otherwise its a match
        //

        return entry;
    }

    //
    // Got to the end.  Return Previous
    //
    return pPrevious;
}

BOOLEAN 
AFSExtentContains( IN AFSExtent *Extent, IN PLARGE_INTEGER Offset) 
{
    if (NULL == Extent) 
    {
        return FALSE;
    }
    return (Extent->FileOffset.QuadPart <= Offset->QuadPart &&
            (Extent->FileOffset.QuadPart + Extent->Size) > Offset->QuadPart);
}


//
// Return the extent that contains the offset
//
PAFSExtent
AFSExtentForOffsetHint( IN AFSFcb *Fcb, 
                        IN PLARGE_INTEGER Offset,
                        IN BOOLEAN ReturnPrevious,
                        IN AFSExtent *Hint) 
{
    AFSExtent *pPrevious = Hint;
    LIST_ENTRY *pLe;
    LONG i;
    
    ASSERT( ExIsResourceAcquiredLite( &Fcb->NPFcb->Specific.File.ExtentsResource ));

#if AFS_VALIDATE_EXTENTS
    VerifyExtentsLists(Fcb);
#endif

    //
    // So we will go across the skip lists until we find an
    // appropriate entry (previous or direct match).  If it's a match
    // we are done, other wise we start on the next layer down
    //
    for (i = AFS_NUM_EXTENT_LISTS-1; i >= AFS_EXTENTS_LIST; i--)
    {
        if (NULL == pPrevious) 
        {
            //
            // We haven't found anything in the previous layers
            //
            pLe = Fcb->Specific.File.ExtentsLists[i].Flink;
        }
        else if (NULL == pPrevious->Lists[i].Flink) 
        {
            ASSERT(AFS_EXTENTS_LIST != i);
            //
            // The hint doesn't exist at this level, next one down
            //
            continue;
        }
        else
        {
            //
            // take the previous into the next
            //
            pLe = &pPrevious->Lists[i];
        }

        pPrevious = ExtentForOffsetInList( Fcb, pLe, i, Offset);

        if (NULL != pPrevious && AFSExtentContains(pPrevious, Offset)) 
        {
            //
            // Found it immediately.  Stop here
            //
            return pPrevious;
        }
    }

    if (NULL == pPrevious || ReturnPrevious )
    {       
        return pPrevious;
    }

    ASSERT( !AFSExtentContains(pPrevious, Offset) );

    return NULL;
}

LIST_ENTRY *
AFSEntryForOffset( IN AFSFcb *Fcb, 
                   IN PLARGE_INTEGER Offset) 
{
    AFSExtent *pPrevious = NULL;
    LIST_ENTRY *pLe;
    LONG i;
    
    ASSERT( ExIsResourceAcquiredLite( &Fcb->NPFcb->Specific.File.ExtentsResource ));

#if AFS_VALIDATE_EXTENTS
    VerifyExtentsLists(Fcb);
#endif

    //
    // So we will go across the skip lists until we find an
    // appropriate entry (previous or direct match).  If it's a match
    // we are done, other wise we start on the next layer down
    //
    for (i = AFS_NUM_EXTENT_LISTS-1; i >= AFS_EXTENTS_LIST; i--)
    {
        if (NULL == pPrevious) 
        {
            //
            // We haven't found anything in the previous layers
            //
            pLe = Fcb->Specific.File.ExtentsLists[i].Flink;
        }
        else if (NULL == pPrevious->Lists[i].Flink) 
        {
            ASSERT(AFS_EXTENTS_LIST != i);
            //
            // The hint doesn't exist at this level, next one down
            //
            continue;
        }
        else
        {
            //
            // take the previous into the next
            //
            pLe = &pPrevious->Lists[i];
        }

        pPrevious = ExtentForOffsetInList( Fcb, pLe, i, Offset);

        if (NULL != pPrevious && AFSExtentContains(pPrevious, Offset)) 
        {
            //
            // Found it immediately.  Stop here
            //
            return pLe;
        }
    }

    return NULL;
}

PAFSExtent
AFSExtentForOffset( IN AFSFcb *Fcb, 
                    IN PLARGE_INTEGER Offset,
                    IN BOOLEAN ReturnPrevious)
{
    return AFSExtentForOffsetHint(Fcb, Offset, ReturnPrevious, NULL);
}


BOOLEAN AFSDoExtentsMapRegion(IN AFSFcb *Fcb, 
                              IN PLARGE_INTEGER Offset, 
                              IN ULONG Size,
                              IN OUT AFSExtent **FirstExtent,
                              OUT AFSExtent **LastExtent)
{
    //
    // Return TRUE region is completely mapped.  FALSE
    // otherwise.  If the region isn't mapped then the last
    // extent to map part of the region is returned.
    //
    // *LastExtent as input is where to start looking.
    // *LastExtent as output is either the extent which
    //  contains the Offset, or the last one which doesn't
    //
    AFSExtent *entry;
    AFSExtent *newEntry;
    BOOLEAN retVal = FALSE;
    
    AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSDoExtentsMapRegion Acquiring Fcb extent lock %08lX SHARED %08lX\n",
                  &Fcb->NPFcb->Specific.File.ExtentsResource,
                  PsGetCurrentThread());

    AFSAcquireShared( &Fcb->NPFcb->Specific.File.ExtentsResource, TRUE );

    __Enter
    {
        entry = AFSExtentForOffsetHint(Fcb, Offset, TRUE, *FirstExtent);
        *FirstExtent = entry;

        if (NULL == entry || !AFSExtentContains(entry, Offset)) 
        {
            try_return (retVal = FALSE);
        }
        
        ASSERT(Offset->QuadPart >= entry->FileOffset.QuadPart);
            
        while (TRUE) 
        {
            if ((entry->FileOffset.QuadPart + entry->Size) >= 
                                                (Offset->QuadPart + Size)) 
            {
                //
                // The end is inside the extent
                //
                try_return (retVal = TRUE);
            }
        
            if (entry->Lists[AFS_EXTENTS_LIST].Flink == &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST]) 
            {
                //
                // Run out of extents
                //
                try_return (retVal = FALSE);
            }

            newEntry = NextExtent( entry, AFS_EXTENTS_LIST );

            if (newEntry->FileOffset.QuadPart !=
                (entry->FileOffset.QuadPart + entry->Size)) 
            {
                //
                // Gap
                //
                try_return (retVal = FALSE);
            }

            entry = newEntry;
        }
try_exit:

    AFSReleaseResource( &Fcb->NPFcb->Specific.File.ExtentsResource );    
    }
    *LastExtent = entry;
    return retVal;
}
    
//
// Given an FCB and an Offset we look to see whether there extents to
// Map them all.  If there are then we return TRUE to fullymapped
// and *FirstExtent points to the first extent to map the extent.
// If not then we return FALSE, but we request the extents to be mapped.
// Further *FirstExtent (if non null) is the last extent which doesn't
// map the extent.
//
// Finally on the way *in* if *FirstExtent is non null it is where we start looking
//

NTSTATUS
AFSRequestExtents( IN AFSFcb *Fcb, 
                   IN PLARGE_INTEGER Offset, 
                   IN ULONG Size,
                   OUT BOOLEAN *FullyMapped)
{

    AFSDeviceExt        *pDevExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;
    NTSTATUS             ntStatus = STATUS_SUCCESS;
    AFSExtent           *pExtent;
    AFSRequestExtentsCB  request;
    AFSNonPagedFcb      *pNPFcb = Fcb->NPFcb;
    AFSExtent           *pFirstExtent;
    LARGE_INTEGER        liAlignedOffset;
    ULONG                ulAlignedLength = 0;
    LARGE_INTEGER        liTimeOut;
    
    //
    // Check our extents, then fire off a request if we need to.
    //

    ASSERT( !ExIsResourceAcquiredLite( &pNPFcb->Specific.File.ExtentsResource ));

    //
    // We start off knowing nothing about where we will go.
    //
    pFirstExtent = NULL;

    AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSRequestExtents File %wZ FID %08lX-%08lX-%08lX-%08lX Offset %I64X Length %08lX\n",
                  &Fcb->DirEntry->DirectoryEntry.FileName,
                  Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                  Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                  Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                  Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                  Offset->QuadPart,
                  Size);        

    *FullyMapped = AFSDoExtentsMapRegion( Fcb, Offset, Size, &pFirstExtent, &pExtent );

    if (*FullyMapped) 
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSRequestExtents File %wZ FID %08lX-%08lX-%08lX-%08lX Offset %I64X Length %08lX Fully mapped\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      Offset->QuadPart,
                      Size);        

        ASSERT(AFSExtentContains(pFirstExtent, Offset));
        LARGE_INTEGER end = *Offset;
        end.QuadPart += (Size-1);
        ASSERT(AFSExtentContains(pExtent, &end));

        return STATUS_SUCCESS;
    } 

    //
    // So we need to queue a request. Since we will be clearing the
    // ExtentsRequestComplete event we need to do with with the lock
    // EX
    //

    liTimeOut.QuadPart = -(50000000);
    
    while (TRUE) 
    {
        if (!NT_SUCCESS( pNPFcb->Specific.File.ExtentsRequestStatus)) 
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSRequestExtents File %wZ FID %08lX-%08lX-%08lX-%08lX Failure from service Status %08lX\n",
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          pNPFcb->Specific.File.ExtentsRequestStatus);        

            //
            // The cache has been torn down.  Nothing to wait for
            //

            ntStatus = pNPFcb->Specific.File.ExtentsRequestStatus;

            break;
        }

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSRequestExtents Waiting on ExtentsRequestComplete event for file %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique
                      );

        ntStatus = KeWaitForSingleObject( &pNPFcb->Specific.File.ExtentsRequestComplete,
                                          Executive,
                                          KernelMode,
                                          FALSE,
                                          &liTimeOut);
        if (!NT_SUCCESS(ntStatus)) 
        {

            //
            // try again
            //

            continue;
        }

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSRequestExtents ExtentsRequestComplete event SET for file %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique
                      );

        //
        // Lock resource EX and look again
        //

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSRequestExtents Acquiring Fcb extent lock %08lX EXCL %08lX\n",
                      &pNPFcb->Specific.File.ExtentsResource,
                      PsGetCurrentThread());

        AFSAcquireExcl( &pNPFcb->Specific.File.ExtentsResource, TRUE );

        if (!NT_SUCCESS( pNPFcb->Specific.File.ExtentsRequestStatus)) 
        {

            //
            // Teardown event sensed.  Return
            //
            ntStatus = pNPFcb->Specific.File.ExtentsRequestStatus;

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSRequestExtents File %wZ FID %08lX-%08lX-%08lX-%08lX Failure from service Status %08lX\n",
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          ntStatus);        

            AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );

            break;
        }

        if( KeReadStateEvent( &pNPFcb->Specific.File.ExtentsRequestComplete) ||
            ntStatus == STATUS_TIMEOUT)
        {

            ntStatus = pNPFcb->Specific.File.ExtentsRequestStatus;

            if( !NT_SUCCESS( ntStatus))
            {

                AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSRequestExtents File %wZ FID %08lX-%08lX-%08lX-%08lX Failure from service Status %08lX\n",
                              &Fcb->DirEntry->DirectoryEntry.FileName,
                              Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                              Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                              Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                              Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                              ntStatus);        

                AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );
            }

            break;
        }

        AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );
    }

    if (!NT_SUCCESS(ntStatus)) 
    {

        return ntStatus;
    }

    __Enter
    {
        //
        // We have the lock Ex and there is no filling going on.
        // Check again to see whether things have moved since we last
        // checked.  Since we haven't locked against pinning, we will
        // reset here.  
        //

        pFirstExtent = NULL;
        
        *FullyMapped = AFSDoExtentsMapRegion(Fcb, Offset, Size, &pFirstExtent, &pExtent);

        if (*FullyMapped) 
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSRequestExtents File %wZ FID %08lX-%08lX-%08lX-%08lX Offset %I64X Length %08lX Fully mapped (Second check)\n",
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          Offset->QuadPart,
                          Size);        

            ASSERT(AFSExtentContains(pFirstExtent, Offset));
            LARGE_INTEGER end = *Offset;
            end.QuadPart += (Size-1);
            ASSERT(AFSExtentContains(pExtent, &end));
            
            try_return (ntStatus = STATUS_SUCCESS);
        }

        RtlZeroMemory( &request, 
                       sizeof( AFSRequestExtentsCB));

        //
        // Align the request
        //

        ulAlignedLength = Size;

        liAlignedOffset = *Offset;

        if( liAlignedOffset.QuadPart % pDevExt->Specific.RDR.CacheBlockSize != 0)
        {

            liAlignedOffset.QuadPart = (ULONGLONG)( (ULONGLONG)(liAlignedOffset.QuadPart / pDevExt->Specific.RDR.CacheBlockSize) * (ULONGLONG)pDevExt->Specific.RDR.CacheBlockSize);

            ulAlignedLength += (ULONG)(Offset->QuadPart - liAlignedOffset.QuadPart);
        }

        if( ulAlignedLength % pDevExt->Specific.RDR.CacheBlockSize != 0)
        {

            ulAlignedLength = (ULONG)(((ulAlignedLength / pDevExt->Specific.RDR.CacheBlockSize) + 1) * pDevExt->Specific.RDR.CacheBlockSize);
        }

        //
        // If the requested length is larger than the AFS cache manager's
        // maximum rpc length, break the request up into multiple requests
        // of the maximum rpc length.  these requests could be parallelized
        // to improve performance.
        //
        do {
                
            request.ByteOffset = liAlignedOffset;
            request.Length = ulAlignedLength > pDevExt->Specific.RDR.MaximumRPCLength ? pDevExt->Specific.RDR.MaximumRPCLength : ulAlignedLength;

            ASSERT( request.Length <= pDevExt->Specific.RDR.MaximumRPCLength);

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSRequestExtents Requesting extents for %wZ FID %08lX-%08lX-%08lX-%08lX Offset %I64X Length %08lX\n",
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          liAlignedOffset.QuadPart,
                          ulAlignedLength);        

            ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_REQUEST_FILE_EXTENTS,
                                          0,
                                          Fcb->Specific.File.ExtentProcessId,
                                          NULL,
                                          &Fcb->DirEntry->DirectoryEntry.FileId,
                                          &request,
                                          sizeof( AFSRequestExtentsCB ),
                                          NULL,
                                          NULL);

            if( NT_SUCCESS( ntStatus)) 
            {

                KeClearEvent( &pNPFcb->Specific.File.ExtentsRequestComplete );
            }

            if ( request.Length == ulAlignedLength ||
                 !NT_SUCCESS( ntStatus))
            {
                break;
            }

            ulAlignedLength -= pDevExt->Specific.RDR.MaximumRPCLength;
            liAlignedOffset.QuadPart += pDevExt->Specific.RDR.MaximumRPCLength;

        } while ( TRUE);

try_exit:

        if (NT_SUCCESS( ntStatus )) 
        {
            KeQueryTickCount( &Fcb->Specific.File.LastExtentAccess );
        }

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSRequestExtents Completed for %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      ntStatus);        
    
        AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );    
    }

    return ntStatus;
}

NTSTATUS
AFSRequestExtentsAsync( IN AFSFcb *Fcb, 
                        IN PLARGE_INTEGER Offset, 
                        IN ULONG Size)
{

    AFSDeviceExt        *pDevExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;
    NTSTATUS             ntStatus = STATUS_SUCCESS;
    AFSExtent           *pExtent;
    AFSRequestExtentsCB  request;
    AFSNonPagedFcb      *pNPFcb = Fcb->NPFcb;
    AFSExtent           *pFirstExtent = NULL;
    LARGE_INTEGER        liAlignedOffset;
    ULONG                ulAlignedLength = 0;
    BOOLEAN              bRegionMapped = FALSE;
    
    __Enter
    {

        ASSERT( !ExIsResourceAcquiredLite( &pNPFcb->Specific.File.ExtentsResource ));

        //
        // Check if we are already mapped
        //

        bRegionMapped = AFSDoExtentsMapRegion( Fcb, Offset, Size, &pFirstExtent, &pExtent);

        if( bRegionMapped) 
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSRequestExtentsAsync File %wZ FID %08lX-%08lX-%08lX-%08lX Offset %I64X Length %08lX Fully mapped\n",
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          Offset->QuadPart,
                          Size);        

            try_return( ntStatus = STATUS_SUCCESS);
        }

        //
        // Align our request on extent size boundary
        //

        ulAlignedLength = Size;

        liAlignedOffset = *Offset;

        if( liAlignedOffset.QuadPart % pDevExt->Specific.RDR.CacheBlockSize != 0)
        {

            liAlignedOffset.QuadPart = (ULONGLONG)( (ULONGLONG)(liAlignedOffset.QuadPart / pDevExt->Specific.RDR.CacheBlockSize) * (ULONGLONG)pDevExt->Specific.RDR.CacheBlockSize);

            ulAlignedLength += (ULONG)(Offset->QuadPart - liAlignedOffset.QuadPart);
        }

        if( ulAlignedLength % pDevExt->Specific.RDR.CacheBlockSize != 0)
        {

            ulAlignedLength = (ULONG)(((ulAlignedLength / pDevExt->Specific.RDR.CacheBlockSize) + 1) * pDevExt->Specific.RDR.CacheBlockSize);
        }

        RtlZeroMemory( &request, 
                       sizeof( AFSRequestExtentsCB));

        //
        // If the requested length is larger than the AFS cache manager's
        // maximum rpc length, break the request up into multiple requests
        // of the maximum rpc length.  these requests could be parallelized
        // to improve performance.
        //
        do {
                
            request.ByteOffset = liAlignedOffset;
            request.Length = ulAlignedLength > pDevExt->Specific.RDR.MaximumRPCLength ? pDevExt->Specific.RDR.MaximumRPCLength : ulAlignedLength;

            ASSERT( request.Length <= pDevExt->Specific.RDR.MaximumRPCLength);

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSRequestExtentsAsync Requesting extents for %wZ FID %08lX-%08lX-%08lX-%08lX Offset %I64X Length %08lX Original Offset %I64X Len %08lX\n",
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          liAlignedOffset.QuadPart,
                          ulAlignedLength,
                          Offset->QuadPart,
                          Size);        

            ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_REQUEST_FILE_EXTENTS,
                                          0,
                                          Fcb->Specific.File.ExtentProcessId,
                                          NULL,
                                          &Fcb->DirEntry->DirectoryEntry.FileId,
                                          &request,
                                          sizeof( AFSRequestExtentsCB ),
                                          NULL,
                                          NULL);

            if( NT_SUCCESS( ntStatus)) 
            {

                KeClearEvent( &pNPFcb->Specific.File.ExtentsRequestComplete );
            }

            if ( request.Length == ulAlignedLength ||
                 !NT_SUCCESS( ntStatus))
            {
                break;
            }

            ulAlignedLength -= pDevExt->Specific.RDR.MaximumRPCLength;
            liAlignedOffset.QuadPart += pDevExt->Specific.RDR.MaximumRPCLength;

        } while ( TRUE);

try_exit:

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSRequestExtentsAsync Completed for %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      ntStatus);        
    }

    return ntStatus;
}

NTSTATUS
AFSProcessExtentsResult( IN AFSFcb *Fcb,
                         IN ULONG   Count,
                         IN AFSFileExtentCB *Result)
{
    NTSTATUS          ntStatus = STATUS_SUCCESS;
    AFSFileExtentCB  *pFileExtents = Result;
    AFSExtent        *pExtent;
    LIST_ENTRY       *le;
    AFSNonPagedFcb   *pNPFcb = Fcb->NPFcb;
    ULONG             fileExtentsUsed = 0;
    BOOLEAN           bFoundExtent = FALSE;
    LIST_ENTRY       *pSkipEntries[AFS_NUM_EXTENT_LISTS] = { 0 };
    BOOLEAN           bInsertedEntry = FALSE;

    //
    // Grab the extents exclusive for the duration
    //

    AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSProcessExtentsResult Acquiring Fcb extent lock %08lX EXCL %08lX\n",
                  &pNPFcb->Specific.File.ExtentsResource,
                  PsGetCurrentThread());

    AFSAcquireExcl( &pNPFcb->Specific.File.ExtentsResource, TRUE );

    __Enter 
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessExtentsResult Entered for %wZ FID %08lX-%08lX-%08lX-%08lX Count %08lX Starting offset %I64X Size %08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      Count,
                      pFileExtents->FileOffset.QuadPart,
                      pFileExtents->Length);        

        //
        // Find where to put the extents
        //
        for (ULONG i = AFS_EXTENTS_LIST; i < AFS_NUM_EXTENT_LISTS; i++)
        {

            pSkipEntries[i] = Fcb->Specific.File.ExtentsLists[i].Flink;
        }

        le = pSkipEntries[AFS_EXTENTS_LIST];

        if (le == &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST]) 
        {
            //
            // No extents.  Insert at head of list (which is where the skip lists point!)
            //
            pExtent = NULL;
        } 
        else if (0 != pFileExtents->FileOffset.QuadPart) 
        {
            //
            // We want to find the best extents immediately *behind* this offset
            //
            LARGE_INTEGER offset = pFileExtents->FileOffset;

            //
            // Ask in the top skip list first, then work down
            //
            for (LONG i = AFS_NUM_EXTENT_LISTS-1; i >= AFS_EXTENTS_LIST; i--)
            {
                pExtent = ExtentForOffsetInList( Fcb,
                                                 pSkipEntries[i],
                                                 i,
                                                 &offset);
                
                if (NULL == pExtent) 
                {
                    //
                    // No dice.  Header has to become the head of the list
                    //
                    pSkipEntries[i] = &Fcb->Specific.File.ExtentsLists[i];
                    //
                    // And as  a loop invariant we should never have found an extent
                    //
                    ASSERT(!bFoundExtent);
                }
                else
                {
                    //
                    // pExtent is where to start to insert at this level
                    //
                    pSkipEntries[i] = &pExtent->Lists[i];
                        
                    //
                    // And also where to start to look at the next level
                    //
                        
                    if (i > AFS_EXTENTS_LIST)
                    {
                        pSkipEntries[i-1] = &pExtent->Lists[i-1];
                    }
                    bFoundExtent = TRUE;
                }
            }
                
            if (NULL == pExtent) 
            {
                pExtent = ExtentFor( le, AFS_EXTENTS_LIST);
                le = le->Blink;
            } 
            else
            {
                le = pExtent->Lists[AFS_EXTENTS_LIST].Blink;
            }
        }
        else 
        {
            // 
            // Looking at offset 0, so we must start at the beginning
            //

            pExtent = ExtentFor(le, AFS_EXTENTS_LIST);
            le = le->Blink;

            //
            // And set up the skip lists
            //

            for (ULONG i = AFS_EXTENTS_LIST; i < AFS_NUM_EXTENT_LISTS; i++)
            {
                pSkipEntries[i] = &Fcb->Specific.File.ExtentsLists[i];
            }
        }

        while (fileExtentsUsed < Count) 
        {

            //
            // Loop invariant - le points to where to insert after and
            // pExtent points to le->fLink
            //
            
            ASSERT (NULL == pExtent ||
                    le->Flink == &pExtent->Lists[AFS_EXTENTS_LIST]);
 
            if (NULL == pExtent ||
                pExtent->FileOffset.QuadPart > pFileExtents->FileOffset.QuadPart)
            {
                //
                // We need to insert a new extent at le.  Start with
                // some sanity check on spanning
                //
                if (NULL != pExtent &&
                    ((pFileExtents->FileOffset.QuadPart + pFileExtents->Length) >
                     pExtent->FileOffset.QuadPart))
                {
                    //
                    // File Extents overlaps pExtent
                    //
                    ASSERT( (pFileExtents->FileOffset.QuadPart + pFileExtents->Length) <=
                            pExtent->FileOffset.QuadPart);
            
                    try_return (ntStatus = STATUS_INVALID_PARAMETER);
                }

                //
                // File offset is entirely in front of this extent.  Create
                // a new one (remember le is the previous list entry)
                //
                pExtent = (AFSExtent *) ExAllocatePoolWithTag( NonPagedPool,
                                                               sizeof( AFSExtent),
                                                               AFS_EXTENT_TAG );
                if (NULL  == pExtent) 
                {

                    ASSERT( FALSE);

                    try_return (ntStatus = STATUS_INSUFFICIENT_RESOURCES );
                }
                AFSAllocationMemoryLevel += sizeof( AFSExtent);
    
                RtlZeroMemory( pExtent, sizeof( AFSExtent ));

                pExtent->FileOffset = pFileExtents->FileOffset;
                pExtent->CacheOffset = pFileExtents->CacheOffset;
                pExtent->Size = pFileExtents->Length;

                InterlockedIncrement( &Fcb->Specific.File.ExtentCount);

                AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSProcessExtentsResult Adding extent for %wZ FID %08lX-%08lX-%08lX-%08lX Offset %I64X Len %08lX\n",
                              &Fcb->DirEntry->DirectoryEntry.FileName,
                              Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                              Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                              Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                              Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                              pFileExtents->FileOffset.QuadPart,
                              pFileExtents->Length);        

                //
                // Insert into list
                //
                InsertHeadList(le, &pExtent->Lists[AFS_EXTENTS_LIST]);
                ASSERT(le->Flink == &pExtent->Lists[AFS_EXTENTS_LIST]);
                ASSERT(0 == (pExtent->FileOffset.LowPart & ExtentsMasks[AFS_EXTENTS_LIST]));

                //
                // Do not move the cursor - we will do it next time
                //

                //
                // And into the (upper) skip lists - Again, do not move the cursor
                //
                for (ULONG i = AFS_NUM_EXTENT_LISTS-1; i > AFS_EXTENTS_LIST; i--)
                {
                    if (0 == (pExtent->FileOffset.LowPart & ExtentsMasks[i]))
                    {
                        InsertHeadList(pSkipEntries[i], &pExtent->Lists[i]);
#if AFS_VALIDATE_EXTENTS
                        VerifyExtentsLists(Fcb);
#endif
                    }
                }

                bInsertedEntry = TRUE;
            } 
            else if (pExtent->FileOffset.QuadPart == pFileExtents->FileOffset.QuadPart)
            {

                if( !bInsertedEntry)
                {

                    ASSERT( FALSE);
                }
                else
                {

                    bInsertedEntry = TRUE;
                }

                if (pExtent->Size != pFileExtents->Length) 
                {

                    ASSERT (pExtent->Size == pFileExtents->Length);
                
                    try_return (ntStatus = STATUS_INVALID_PARAMETER);
                }
            
                //
                // Move both cursors forward.
                //
                // First the extent pointer
                //
                fileExtentsUsed++;
                le = &pExtent->Lists[AFS_EXTENTS_LIST];

                //
                // Then the skip lists cursors forward if needed
                //
                for (ULONG i = AFS_NUM_EXTENT_LISTS-1; i > AFS_EXTENTS_LIST; i--)
                {
                    if (0 == (pExtent->FileOffset.LowPart & ExtentsMasks[i]))
                    {
                        //
                        // Check sanity before
                        //
#if AFS_VALIDATE_EXTENTS
                        VerifyExtentsLists(Fcb);
#endif

                        //
                        // Skip list should point to us
                        //
                        //ASSERT(pSkipEntries[i] == &pExtent->Lists[i]);
                        //
                        // Move forward cursor
                        //
                        pSkipEntries[i] = pSkipEntries[i]->Flink;
                        //
                        // Check sanity before
                        //
#if AFS_VALIDATE_EXTENTS
                        VerifyExtentsLists(Fcb);
#endif
                    }
                }

                //
                // And then the cursor in the supplied array
                //

                pFileExtents++;

                //
                // setup pExtent if there is one
                // 
                if (le->Flink != &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST])
                {
                    pExtent = NextExtent( pExtent, AFS_EXTENTS_LIST ) ;
                } 
                else 
                {
                    pExtent = NULL;
                }
            } 
            else 
            {

                ASSERT( pExtent->FileOffset.QuadPart < pFileExtents->FileOffset.QuadPart );

                //
                // Sanity check on spanning
                //
                if ((pExtent->FileOffset.QuadPart + pExtent->Size) >
                    pFileExtents->FileOffset.QuadPart) 
                {

                    ASSERT( (pExtent->FileOffset.QuadPart + pExtent->Size) <=
                            pFileExtents->FileOffset.QuadPart);
            
                    try_return (ntStatus = STATUS_INVALID_PARAMETER);
                }
            
                //
                // Move le and pExtent forward
                //
                le = &pExtent->Lists[AFS_EXTENTS_LIST];

                //
                // Then the check the skip lists cursors
                //
                for (ULONG i = AFS_NUM_EXTENT_LISTS-1; i > AFS_EXTENTS_LIST; i--)
                {
                    if (0 == (pFileExtents->FileOffset.LowPart & ExtentsMasks[i]))
                    {
                        //
                        // Three options:
                        //    - empty list (pSkipEntries[i]->Flink == pSkipEntries[i]->Flink == fcb->lists[i]
                        //    - We are the last on the list (pSkipEntries[i]->Flink == fcb->lists[i])
                        //    - We are not the last on the list.  In that case we have to be strictly less than
                        //      that extent.
                        if (pSkipEntries[i]->Flink != &Fcb->Specific.File.ExtentsLists[i]) {

                            AFSExtent *otherExtent = ExtentFor(pSkipEntries[i]->Flink, i);
                            ASSERT(pFileExtents->FileOffset.LowPart < otherExtent->FileOffset.QuadPart);
                        }
                    }
                }

                //
                // setup pExtent if there is one
                //

                if (le->Flink != &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST])
                {
                    pExtent = NextExtent( pExtent, AFS_EXTENTS_LIST ) ;
                } 
                else 
                {
                    pExtent = NULL;
                }
            }
        }

        //
        // All done, signal that we are done drop the lock, exit
        //

try_exit:

        if( !NT_SUCCESS( ntStatus))
        {

            //
            // If we failed the service is going to drop all extents so trim away the 
            // set given to us
            //

            AFSTrimSpecifiedExtents( Fcb,
                                     Count,
                                     Result);
        }

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessExtentsResult Completed for %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX Setting ExtentsRequestComplete event\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      ntStatus);        

#if AFS_VALIDATE_EXTENTS
        VerifyExtentsLists(Fcb);
#endif

        KeSetEvent( &pNPFcb->Specific.File.ExtentsRequestComplete,
                    0,
                    FALSE);

        AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );
    }

    return ntStatus;
}

NTSTATUS
AFSProcessSetFileExtents( IN AFSSetFileExtentsCB *SetExtents )
{
    AFSFcb       *pFcb = NULL, *pVcb = NULL;
    NTSTATUS      ntStatus = STATUS_SUCCESS;
    AFSDeviceExt *pDevExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;
    ULONGLONG     ullIndex = 0;

    __Enter 
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessSetFileExtents Acquiring RDR VolumeTreeLock lock %08lX SHARED %08lX\n",
                      &pDevExt->Specific.RDR.VolumeTreeLock,
                      PsGetCurrentThread());

        AFSAcquireShared( &pDevExt->Specific.RDR.VolumeTreeLock, TRUE);

        //
        // Locate the volume node
        //

        ullIndex = AFSCreateHighIndex( &SetExtents->FileId);

        ntStatus = AFSLocateHashEntry( pDevExt->Specific.RDR.VolumeTree.TreeHead,
                                       ullIndex,
                                       &pVcb);

        if( pVcb != NULL)
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSProcessSetFileExtents Acquiring VolumeRoot FileIDTree.TreeLock lock %08lX SHARED %08lX\n",
                          pVcb->Specific.VolumeRoot.FileIDTree.TreeLock,
                          PsGetCurrentThread());

            AFSAcquireShared( pVcb->Specific.VolumeRoot.FileIDTree.TreeLock,
                              TRUE);
        }

        AFSReleaseResource( &pDevExt->Specific.RDR.VolumeTreeLock);

        if( !NT_SUCCESS( ntStatus) ||
            pVcb == NULL) 
        {

            ASSERT( FALSE);

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessSetFileExtents Invalid volume index %I64X\n",
                          ullIndex);        

            try_return( ntStatus = STATUS_UNSUCCESSFUL);
        }

        //
        // Now locate the Fcb in this volume
        //

        ullIndex = AFSCreateLowIndex( &SetExtents->FileId);

        ntStatus = AFSLocateHashEntry( pVcb->Specific.VolumeRoot.FileIDTree.TreeHead,
                                       ullIndex,
                                       &pFcb);

        AFSReleaseResource( pVcb->Specific.VolumeRoot.FileIDTree.TreeLock);

        if( !NT_SUCCESS( ntStatus) ||
            pFcb == NULL) 
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessSetFileExtents Invalid file index %I64X\n",
                          ullIndex);        

            try_return( ntStatus = STATUS_UNSUCCESSFUL);
        }

        //
        // If we have a result failure then don't bother trying to set the extents
        //

        if( SetExtents->ResultStatus != STATUS_SUCCESS)
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessSetFileExtents Failed to retrieve extents for %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX\n", 
                          &pFcb->DirEntry->DirectoryEntry.FileName,
                          pFcb->DirEntry->DirectoryEntry.FileId.Cell,
                          pFcb->DirEntry->DirectoryEntry.FileId.Volume,
                          pFcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          pFcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          SetExtents->ResultStatus);        

            AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSProcessSetFileExtents Acquiring Fcb extents lock %08lX EXCL %08lX\n",
                          &pFcb->NPFcb->Specific.File.ExtentsResource,
                          PsGetCurrentThread());

            AFSAcquireExcl( &pFcb->NPFcb->Specific.File.ExtentsResource, 
                            TRUE);

            pFcb->NPFcb->Specific.File.ExtentsRequestStatus = STATUS_CANCELLED;

            KeSetEvent( &pFcb->NPFcb->Specific.File.ExtentsRequestComplete,
                        0,
                        FALSE);

            AFSReleaseResource( &pFcb->NPFcb->Specific.File.ExtentsResource);

            try_return( ntStatus);
        }

        ntStatus = AFSProcessExtentsResult ( pFcb, 
                                             SetExtents->ExtentCount, 
                                             SetExtents->FileExtents );

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessSetFileExtents Completed for %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX\n", 
                      &pFcb->DirEntry->DirectoryEntry.FileName,
                      pFcb->DirEntry->DirectoryEntry.FileId.Cell,
                      pFcb->DirEntry->DirectoryEntry.FileId.Volume,
                      pFcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      pFcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      ntStatus);        

try_exit:

        NOTHING;
    }

    return ntStatus;
}

//
// Helper fuctions for Usermode initiation of release of extents
//
NTSTATUS
AFSReleaseSpecifiedExtents( IN  AFSReleaseFileExtentsCB *Extents,
                            IN  AFSFcb *Fcb,
                            OUT AFSFileExtentCB *FileExtents,
                            IN  ULONG BufferSize,
                            OUT ULONG *ExtentCount)
{
    AFSExtent           *pExtent;
    LIST_ENTRY          *le;
    LIST_ENTRY          *leNext;
    BOOLEAN              locked = FALSE;
    ULONG                ulExtentCount = 0;
    NTSTATUS             ntStatus;

    __Enter 
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSReleaseSpecifiedExtents Entered for %wZ FID %08lX-%08lX-%08lX-%08lX\n", 
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique
                      );

        if (BufferSize < (Extents->ExtentCount * sizeof(AFSFileExtentCB)))
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSReleaseSpecifiedExtents Buffer too small for %wZ FID %08lX-%08lX-%08lX-%08lX\n", 
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique
                          );

            try_return(STATUS_BUFFER_TOO_SMALL);
        }

        RtlZeroMemory( FileExtents, BufferSize);
        *ExtentCount = 0;

        //
        // Flush out anything which might be dirty
        //

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSReleaseSpecifiedExtents Flushing extents for %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique
                      );

        ntStatus = AFSFlushExtents( Fcb);

        if (!NT_SUCCESS(ntStatus)) 
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSReleaseSpecifiedExtents Failed flush extents for %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX\n", 
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          ntStatus);        

            try_return( ntStatus );
        }

        //
        // Make sure noone is using the extents and return with the
        // lock held
        //

        AFSLockForExtentsTrim( Fcb );

        locked = TRUE;

        //
        // iterate until we have dealt with all we were asked for or
        // are at the end of the list.  Note that this deals (albeit
        // badly) with out of order extents
        //

        pExtent = AFSExtentForOffset( Fcb,
                                      &Extents->FileExtents[0].FileOffset,
                                      FALSE );

        if (NULL == pExtent) 
        {
            le = Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST].Flink;
        } 
        else
        {
            le = &pExtent->Lists[AFS_EXTENTS_LIST];
        }
        ulExtentCount = 0;

        while (le != &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST] && 
               ulExtentCount < Extents->ExtentCount) 
        {
            pExtent = ExtentFor( le, AFS_EXTENTS_LIST);
            
            AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSReleaseSpecifiedExtents For %wZ FID %08lX-%08lX-%08lX-%08lX locating offset %I64X Len %08lX\n", 
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          pExtent->FileOffset.QuadPart,
                          pExtent->Size);        

            if (pExtent->FileOffset.QuadPart < Extents->FileExtents[ulExtentCount].FileOffset.QuadPart) 
            {
                //
                // Skip forward through the extent list until we get
                // to the one we want
                //
                le = le->Flink;
            } 
            else if (pExtent->FileOffset.QuadPart > Extents->FileExtents[ulExtentCount].FileOffset.QuadPart) 
            {
                //
                // We don't have the extent asked for (or out of order)
                //
                ulExtentCount ++;
            } 
            else 
            {

                AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSReleaseSpecifiedExtents For %wZ FID %08lX-%08lX-%08lX-%08lX releasing offset %I64X Len %08lX\n", 
                              &Fcb->DirEntry->DirectoryEntry.FileName,
                              Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                              Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                              Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                              Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                              pExtent->FileOffset.QuadPart,
                              pExtent->Size);        

                //
                // This is one to purge
                //
                FileExtents[*ExtentCount] = Extents->FileExtents[ulExtentCount];
                FileExtents[*ExtentCount].Flags = AFS_EXTENT_FLAG_RELEASE;
                //
                // move forward all three cursors
                //
                le = le->Flink;
                ulExtentCount ++;
                *ExtentCount = (*ExtentCount) + 1;

                //
                // And unpick
                //
                for (ULONG i = 0; i < AFS_NUM_EXTENT_LISTS; i ++) 
                {
                    if (NULL != pExtent->Lists[i].Flink && !IsListEmpty(&pExtent->Lists[i]))
                    {
                        RemoveEntryList( &pExtent->Lists[i] );
                    }
                }

                //
                // and free
                //
                ExFreePoolWithTag( pExtent, AFS_EXTENT_TAG );
                AFSAllocationMemoryLevel -= sizeof( AFSExtent);

                InterlockedDecrement( &Fcb->Specific.File.ExtentCount);
            }
        }

try_exit:

        AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSReleaseSpecifiedExtents Completed for %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX\n", 
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      ntStatus);        

        if (locked) 
        {
            AFSReleaseResource( &Fcb->NPFcb->Specific.File.ExtentsResource );
        }
    }

    return ntStatus;
}

//
// Helper fuctions for Usermode initiation of release of extents
//
VOID
AFSReleaseFileExtents( IN  AFSFcb *Fcb,
                       OUT AFSFileExtentCB *FileExtents,
                       IN  ULONG BufferSize,
                       IN  ULONG AskedCount,
                       OUT ULONG *ExtentCount)
{

    AFSNonPagedFcb      *pNPFcb = Fcb->NPFcb;
    AFSExtent           *pExtent;
    LIST_ENTRY          *le;
    NTSTATUS             ntStatus;
    ULONG                sizeLeft = BufferSize;

    ASSERT( ExIsResourceAcquiredExclusiveLite( &Fcb->NPFcb->Specific.File.ExtentsResource ));

    *ExtentCount = 0;

    if (0 == Fcb->Specific.File.LastPurgePoint.QuadPart) 
    {
        //
        // This is the first time this file has been cleaned, or we
        // did a full clean last time.
        //
        le = Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST].Flink;
    } 
    else 
    {
        //
        // start where we left off
        //
        pExtent = AFSExtentForOffset( Fcb, &Fcb->Specific.File.LastPurgePoint, TRUE);

        if (NULL == pExtent) 
        {
            //
            // Its all moved
            //
            le = Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST].Flink;
        } 
        else 
        {
            le = &pExtent->Lists[AFS_EXTENTS_LIST];
        }
    }

    while (le != &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST] &&
           sizeLeft > sizeof(AFSFileExtentCB) &&
           *ExtentCount < AskedCount) 
    {

        pExtent = ExtentFor( le, AFS_EXTENTS_LIST);

        FileExtents[*ExtentCount].Flags = AFS_EXTENT_FLAG_RELEASE;

        if( BooleanFlagOn( pExtent->Flags, AFS_EXTENT_DIRTY))
        {

            AFSAcquireExcl( &pNPFcb->Specific.File.DirtyExtentsListLock, 
                            TRUE);

            if( BooleanFlagOn( pExtent->Flags, AFS_EXTENT_DIRTY))
            {
                LONG dirtyCount;

                RemoveEntryList( &pExtent->DirtyList);

                dirtyCount = InterlockedDecrement( &Fcb->Specific.File.ExtentsDirtyCount);

                ASSERT( dirtyCount >= 0);

                FileExtents[*ExtentCount].Flags |= AFS_EXTENT_FLAG_DIRTY;
            
            }

            AFSReleaseResource( &pNPFcb->Specific.File.DirtyExtentsListLock);

        }

        FileExtents[*ExtentCount].Length = pExtent->Size;
        FileExtents[*ExtentCount].CacheOffset = pExtent->CacheOffset;
        FileExtents[*ExtentCount].FileOffset = pExtent->FileOffset;

        AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSReleaseFileExtents Releasing extent on %wZ FID %08lX-%08lX-%08lX-%08lX Offset %I64X Len %08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      pExtent->FileOffset.QuadPart,
                      pExtent->Size);        

        le = le->Flink;
        *ExtentCount = (*ExtentCount) + 1;
        sizeLeft -= sizeof(AFSFileExtentCB);

        //
        // And unpick
        //
        for (ULONG i = 0; i < AFS_NUM_EXTENT_LISTS; i ++) 
        {
            if (NULL != pExtent->Lists[i].Flink && !IsListEmpty(&pExtent->Lists[i]))
            {
                RemoveEntryList( &pExtent->Lists[i] );
            }
        }
#if AFS_VALIDATE_EXTENTS
        VerifyExtentsLists(Fcb);
#endif

        //
        // Move forward last used cursor
        //
        Fcb->Specific.File.LastPurgePoint = pExtent->FileOffset;
        Fcb->Specific.File.LastPurgePoint.QuadPart += pExtent->Size;

        //
        // and free
        //
        ExFreePoolWithTag( pExtent, AFS_EXTENT_TAG );
        AFSAllocationMemoryLevel -= sizeof( AFSExtent);

        InterlockedDecrement( &Fcb->Specific.File.ExtentCount);
    }
    if (le == &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST]) 
    {
        //
        // We got to the end - reset the cursor
        //
        Fcb->Specific.File.LastPurgePoint.QuadPart = 0;
    }

    return;
}

AFSFcb* 
AFSFindFcbToClean(ULONG IgnoreTime, AFSFcb *LastFcb, BOOLEAN Block) 
{
    //
    // Iterate through the FCBs (starting at Last) until we find an
    // FCB which hasn't been touch recently (where IgnoreTime is the
    // number of time gaps we want to do)
    //
    AFSFcb *pFcb = NULL, *pVcb = NULL;
    AFSDeviceExt *pRDRDeviceExt = NULL;
    AFSDeviceExt *pControlDeviceExt = NULL;
    LARGE_INTEGER since;
    BOOLEAN bLocatedEntry = FALSE;

    pRDRDeviceExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;
    pControlDeviceExt = (AFSDeviceExt *)AFSDeviceObject->DeviceExtension;

    //
    // Set the time after which we have a candidate fcb
    // 
    
    KeQueryTickCount( &since );
    if (since.QuadPart > 
        (IgnoreTime * pControlDeviceExt->Specific.Control.FcbPurgeTimeCount.QuadPart)) {

        since.QuadPart -= IgnoreTime * pControlDeviceExt->Specific.Control.FcbPurgeTimeCount.QuadPart;
    } 
    else
    {
        //
        // That is to day only look at FCBs that haven't been touched since
        // before we booted.
        return NULL;
    }

    AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSFindFcbToClean Acquiring RDR VolumeListLock lock %08lX SHARED %08lX\n",
                  &pRDRDeviceExt->Specific.RDR.VolumeListLock,
                  PsGetCurrentThread());

    AFSAcquireShared( &pRDRDeviceExt->Specific.RDR.VolumeListLock,
                      TRUE);

    pVcb = pRDRDeviceExt->Specific.RDR.VolumeListHead;

    while( pVcb != NULL)
    {

        //
        // The Volume list may move under our feet.  Lock it.
        //

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSFindFcbToClean Acquiring VolumeRoot FcbListLock lock %08lX SHARED %08lX\n",
                      pVcb->Specific.VolumeRoot.FcbListLock,
                      PsGetCurrentThread());

        AFSAcquireShared( pVcb->Specific.VolumeRoot.FcbListLock,
                          TRUE);

        if (NULL == LastFcb) 
        {

            pFcb = pVcb->Specific.VolumeRoot.FcbListHead;
        } 
        else 
        {

            pFcb = (AFSFcb *)LastFcb->ListEntry.fLink;
        }

        while( pFcb != NULL)
        {
            //
            // If the FCB is a candidate we try to lock it (but without waiting - which
            // means we are deadlock free
            //

            if (pFcb->Header.NodeTypeCode == AFS_FILE_FCB &&
                pFcb->Specific.File.LastExtentAccess.QuadPart <= since.QuadPart)
            {
                
                if( Block)
                {
                    
                    AFSLockForExtentsTrim( pFcb);
                }
                else
                {
                
                    if( !AFSLockForExtentsTrimNoWait( pFcb))
                    {

                        pFcb = (AFSFcb *)pFcb->ListEntry.fLink;
                        
                        continue;
                    }
                }

                //
                // Need to be sure there are no current flushes in the queue
                //

                if( IsListEmpty( &pFcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST]))
                {

                    AFSReleaseResource(&pFcb->NPFcb->Specific.File.ExtentsResource);

                    pFcb = (AFSFcb *)pFcb->ListEntry.fLink;
                        
                    continue;
                }

                if( pFcb->Specific.File.QueuedFlushCount > 0)
                {

                    //DbgPrint("AFSFindFcbToClean Have queued flush count for %wZ %u.%u.%u.%u Count %d\n",
                    //          &pFcb->DirEntry->DirectoryEntry.FileName,
                    //          pFcb->DirEntry->DirectoryEntry.FileId.Cell,
                    //          pFcb->DirEntry->DirectoryEntry.FileId.Volume,
                    //          pFcb->DirEntry->DirectoryEntry.FileId.Vnode,
                    //          pFcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                    //          pFcb->Specific.File.QueuedFlushCount);

                    AFSReleaseResource(&pFcb->NPFcb->Specific.File.ExtentsResource);

                    if ( Block) 
                    {
                        AFSWaitOnQueuedFlushes( pFcb);

                    } else {

                        pFcb = (AFSFcb *)pFcb->ListEntry.fLink;

                    }

                    continue;
                }

                //DbgPrint("AFSFindFcbToClean Have Fcb %wZ %u.%u.%u.%u\n",
                //          &pFcb->DirEntry->DirectoryEntry.FileName,
                //          pFcb->DirEntry->DirectoryEntry.FileId.Cell,
                //          pFcb->DirEntry->DirectoryEntry.FileId.Volume,
                //          pFcb->DirEntry->DirectoryEntry.FileId.Vnode,
                //          pFcb->DirEntry->DirectoryEntry.FileId.Unique);
             
                //
                // A hit a very palpable hit.  Pin it
                //

                InterlockedIncrement( &pFcb->OpenReferenceCount);

                bLocatedEntry = TRUE;

                break;
            }

            pFcb = (AFSFcb *)pFcb->ListEntry.fLink;
        }

        AFSReleaseResource( pVcb->Specific.VolumeRoot.FcbListLock);
        
        if( bLocatedEntry)
        {            
            break;
        }

        pVcb = (AFSFcb *)pVcb->ListEntry.fLink;
    }

    AFSReleaseResource( &pRDRDeviceExt->Specific.RDR.VolumeListLock);

    return pFcb;
}

VOID
AFSCleanExtentsOnVolume(IN PVOID Buffer,
                        IN ULONG BufferSize,
                        IN ULONG AskedCount,
                        IN BOOLEAN Block,
                        OUT AFSFcb **Fcbs,
                        OUT ULONG *FileCount)
{
    AFSFcb                            *pFcb;
    AFSFcb                            *pLastFcb = NULL;
    LONG                               slLoopCount = AFS_SERVER_PURGE_SLEEP;
    ULONG                              ulBufferLeft = BufferSize;
    CHAR                              *pcBuffer = (CHAR*) Buffer;
    AFSReleaseFileExtentsResultFileCB *pFile = NULL;
    ULONG                              ulExtentsProcessed = 0;
    ULONG                              sz;

    *FileCount = 0;

    //
    // We loop multiple times, looking for older FCBs each time
    //

    while (slLoopCount >= 0 &&
           *FileCount < AFS_MAX_FCBS_TO_DROP &&
           ulBufferLeft >= ( sizeof(AFSReleaseFileExtentsResultFileCB))) 
    {
        pFile = (AFSReleaseFileExtentsResultFileCB*) pcBuffer;

        pFcb = AFSFindFcbToClean( slLoopCount, pLastFcb, Block);
            
        //
        // Now dereference the last FCB
        //
        if (NULL != pLastFcb) 
        {

            ASSERT( pLastFcb->OpenReferenceCount != 0);

            InterlockedDecrement( &pLastFcb->OpenReferenceCount);

            pLastFcb = NULL;
        }

        //
        // Did we find an FCB?
        //
        if (NULL == pFcb) {
            //
            // Nope, increment loopCount and continue around the outer loop
            //
            slLoopCount --;
            continue;
        }

        //
        // Otherwise we did.  Lets try to populate
        //

        AFSReleaseFileExtents( pFcb, 
                               pFile->FileExtents, 
                               ulBufferLeft - FIELD_OFFSET(AFSReleaseFileExtentsResultFileCB, FileExtents),
                               AskedCount - ulExtentsProcessed,
                               &pFile->ExtentCount);

        //
        // Fcb it is referenced, pass that on to the next one
        //
        pLastFcb = pFcb;

        if (0 == pFile->ExtentCount) 
        {
            //
            // Nothing filled in, so loop - dropping this FCB lock..
            //
            AFSReleaseResource(&pFcb->NPFcb->Specific.File.ExtentsResource);
            continue;
        }

        ulExtentsProcessed += pFile->ExtentCount;

        //
        // Pass control (lock and reference) of the FCB to the array
        //
        Fcbs[(*FileCount)] = pFcb;
        InterlockedIncrement( &pFcb->OpenReferenceCount);

        AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSCleanExtentsOnVolume Cleaning file %wZ FID %08lX:%08lX:%08lX:%08lX ExtentCount %lX\n",
                      &pFcb->DirEntry->DirectoryEntry.FileName,
                      pFcb->DirEntry->DirectoryEntry.FileId.Cell,
                      pFcb->DirEntry->DirectoryEntry.FileId.Volume,
                      pFcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      pFcb->DirEntry->DirectoryEntry.FileId.Unique,
                      pFile->ExtentCount
                      );

        //
        // Populate the rest of the field
        //
        pFile->FileId = pFcb->DirEntry->DirectoryEntry.FileId;
        pFile->Flags = AFS_EXTENT_FLAG_RELEASE;
        pFile->ProcessId.QuadPart = pFcb->Specific.File.ExtentProcessId;

        sz = FIELD_OFFSET(AFSReleaseFileExtentsResultFileCB, FileExtents) + 
            (pFile->ExtentCount * sizeof(AFSFileExtentCB));
        
        //
        // Move cursors forwards/backwards as required
        //

        (*FileCount) ++;
        pcBuffer += sz;
        ASSERT(((PVOID)pcBuffer) == ((PVOID)&pFile->FileExtents[pFile->ExtentCount]));
        ASSERT(ulBufferLeft >= sz);
        ulBufferLeft = ulBufferLeft - sz;
    }

    if (pLastFcb) 
    {

        ASSERT( pLastFcb->OpenReferenceCount != 0);

        InterlockedDecrement( &pLastFcb->OpenReferenceCount);
        
        pLastFcb = NULL;
    }

    //
    // All done
    //
    return;
}

NTSTATUS
AFSProcessReleaseFileExtentsDone( PIRP Irp) 
{
    AFSReleaseFileExtentsResultDoneCB *pResult;
    NTSTATUS                           ntStatus = STATUS_SUCCESS;
    AFSDeviceExt                      *pDeviceExt = (AFSDeviceExt *) AFSDeviceObject->DeviceExtension;
    PIO_STACK_LOCATION                 pIrpSp = IoGetCurrentIrpStackLocation( Irp);


    __Enter
    {
        if( pIrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof( AFSReleaseFileExtentsResultDoneCB))
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessReleaseFileExtentsDone Input buffer too small\n");        

            try_return( ntStatus = STATUS_INVALID_PARAMETER);
        }

        pResult = (AFSReleaseFileExtentsResultDoneCB *)  Irp->AssociatedIrp.SystemBuffer;

        AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSProcessReleaseFileExtentsDone For serial number %08lX Expected %08lX\n",
                      pResult->SerialNumber,
                      pDeviceExt->Specific.Control.ExtentReleaseSequence);        

        if ( pResult->SerialNumber == 
             pDeviceExt->Specific.Control.ExtentReleaseSequence)
        {
            //
            // Usual case - they match
            //
            ntStatus = STATUS_SUCCESS;
            KeSetEvent( &pDeviceExt->Specific.Control.ExtentReleaseEvent,
                        0,
                        FALSE );
        } 
        else
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessReleaseFileExtentsDone INCORRECT serial number %08lX Expected %08lX\n",
                          pResult->SerialNumber,
                          pDeviceExt->Specific.Control.ExtentReleaseSequence);        

            //
            // Logic bug, so complain
            //
            ASSERT( pResult->SerialNumber == 
                    pDeviceExt->Specific.Control.ExtentReleaseSequence);

            try_return( ntStatus = STATUS_INVALID_PARAMETER);
        }

try_exit:
        
        NOTHING;
    }

    return ntStatus;
}

NTSTATUS
AFSProcessReleaseFileExtents( IN PIRP Irp, 
                              IN BOOLEAN CallBack, 
                              IN BOOLEAN *Complete)
{
    NTSTATUS                           ntStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION                 pIrpSp = IoGetCurrentIrpStackLocation( Irp);
    PFILE_OBJECT                       pFileObject = pIrpSp->FileObject;
    AFSFcb                            *pFcb = NULL, *pVcb = NULL;
    AFSDeviceExt                      *pDevExt;
    AFSReleaseFileExtentsCB           *pExtents;
    AFSReleaseFileExtentsResultCB     *pResult = NULL;
    AFSReleaseFileExtentsResultFileCB *pFile = NULL;
    ULONG                              ulSz = 0;
    ULONGLONG                          ullIndex = 0;

    *Complete = TRUE;
    pDevExt = (AFSDeviceExt *) AFSRDRDeviceObject->DeviceExtension;
    __Enter 
    {
        pExtents = (AFSReleaseFileExtentsCB*) Irp->AssociatedIrp.SystemBuffer;

        if( pIrpSp->Parameters.DeviceIoControl.InputBufferLength < 
                                            sizeof( AFSReleaseFileExtentsCB))
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessReleaseFileExtents INPUT Buffer too small\n");        

            try_return( ntStatus = STATUS_INVALID_PARAMETER );
        }

        if ( pIrpSp->Parameters.DeviceIoControl.OutputBufferLength <
                                        sizeof(AFSReleaseFileExtentsResultCB))
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessReleaseFileExtents OUTPUT Buffer too small\n");        

            //
            // Must have space for one extent in one file
            //
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (pExtents->ExtentCount == 0)
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_ERROR,
                          "AFSProcessReleaseFileExtents Extent count zero\n");        

            try_return( ntStatus = STATUS_INVALID_PARAMETER);
        }

        if (pExtents->FileId.Cell   != 0 ||
            pExtents->FileId.Volume != 0 ||
            pExtents->FileId.Vnode  != 0 ||
            pExtents->FileId.Unique != 0)
        {

            AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSProcessReleaseFileExtents Processing FID %08lX:%08lX:%08lX:%08lX\n",
                                      pExtents->FileId.Cell,
                                      pExtents->FileId.Volume,
                                      pExtents->FileId.Vnode,
                                      pExtents->FileId.Unique);        

            if( pIrpSp->Parameters.DeviceIoControl.InputBufferLength < 
                            ( FIELD_OFFSET( AFSReleaseFileExtentsCB, ExtentCount) + sizeof(ULONG)) ||
                pIrpSp->Parameters.DeviceIoControl.InputBufferLength <
                            ( FIELD_OFFSET( AFSReleaseFileExtentsCB, ExtentCount) + sizeof(ULONG) +
                                                            sizeof (AFSFileExtentCB) * pExtents->ExtentCount))
            {

                AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSProcessReleaseFileExtents Buffer too small for FID %08lX:%08lx:%08lX:%08lX\n",
                              pExtents->FileId.Cell,
                              pExtents->FileId.Volume,
                              pExtents->FileId.Vnode,
                              pExtents->FileId.Unique);        

                try_return( ntStatus = STATUS_INVALID_PARAMETER );
            }

            //
            //If this was from the control then look
            // for the FCB, otherwise collect it fromn the FCB
            //
            if (!CallBack)
            {

                AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSProcessReleaseFileExtents Acquiring RDR VolumeTreeLock lock %08lX SHARED %08lX\n",
                              &pDevExt->Specific.RDR.VolumeTreeLock,
                              PsGetCurrentThread());

                AFSAcquireShared( &pDevExt->Specific.RDR.VolumeTreeLock, TRUE);

                //
                // Locate the volume node
                //

                ullIndex = AFSCreateHighIndex( &pExtents->FileId);

                ntStatus = AFSLocateHashEntry( pDevExt->Specific.RDR.VolumeTree.TreeHead,
                                               ullIndex,
                                               &pVcb);

                if( pVcb != NULL)
                {

                    AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSProcessReleaseFileExtents Acquiring VolumeRoot FileIDTree.TreeLock lock %08lX SHARED %08lX\n",
                                  pVcb->Specific.VolumeRoot.FileIDTree.TreeLock,
                                  PsGetCurrentThread());

                    AFSAcquireShared( pVcb->Specific.VolumeRoot.FileIDTree.TreeLock,
                                      TRUE);
                }

                AFSReleaseResource( &pDevExt->Specific.RDR.VolumeTreeLock);

                if( !NT_SUCCESS( ntStatus) ||
                    pVcb == NULL) 
                {

                    AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                                  AFS_TRACE_LEVEL_ERROR,
                                  "AFSProcessReleaseFileExtents Invalid volume index %I64X\n",
                                  ullIndex);        

                    try_return( ntStatus = STATUS_UNSUCCESSFUL);
                }

                //
                // Now locate the Fcb in this volume
                //

                ullIndex = AFSCreateLowIndex( &pExtents->FileId);

                ntStatus = AFSLocateHashEntry( pVcb->Specific.VolumeRoot.FileIDTree.TreeHead,
                                               ullIndex,
                                               &pFcb);

                AFSReleaseResource( pVcb->Specific.VolumeRoot.FileIDTree.TreeLock);

                if( !NT_SUCCESS( ntStatus) ||
                    pFcb == NULL) 
                {

                    AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                                  AFS_TRACE_LEVEL_ERROR,
                                  "AFSProcessReleaseFileExtents Invalid file index %I64X\n",
                                  ullIndex);        

                    try_return( ntStatus = STATUS_UNSUCCESSFUL);
                }
            }
            else
            {
                pFcb = (AFSFcb*) pFileObject->FsContext;
            }

            //
            // The input buffer == the output buffer, so we will grab
            // some working space 1 header, 1 file, a bunch of extents
            // (note that the a result has 1 file in it and file as 1
            // extent in it
            //
            ulSz = (pExtents->ExtentCount-1) * sizeof(AFSFileExtentCB);
            ulSz += sizeof(AFSReleaseFileExtentsResultCB);

            if (ulSz > pIrpSp->Parameters.DeviceIoControl.OutputBufferLength)
            {
                try_return( ntStatus = STATUS_BUFFER_TOO_SMALL );
            }
            
            pResult = (AFSReleaseFileExtentsResultCB*) ExAllocatePoolWithTag(PagedPool,
                                                                             ulSz,
                                                                             AFS_EXTENTS_RESULT_TAG);
            if (NULL == pResult)
            {
                
                AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSProcessReleaseFileExtents Failed to allocate result block\n");        

                try_return( ntStatus = STATUS_INSUFFICIENT_RESOURCES );
            }

            //
            // Set up the header (for an array of one)
            //
            pResult->FileCount = 1;
            pResult->Flags = AFS_EXTENT_FLAG_RELEASE;;
            ulSz -= FIELD_OFFSET(AFSReleaseFileExtentsResultCB, Files);

            //
            // Setup the first (and only) file
            //
            pFile = pResult->Files;
            pFile->FileId = pExtents->FileId;
            pFile->Flags = AFS_EXTENT_FLAG_RELEASE;
            pFile->ProcessId.QuadPart = pFcb->Specific.File.ExtentProcessId;
            ulSz -= FIELD_OFFSET(AFSReleaseFileExtentsResultFileCB, FileExtents);
   
            ntStatus = AFSReleaseSpecifiedExtents( pExtents,
                                                   pFcb,
                                                   pFile->FileExtents,
                                                   ulSz,
                                                   &pFile->ExtentCount );

            if (!NT_SUCCESS(ntStatus)) 
            {

                AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSProcessReleaseFileExtents Failed to release extents for %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX\n",
                              &pFcb->DirEntry->DirectoryEntry.FileName,
                              pFcb->DirEntry->DirectoryEntry.FileId.Cell,
                              pFcb->DirEntry->DirectoryEntry.FileId.Volume,
                              pFcb->DirEntry->DirectoryEntry.FileId.Vnode,
                              pFcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                              ntStatus);        

                try_return( ntStatus );
            }
            
            ulSz = (pExtents->ExtentCount-1) * sizeof(AFSFileExtentCB);
            ulSz += sizeof(AFSReleaseFileExtentsResultCB);

            //
            //

            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, pResult, ulSz);

            //
            // And fall into common path
            //
            //
            // Now hand back if we were told to - NOTE that this is unsafe
            // - we should give the extents back while the lock is held.
            // However this code path is only used in debug mode (when
            // prodding the redirector from outside the service).
            //
            if (CallBack ) {
                
                PCHAR ptr;
                AFSReleaseExtentsCB *pRelease = NULL;
                
                pFile = pResult->Files;
            
                for (ULONG i = 0; i < pResult->FileCount; i++) {
                
                    ULONG ulMySz;
                    ulMySz = sizeof( AFSReleaseExtentsCB ) + (pFile->ExtentCount * sizeof ( AFSFileExtentCB ));
                    
                    pRelease = (AFSReleaseExtentsCB*) ExAllocatePoolWithTag( NonPagedPool,
                                                                             ulMySz,
                                                                             AFS_EXTENT_RELEASE_TAG);
                    if (NULL == pRelease) 
                    {

                        AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                                      AFS_TRACE_LEVEL_ERROR,
                                      "AFSProcessReleaseFileExtents Failed to allocate result block\n");        

                        try_return ( ntStatus = STATUS_INSUFFICIENT_RESOURCES );
                    }

                    pRelease->Flags = AFS_EXTENT_FLAG_RELEASE;
                    pRelease->ExtentCount = pFile->ExtentCount;
                    RtlCopyMemory( pRelease->FileExtents, pFile->FileExtents, pFile->ExtentCount * sizeof ( AFSFileExtentCB ));

                    AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSProcessReleaseFileExtents Calling AFS_REQUEST_TYPE_RELEASE_FILE_EXTENTS for %wZ FID %08lX-%08lX-%08lX-%08lX PID %I64X\n",
                                  &pFcb->DirEntry->DirectoryEntry.FileName,
                                  pFcb->DirEntry->DirectoryEntry.FileId.Cell,
                                  pFcb->DirEntry->DirectoryEntry.FileId.Volume,
                                  pFcb->DirEntry->DirectoryEntry.FileId.Vnode,
                                  pFcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                                  pFile->ProcessId.QuadPart);

                    ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_RELEASE_FILE_EXTENTS,
                                              AFS_REQUEST_FLAG_SYNCHRONOUS,
                                              pFile->ProcessId.QuadPart,
                                              NULL,
                                              &pFile->FileId,
                                              pRelease,
                                              ulMySz,
                                              NULL,
                                              NULL);

                    ASSERT( ntStatus == STATUS_SUCCESS);

                    ExFreePoolWithTag(pRelease, AFS_EXTENT_RELEASE_TAG);

                    ptr = (PCHAR) pFile->FileExtents;
                    ptr += pFile->ExtentCount * sizeof ( AFSFileExtentCB );
                    ASSERT(((PVOID)ptr) == ((PVOID)&pFile->FileExtents[pFile->ExtentCount]));
                    pFile = (AFSReleaseFileExtentsResultFileCB*) ptr;                
                }
            }
        } 
        else
        {

            IoMarkIrpPending(Irp);

            *Complete = FALSE;

            ntStatus = AFSQueueExtentRelease( Irp);

            if (!NT_SUCCESS(ntStatus)) 
            { 
                
                //
                // That failed, but we have marked the Irp pending so
                // we gotta return pending.  Complete now
                //

                Irp->IoStatus.Status = ntStatus;
                Irp->IoStatus.Information = 0;

                AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                              AFS_TRACE_LEVEL_ERROR,
                              "AFSProcessReleaseFileExtents Failed to queue work item Status %08lX\n",
                              ntStatus);        

                AFSCompleteRequest( Irp,
                                    ntStatus);
            } 

            ntStatus = STATUS_PENDING;
        }

try_exit:

        //
        // Note for the below - if we have complete the irp we didn't allocate a buffer
        //
        if (NULL != pResult &&
            Irp->AssociatedIrp.SystemBuffer != pResult) 
        {
            //
            // We allocated space - give it back
            //
            ExFreePoolWithTag(pResult, AFS_EXTENTS_RESULT_TAG);
        }

        if (*Complete) 
        {

            if (NT_SUCCESS(ntStatus)) 
            {
                Irp->IoStatus.Information = ulSz;
            }
            else
            {
                Irp->IoStatus.Information = 0;
            }

            if (!CallBack)
            {
                Irp->IoStatus.Information = 0;
            }

            Irp->IoStatus.Status = ntStatus;
        }
    }

    return ntStatus;
}

VOID AFSReleaseExtentsWork(AFSWorkItem *WorkItem)
{
    NTSTATUS                       ntStatus = STATUS_SUCCESS;
    PIRP                           pIrp = WorkItem->Specific.ReleaseExtents.Irp;
    PIO_STACK_LOCATION             pIrpSp = IoGetCurrentIrpStackLocation( pIrp);
    AFSReleaseFileExtentsCB       *pExtents;
    PFILE_OBJECT                   pFileObject = pIrpSp->FileObject;
    ULONG                          ulSz;
    ULONG                          ulFileCount;
    PAFSFcb                        Fcbs[AFS_MAX_FCBS_TO_DROP] = {0};
    AFSReleaseFileExtentsResultCB *pResult = NULL;
    AFSDeviceExt                  *pDeviceExt = (AFSDeviceExt *) AFSDeviceObject->DeviceExtension;
    BOOLEAN                        bBlockRequest = FALSE;
    AFSDeviceExt                  *pRDRDevExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;

    __Enter
    {

        pDeviceExt = (AFSDeviceExt *)AFSDeviceObject->DeviceExtension;
    
        //
        // We only allow one of these at one time.  This makes the
        // acknowledge easier to detect.  This is purely a coding nicety.
        // We can support multiple ones but then we need rarely exercised
        // code to go from serial number to event.
        //

        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSReleaseExtentsWork Acquiring Control ExtentReleaseResource lock %08lX EXCL %08lX\n",
                      &pDeviceExt->Specific.Control.ExtentReleaseResource,
                      PsGetCurrentThread());

        AFSAcquireExcl( &pDeviceExt->Specific.Control.ExtentReleaseResource, TRUE);

        //
        // Set up Input and Output
        //

        pExtents = (AFSReleaseFileExtentsCB*) pIrp->AssociatedIrp.SystemBuffer;

        ASSERT(pExtents->FileId.Cell   == 0 &&
               pExtents->FileId.Volume == 0 &&
               pExtents->FileId.Vnode  == 0 &&
               pExtents->FileId.Unique == 0);

        //
        // Setup the result buffer
        //

        pResult = (AFSReleaseFileExtentsResultCB*) pIrp->AssociatedIrp.SystemBuffer;
        ulSz = pIrpSp->Parameters.DeviceIoControl.OutputBufferLength;
        
        pResult->Flags = AFS_EXTENT_FLAG_RELEASE;
        ulSz -= FIELD_OFFSET( AFSReleaseFileExtentsResultCB, Files);

        bBlockRequest = FALSE;

        ulFileCount = 0;

        while( ulFileCount == 0)
        {

            ntStatus = STATUS_SUCCESS;

            AFSCleanExtentsOnVolume( pResult->Files, 
                                     ulSz, 
                                     pExtents->ExtentCount, 
                                     bBlockRequest,
                                     Fcbs,
                                     &ulFileCount);

            if( ulFileCount == 0)
            {

                if( bBlockRequest)
                {

                    //DbgPrint("AFSReleaseExtentsWork Blocked on all files and REALLY don't have anything to give up ...\n");

                    ntStatus = STATUS_DEVICE_NOT_READY;

                    break;
                }

                bBlockRequest = TRUE;
            }
        }

        pResult->FileCount = ulFileCount;

        //
        // Get ready to complete the Irp
        //

        pIrp->IoStatus.Status = ntStatus;

        pIrp->IoStatus.Information = 0;

        if( NT_SUCCESS( ntStatus))
        {

            pIrp->IoStatus.Information = pIrpSp->Parameters.DeviceIoControl.OutputBufferLength;

            pResult->SerialNumber = ++(pDeviceExt->Specific.Control.ExtentReleaseSequence);

            //
            // Clear the event.  When the response comes back it will be set
            //

            KeClearEvent( &pDeviceExt->Specific.Control.ExtentReleaseEvent);
        }

        AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSReleaseExtentsWork Sending extents File Count %d SN %08lX Waiting ... Status %08lX\n",
                      ulFileCount,
                      pResult->SerialNumber,
                      ntStatus);

        //
        // We are all done.  Send back the Irp
        //

        AFSCompleteRequest( pIrp, ntStatus);

        if( NT_SUCCESS( ntStatus))
        {

            //
            // Wait for the response
            //

            ntStatus = KeWaitForSingleObject( &pDeviceExt->Specific.Control.ExtentReleaseEvent,
                                              Executive,
                                              KernelMode,
                                              FALSE,
                                              NULL);

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSReleaseExtentsWork Sent extents File Count %d Wait completed\n",
                          ulFileCount);

            for (ULONG i = 0; i < ulFileCount; i ++) 
            {

                //
                // Release the extent locks
                //
                AFSReleaseResource( &Fcbs[i]->NPFcb->Specific.File.ExtentsResource);
                //
                // Give back reference
                //

                ASSERT( Fcbs[i]->OpenReferenceCount != 0);

                InterlockedDecrement( &Fcbs[i]->OpenReferenceCount);
            }
        }

        AFSReleaseResource( &pDeviceExt->Specific.Control.ExtentReleaseResource);   

        //
        // We're done so decrement our count and set the event
        //

        if( InterlockedDecrement( &pRDRDevExt->Specific.RDR.QueuedReleaseExtentCount) == 0)
        {

            KeSetEvent( &pRDRDevExt->Specific.RDR.QueuedReleaseExtentEvent,
                        0,
                        FALSE);
        }
    }

    return;
}

NTSTATUS
AFSWaitForExtentMapping( AFSFcb *Fcb )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    LARGE_INTEGER liTimeOut;

    __Enter
    {

        if (!NT_SUCCESS( Fcb->NPFcb->Specific.File.ExtentsRequestStatus)) 
        {

            try_return( ntStatus = Fcb->NPFcb->Specific.File.ExtentsRequestStatus);
        }

        liTimeOut.QuadPart = -(50000000);

        ntStatus = KeWaitForSingleObject( &Fcb->NPFcb->Specific.File.ExtentsRequestComplete,
                                          Executive,
                                          KernelMode, 
                                          FALSE,
                                          &liTimeOut);

        if (!NT_SUCCESS( Fcb->NPFcb->Specific.File.ExtentsRequestStatus)) 
        {

            try_return( ntStatus = Fcb->NPFcb->Specific.File.ExtentsRequestStatus);
        }

        if( ntStatus == STATUS_TIMEOUT)
        {

            ntStatus = STATUS_SUCCESS;
        }

try_exit:

        NOTHING;
    }

    return ntStatus;
}

NTSTATUS
AFSFlushExtents( IN AFSFcb *Fcb)
{
    AFSNonPagedFcb      *pNPFcb = Fcb->NPFcb;
    AFSExtent           *pExtent;
    LIST_ENTRY          *le;
    AFSReleaseExtentsCB *pRelease = NULL;
    ULONG                count = 0;
    ULONG                initialDirtyCount = 0;
    BOOLEAN              bExtentsLocked = FALSE;
    ULONG                total = 0;
    ULONG                sz = 0;
    NTSTATUS             ntStatus = STATUS_SUCCESS;
    ULONGLONG            hExtentProcessId = 0;
    LARGE_INTEGER        liLastFlush;
    LIST_ENTRY           dirtyList;

    ASSERT( Fcb->Header.NodeTypeCode == AFS_FILE_FCB);

    //
    // Grab a process context if we don't have one
    //

    if( Fcb->Specific.File.ExtentProcessId != 0)
    {

        hExtentProcessId = Fcb->Specific.File.ExtentProcessId;
    }
    else
    {

        hExtentProcessId = (ULONGLONG)PsGetCurrentProcessId();
    }
   
    //
    // Save, then reset the flush time
    //

    liLastFlush = Fcb->Specific.File.LastServerFlush; 
    
    KeQueryTickCount( &Fcb->Specific.File.LastServerFlush);

    __Enter
    {

        //
        // Lock extents while we count and set up the array to send to
        // the service
        //
        
        AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSFlushExtents Acquiring(1) Fcb extents lock %08lX SHARED %08lX\n",
                      &pNPFcb->Specific.File.ExtentsResource,
                      PsGetCurrentThread());

        AFSAcquireShared( &pNPFcb->Specific.File.ExtentsResource, TRUE);
        bExtentsLocked = TRUE;

        InterlockedIncrement( &Fcb->Specific.File.QueuedFlushCount);

        //
        // Clear our queued flush event
        //

        KeClearEvent( &Fcb->NPFcb->Specific.File.QueuedFlushEvent);

        //
        // Initialize our local dirty list
        //

        InitializeListHead( &dirtyList);

        //
        // Look for a start in the list to flush entries
        //

        total = count;
            
        sz = sizeof( AFSReleaseExtentsCB ) + (AFS_MAXIMUM_EXTENT_RELEASE_COUNT * sizeof ( AFSFileExtentCB ));

        pRelease = (AFSReleaseExtentsCB*) ExAllocatePoolWithTag( NonPagedPool,
                                                                 sz,
                                                                 AFS_EXTENT_RELEASE_TAG);
        if( NULL == pRelease) 
        {

            try_return ( ntStatus = STATUS_INSUFFICIENT_RESOURCES );
        }

        //
        // Be sure we wait on any in progress flushes
        //

        ntStatus = KeWaitForSingleObject( &pNPFcb->Specific.File.FlushEvent,
                                          Executive,
                                          KernelMode,
                                          FALSE,
                                          NULL);

        if( !NT_SUCCESS( ntStatus))
        {

            try_return( ntStatus);
        }

        initialDirtyCount = Fcb->Specific.File.ExtentsDirtyCount;

        while( Fcb->Specific.File.ExtentsDirtyCount > 0)
        {

            pRelease->Flags = AFS_EXTENT_FLAG_DIRTY;            
            
            count = 0;

            InitializeListHead( &dirtyList);

            while( count < AFS_MAXIMUM_EXTENT_RELEASE_COUNT)
            {
                LONG dirtyCount;

                AFSAcquireExcl( &pNPFcb->Specific.File.DirtyExtentsListLock, 
                                TRUE);

                if ( IsListEmpty( &pNPFcb->Specific.File.DirtyExtentsList))
                {

                    AFSReleaseResource( &pNPFcb->Specific.File.DirtyExtentsListLock);

                    break;
                }
                
                le = RemoveHeadList( &pNPFcb->Specific.File.DirtyExtentsList);

                pExtent = DirtyExtentFor( le);

                dirtyCount = InterlockedDecrement( &Fcb->Specific.File.ExtentsDirtyCount);

                ASSERT(dirtyCount >= 0);

                ASSERT( pExtent->Flags & AFS_EXTENT_DIRTY);

                //
                // Clear the flag in advance of the write - we'll put
                // it back if it failed.  If we do things this was we
                // know that the clear is pessimistic (any write which
                // happens from now on will set the flag dirty again).
                //

                pExtent->Flags &= ~AFS_EXTENT_DIRTY;

                AFSReleaseResource( &pNPFcb->Specific.File.DirtyExtentsListLock);

                InsertTailList( &dirtyList,
                                &pExtent->DirtyList);

                AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSFlushExtents Flushing DIRTY extent offset %I64X Length %08lX TID %08lX\n",
                              pExtent->FileOffset.QuadPart,
                              pExtent->Size,
                              PsGetCurrentThreadId());        

                pRelease->FileExtents[count].Flags = AFS_EXTENT_FLAG_DIRTY;
                pRelease->FileExtents[count].Length = pExtent->Size;
                pRelease->FileExtents[count].CacheOffset = pExtent->CacheOffset;
                pRelease->FileExtents[count].FileOffset = pExtent->FileOffset;

                count ++;

            }

            //
            // If we are done then get out
            //

            if( count == 0)
            {

                AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSFlushExtents No more dirty extents found\n");        

                break;
            }

            //
            // Fire off the request synchronously
            //

            sz = sizeof( AFSReleaseExtentsCB ) + (count * sizeof ( AFSFileExtentCB ));
            
            pRelease->ExtentCount = count;

            //
            // Drop the extents lock for the duration of the call to
            // the network.  We have pinned the extents so, even
            // though we might get extents added during this period,
            // but none will be removed.  Hence we can carry on from
            // le.
            //

            AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );
            bExtentsLocked = FALSE;

            KeSetEvent( &pNPFcb->Specific.File.FlushEvent,
                        0,
                        FALSE);

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSFlushExtents Calling AFS_REQUEST_TYPE_RELEASE_FILE_EXTENTS for %wZ FID %08lX-%08lX-%08lX-%08lX count %d\n",
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          count);        

            ntStatus = AFSProcessRequest( AFS_REQUEST_TYPE_RELEASE_FILE_EXTENTS,
                                          AFS_REQUEST_FLAG_SYNCHRONOUS,
                                          (ULONGLONG)hExtentProcessId,
                                          NULL,
                                          &Fcb->DirEntry->DirectoryEntry.FileId,
                                          pRelease,
                                          sz,
                                          NULL,
                                          NULL);

            ASSERT( ntStatus == STATUS_SUCCESS);

            AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSFlushExtents Call AFS_REQUEST_TYPE_RELEASE_FILE_EXTENTS for %wZ FID %08lX-%08lX-%08lX-%08lX COMPLETE Status %08lX\n",
                          &Fcb->DirEntry->DirectoryEntry.FileName,
                          Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                          Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                          Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                          Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                          ntStatus);        

            AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                          AFS_TRACE_LEVEL_VERBOSE,
                          "AFSFlushExtents Acquiring(2) Fcb extents lock %08lX SHARED %08lX\n",
                          &pNPFcb->Specific.File.ExtentsResource,
                          PsGetCurrentThread());

            AFSAcquireShared( &pNPFcb->Specific.File.ExtentsResource, TRUE);
            bExtentsLocked = TRUE;

            if( !NT_SUCCESS(ntStatus)) 
            {
                //
                // that failed, so undo all we did.
                //

                Fcb->Specific.File.LastServerFlush = liLastFlush;

                //
                // Go back and set the extents dirty again
                //

                count = 0;

                while (!IsListEmpty( &dirtyList)) 
                {

                    le = RemoveHeadList( &dirtyList);

                    pExtent = DirtyExtentFor( le);

                    AFSAcquireExcl( &pNPFcb->Specific.File.DirtyExtentsListLock, 
                                    TRUE);

                    InsertTailList( &pNPFcb->Specific.File.DirtyExtentsList,
                                    &pExtent->DirtyList);

                    AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                                  AFS_TRACE_LEVEL_VERBOSE,
                                  "AFSFlushExtents Marking extent offset %I64X Length %08lX DIRTY due to flush failure\n",
                                  pExtent->FileOffset.QuadPart,
                                  pExtent->Size);        

                    pExtent->Flags |= AFS_EXTENT_DIRTY;

                    InterlockedIncrement( &Fcb->Specific.File.ExtentsDirtyCount);

                    AFSReleaseResource( &pNPFcb->Specific.File.DirtyExtentsListLock);

                }

                break;
            }

            //
            // Wait for anyone gathering dirty extents
            //

            ntStatus = KeWaitForSingleObject( &pNPFcb->Specific.File.FlushEvent,
                                              Executive,
                                              KernelMode,
                                              FALSE,
                                              NULL);

            if( !NT_SUCCESS( ntStatus))
            {

                try_return( ntStatus);
            }
        }

try_exit:
                               
        if( InterlockedDecrement( &Fcb->Specific.File.QueuedFlushCount) == 0)
        {

            KeSetEvent( &pNPFcb->Specific.File.QueuedFlushEvent,
                        0,
                        FALSE);
        }

        KeSetEvent( &pNPFcb->Specific.File.FlushEvent,
                    0,
                    FALSE);

        if (bExtentsLocked) 
        {
            AFSReleaseResource( &pNPFcb->Specific.File.ExtentsResource );
        }

        if (pRelease) 
        {
            ExFreePoolWithTag( pRelease, AFS_EXTENT_RELEASE_TAG );
        }
    }

    return ntStatus;
}

VOID
AFSMarkDirty( IN AFSFcb *Fcb,
              IN PLARGE_INTEGER Offset,
              IN ULONG   Count)
{
    LARGE_INTEGER  liEnd, liOffset = *Offset;
    AFSExtent     *pExtent, *pDirtyHint;
    LIST_ENTRY    *le;
    AFSDeviceExt  *pRDRDeviceExt = NULL;
    AFSWorkItem   *pWorkItem = NULL;
    AFSNonPagedFcb *pNPFcb = Fcb->NPFcb;

    pRDRDeviceExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;

    liEnd.QuadPart = liOffset.QuadPart + Count;

    AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSMarkDirty Marking offset %I64X count %08lX DIRTY for %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                  liOffset.QuadPart,
                  Count,
                  &Fcb->DirEntry->DirectoryEntry.FileName,
                  Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                  Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                  Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                  Fcb->DirEntry->DirectoryEntry.FileId.Unique);

    AFSDbgLogMsg( AFS_SUBSYSTEM_LOCK_PROCESSING,
                  AFS_TRACE_LEVEL_VERBOSE,
                  "AFSMarkDirty Acquiring Fcb extents lock %08lX SHARED %08lX\n",
                  &Fcb->NPFcb->Specific.File.ExtentsResource,
                  PsGetCurrentThread());

    AFSAcquireShared( &Fcb->NPFcb->Specific.File.ExtentsResource, TRUE);

    pExtent = AFSExtentForOffset( Fcb, &liOffset, TRUE);

    if (NULL == pExtent)
    {
        le = Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST].Flink;
    }
    else 
    {
        le = &pExtent->Lists[AFS_EXTENTS_LIST];
    }

    while( liOffset.QuadPart < liEnd.QuadPart &&
           le != &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST])
    {
        pExtent = ExtentFor( le, AFS_EXTENTS_LIST);

        ASSERT( AFSExtentContains( pExtent, &liOffset));

        if ( liOffset.QuadPart < (pExtent->FileOffset.QuadPart + pExtent->Size) &&
             !BooleanFlagOn( pExtent->Flags, AFS_EXTENT_DIRTY))
        {

            ASSERT( liOffset.QuadPart >= pExtent->FileOffset.QuadPart);

            AFSAcquireExcl( &pNPFcb->Specific.File.DirtyExtentsListLock, 
                            TRUE);

            if ( !BooleanFlagOn( pExtent->Flags, AFS_EXTENT_DIRTY)) {

                AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSMarkDirty Marking extent offset %I64X Length %08lX DIRTY\n",
                              pExtent->FileOffset.QuadPart,
                              pExtent->Size);        

                InsertTailList( &pNPFcb->Specific.File.DirtyExtentsList,
                                &pExtent->DirtyList);

                pExtent->Flags |= AFS_EXTENT_DIRTY;

                //
                // Up the dirty count
                //

                InterlockedIncrement( &Fcb->Specific.File.ExtentsDirtyCount);

            }
            
            AFSReleaseResource( &pNPFcb->Specific.File.DirtyExtentsListLock);

         }

        le = le->Flink;
    
        liOffset.QuadPart = pExtent->FileOffset.QuadPart + pExtent->Size;

    }

    if ((Fcb->Specific.File.ExtentsDirtyCount * pRDRDeviceExt->Specific.RDR.CacheBlockSize) >
        (ULONGLONG) pRDRDeviceExt->Specific.RDR.MaxDirty.QuadPart) 
    {

        AFSQueueFlushExtents( Fcb);
    }

    AFSReleaseResource( &Fcb->NPFcb->Specific.File.ExtentsResource );
    
}
//
// Helper functions
//

static AFSExtent *ExtentFor(PLIST_ENTRY le, ULONG SkipList) 
{
    return CONTAINING_RECORD( le, AFSExtent, Lists[SkipList] );
}

static AFSExtent *NextExtent(AFSExtent *Extent, ULONG SkipList)
{
    return ExtentFor(Extent->Lists[SkipList].Flink, SkipList);
}

static AFSExtent *DirtyExtentFor(PLIST_ENTRY le) 
{
    return CONTAINING_RECORD( le, AFSExtent, DirtyList );
}

static VOID VerifyExtentsLists(AFSFcb *Fcb)
{
#if DBG > 0
    //
    // Check the ordering of the extents lists
    //
    ASSERT( ExIsResourceAcquiredLite( &Fcb->NPFcb->Specific.File.ExtentsResource ));
    
    ASSERT(Fcb->Specific.File.ExtentsLists[0].Flink != &Fcb->Specific.File.ExtentsLists[1]);

    for (ULONG listNo = 0; listNo < AFS_NUM_EXTENT_LISTS; listNo ++)
    {
        LARGE_INTEGER lastOffset;

        lastOffset.QuadPart = 0;

        for (PLIST_ENTRY pLe = Fcb->Specific.File.ExtentsLists[listNo].Flink; 
             pLe != &Fcb->Specific.File.ExtentsLists[listNo];
             pLe = pLe->Flink)
        {
            AFSExtent *pExtent;

            pExtent = ExtentFor(pLe, listNo);

            if (listNo == 0) {
                ASSERT(pLe        != &Fcb->Specific.File.ExtentsLists[1] &&
                       pLe->Flink !=&Fcb->Specific.File.ExtentsLists[1] &&
                       pLe->Blink !=&Fcb->Specific.File.ExtentsLists[1]);
            }

            ASSERT(pLe->Flink->Blink == pLe);
            ASSERT(pLe->Blink->Flink == pLe);

            //
            // Should follow on from previous
            //
            ASSERT(pExtent->FileOffset.QuadPart >= lastOffset.QuadPart);
            lastOffset.QuadPart = pExtent->FileOffset.QuadPart + pExtent->Size;

            //
            // Should match alignment criteria
            //
            ASSERT( 0 == (pExtent->FileOffset.LowPart & ExtentsMasks[listNo]) );

            //
            // "lower" lists should be populated
            //
            for (LONG subListNo = listNo-1; subListNo > 0; subListNo --)
            {
                ASSERT( !IsListEmpty(&pExtent->Lists[subListNo]));
            }
        }
    }
#endif
}

void
AFSTrimExtents( IN AFSFcb *Fcb,
                IN PLARGE_INTEGER FileSize)
{

    AFSNonPagedFcb      *pNPFcb = Fcb->NPFcb;
    LIST_ENTRY          *le;
    AFSExtent           *pExtent;
    BOOLEAN              locked = FALSE;
    NTSTATUS             ntStatus = STATUS_SUCCESS;
    LARGE_INTEGER        liAlignedOffset = {0,0};
    AFSDeviceExt        *pDevExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;

    __Enter
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSTrimExtents For file %wZ Offset %I64X\n",
                                            &Fcb->DirEntry->DirectoryEntry.FileName,
                                            FileSize->QuadPart);        

        //
        // Get an aligned offset
        //

        if( FileSize != NULL)
        {

            liAlignedOffset = *FileSize;
        }

        if( liAlignedOffset.QuadPart > 0 &&
            liAlignedOffset.QuadPart % pDevExt->Specific.RDR.CacheBlockSize != 0)
        {

            //
            // Align UP to the next cache block size
            //

            liAlignedOffset.QuadPart = (ULONGLONG)( (ULONGLONG)((liAlignedOffset.QuadPart / pDevExt->Specific.RDR.CacheBlockSize) + 1) * (ULONGLONG)pDevExt->Specific.RDR.CacheBlockSize);
        }

        //
        // Ensure that noone is working with the extents and grab the
        // lock
        //

        AFSLockForExtentsTrim( Fcb);

        locked = TRUE;

        if( 0 == Fcb->Specific.File.ExtentCount)
        {

            //
            // Update the request extent status
            //

            Fcb->NPFcb->Specific.File.ExtentsRequestStatus = STATUS_SUCCESS;

            try_return( ntStatus = STATUS_SUCCESS);
        }

        //
        // We are truncating from a specific length in the file. If the offset
        // is non-zero then go find the first extent to remove
        //

        if( 0 == FileSize->QuadPart) 
        {

            le = Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST].Flink;
        } 
        else 
        {

            pExtent = AFSExtentForOffset( Fcb, 
                                          FileSize, 
                                          TRUE);

            if( NULL == pExtent) 
            {

                le = Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST].Flink;
            } 
            else 
            {
                le = &pExtent->Lists[AFS_EXTENTS_LIST];
            }
        }

        while( le != &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST]) 
        {

            pExtent = ExtentFor( le, AFS_EXTENTS_LIST);

            //
            // Only trim down extents beyond the aligned offset
            //

            le = le->Flink;

            if( pExtent->FileOffset.QuadPart >= liAlignedOffset.QuadPart)
            {

                if( BooleanFlagOn( pExtent->Flags, AFS_EXTENT_DIRTY))
                {

                    AFSAcquireExcl( &pNPFcb->Specific.File.DirtyExtentsListLock, 
                                    TRUE);

                    if( BooleanFlagOn( pExtent->Flags, AFS_EXTENT_DIRTY))
                    {
                        LONG dirtyCount;

                        RemoveEntryList( &pExtent->DirtyList);

                        dirtyCount = InterlockedDecrement( &Fcb->Specific.File.ExtentsDirtyCount);

                        ASSERT(dirtyCount >= 0);

                    }

                    AFSReleaseResource( &pNPFcb->Specific.File.DirtyExtentsListLock);

                }

                for (ULONG i = 0; i < AFS_NUM_EXTENT_LISTS; i ++) 
                {
                    if (NULL != pExtent->Lists[i].Flink && !IsListEmpty(&pExtent->Lists[i]))
                    {
                        RemoveEntryList( &pExtent->Lists[i] );
                    }
                }

                AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSTrimExtents Trimming extent for %wZ %08lX-%08lX Offset %I64X Len %08lX\n",
                              &Fcb->DirEntry->DirectoryEntry.FileName,
                              Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                              Fcb->DirEntry->DirectoryEntry.FileId.Unique,
                              pExtent->FileOffset.QuadPart,
                              pExtent->Size); 
                //      
                // and free
                //
                ExFreePoolWithTag( pExtent, AFS_EXTENT_TAG );
                AFSAllocationMemoryLevel -= sizeof( AFSExtent);

                InterlockedDecrement( &Fcb->Specific.File.ExtentCount);
            }
        }

        //
        // Update the request extent status
        //

        Fcb->NPFcb->Specific.File.ExtentsRequestStatus = STATUS_SUCCESS;

        AFSReleaseResource( &Fcb->NPFcb->Specific.File.ExtentsResource );
        locked = FALSE;

try_exit:

        AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSTrimExtents Completed for file %wZ Status %08lX FID %08lX-%08lX-%08lX-%08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      ntStatus);        

        if (locked)
        {
            AFSReleaseResource( &Fcb->NPFcb->Specific.File.ExtentsResource );
        }
    }

    return;
}

void
AFSTrimSpecifiedExtents( IN AFSFcb *Fcb,
                         IN ULONG   Count,
                         IN AFSFileExtentCB *Result)
{

    AFSNonPagedFcb      *pNPFcb = Fcb->NPFcb;
    LIST_ENTRY          *le;
    AFSExtent           *pExtent;
    AFSFileExtentCB     *pFileExtents = Result;
    NTSTATUS             ntStatus = STATUS_SUCCESS;
    AFSDeviceExt        *pDevExt = (AFSDeviceExt *)AFSRDRDeviceObject->DeviceExtension;

    __Enter
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSTrimSpecifiedExtents For file %wZ FID %08lX-%08lX-%08lX-%08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique
                      );

        le = Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST].Flink;

        while( le != &Fcb->Specific.File.ExtentsLists[AFS_EXTENTS_LIST] &&
               Count > 0) 
        {

            pExtent = ExtentFor( le, AFS_EXTENTS_LIST);

            //
            // Only trim down extents beyond the aligned offset
            //

            le = le->Flink;

            if( pExtent->FileOffset.QuadPart == pFileExtents->FileOffset.QuadPart)
            {

                if( BooleanFlagOn( pExtent->Flags, AFS_EXTENT_DIRTY))
                {

                    AFSAcquireExcl( &pNPFcb->Specific.File.DirtyExtentsListLock, 
                                    TRUE);

                    if( BooleanFlagOn( pExtent->Flags, AFS_EXTENT_DIRTY))
                    {

                        LONG dirtyCount;

                        RemoveEntryList( &pExtent->DirtyList);

                        dirtyCount = InterlockedDecrement( &Fcb->Specific.File.ExtentsDirtyCount);

                        ASSERT( dirtyCount >= 0);

                    }

                    AFSReleaseResource( &pNPFcb->Specific.File.DirtyExtentsListLock);

                }

                for (ULONG i = 0; i < AFS_NUM_EXTENT_LISTS; i ++) 
                {
                    if (NULL != pExtent->Lists[i].Flink && !IsListEmpty(&pExtent->Lists[i]))
                    {
                        RemoveEntryList( &pExtent->Lists[i] );
                    }
                }

                AFSDbgLogMsg( AFS_SUBSYSTEM_EXTENT_PROCESSING,
                              AFS_TRACE_LEVEL_VERBOSE,
                              "AFSTrimSpecifiedExtents Trimming extent for %wZ FID %08lX-%08lX-%08lX-%08lX Offset %I64X Len %08lX\n",
                              &Fcb->DirEntry->DirectoryEntry.FileName,
                              Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                              Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                              Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                              Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                              pExtent->FileOffset.QuadPart,
                              pExtent->Size); 

                //
                // and free
                //
                ExFreePoolWithTag( pExtent, AFS_EXTENT_TAG );
                AFSAllocationMemoryLevel -= sizeof( AFSExtent);

                InterlockedDecrement( &Fcb->Specific.File.ExtentCount);

                //
                // Next extent we are looking for
                //

                pFileExtents++;

                Count--;
            }
        }

        //
        // Update the request extent status
        //

        Fcb->NPFcb->Specific.File.ExtentsRequestStatus = STATUS_SUCCESS;

        AFSDbgLogMsg( AFS_SUBSYSTEM_IO_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSTrimSpecifiedExtents Completed for file %wZ FID %08lX-%08lX-%08lX-%08lX Status %08lX\n",
                      &Fcb->DirEntry->DirectoryEntry.FileName,
                      Fcb->DirEntry->DirectoryEntry.FileId.Cell,
                      Fcb->DirEntry->DirectoryEntry.FileId.Volume,
                      Fcb->DirEntry->DirectoryEntry.FileId.Vnode,
                      Fcb->DirEntry->DirectoryEntry.FileId.Unique,                                            
                      ntStatus);        
    }

    return;
}