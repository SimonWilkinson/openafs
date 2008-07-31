#ifndef _AFS_COMMON_H
#define _AFS_COMMON_H

//
// File: AFSCommon.h
//

extern "C"
{

#define AFS_KERNEL_MODE

#include <ntifs.h>

#include "AFSDefines.h"

#include "AFSUserCommon.h"

#include "AFSStructs.h"

#include "AFSProvider.h"

#ifndef NO_EXTERN
#include "AFSExtern.h"
#endif

#define NTSTRSAFE_LIB
#include "ntstrsafe.h"

//
// AFSBTreeSupport.cpp Prototypes
//

NTSTATUS
AFSLocateDirEntry( IN AFSDirEntryCB *RootNode,
                   IN ULONG Index,
                   IN OUT AFSDirEntryCB **DirEntry);

NTSTATUS
AFSInsertDirEntry( IN AFSDirEntryCB *RootNode,
                   IN AFSDirEntryCB *DirEntry);

NTSTATUS
AFSRemoveDirEntry( IN AFSDirEntryCB **RootNode,
                   IN AFSDirEntryCB *DirEntry);

NTSTATUS
AFSLocateShortNameDirEntry( IN AFSDirEntryCB *RootNode,
                            IN ULONG Index,
                            IN OUT AFSDirEntryCB **DirEntry);

NTSTATUS
AFSInsertShortNameDirEntry( IN AFSDirEntryCB *RootNode,
                            IN AFSDirEntryCB *DirEntry);

NTSTATUS
AFSRemoveShortNameDirEntry( IN AFSDirEntryCB **RootNode,
                            IN AFSDirEntryCB *DirEntry);

NTSTATUS
AFSLocateFileIDEntry( IN AFSBTreeEntry *TopNode,
                      IN ULONG Index,
                      IN OUT AFSFcb **Fcb);

NTSTATUS
AFSInsertFileIDEntry( IN AFSBTreeEntry *TopNode,
                      IN AFSBTreeEntry *FileIDEntry);

NTSTATUS
AFSRemoveFileIDEntry( IN AFSBTreeEntry **TopNode,
                      IN AFSBTreeEntry *FileIDEntry);

//
// AFSInit.cpp Prototypes
//

NTSTATUS
DriverEntry( IN PDRIVER_OBJECT DriverObj,
             IN PUNICODE_STRING RegPath);

void
AFSUnload( IN PDRIVER_OBJECT DriverObject);

//
// AFSCommSupport.cpp Prototypes
//

NTSTATUS
AFSEnumerateDirectory( IN AFSFileID          *ParentFileID,
                       IN OUT AFSDirHdr      *DirectoryHdr,
                       IN OUT AFSDirEntryCB **DirListHead,
                       IN OUT AFSDirEntryCB **DirListTail,
                       IN OUT AFSDirEntryCB **ShortNameTree,
                       IN UNICODE_STRING       *CallerSID);

NTSTATUS
AFSNotifyFileCreate( IN AFSFcb *ParentDcb,
                     IN PLARGE_INTEGER FileSize,
                     IN ULONG FileAttributes,
                     IN UNICODE_STRING *FileName,
                     OUT AFSDirEntryCB **DirNode);

NTSTATUS
AFSUpdateFileInformation( IN PDEVICE_OBJECT DeviceObject,
                          IN AFSFcb *Fcb);

NTSTATUS
AFSNotifyDelete( IN AFSFcb *Fcb);

NTSTATUS
AFSNotifyRename( IN AFSFcb *Fcb,
                 IN AFSFcb *ParentDcb,
                 IN AFSFcb *TargetDcb,
                 IN UNICODE_STRING *TargetName);

NTSTATUS
AFSEvaluateTargetByID( IN AFSFileID *ParentFileId,
                       IN AFSFileID *SourceFileId,
                       OUT AFSDirEnumEntry **DirEnumEntry);

NTSTATUS
AFSEvaluateTargetByName( IN AFSFileID *ParentFileId,
                         IN PUNICODE_STRING SourceName,
                         OUT AFSDirEnumEntry **DirEnumEntry);

NTSTATUS
AFSProcessRequest( IN ULONG RequestType,
                   IN ULONG RequestFlags,
                   IN HANDLE CallerProcess,
                   IN PUNICODE_STRING FileName,
                   IN AFSFileID *FileId,
                   IN void  *Data,
                   IN ULONG DataLength,
                   IN OUT void *ResultBuffer,
                   IN OUT PULONG ResultBufferLength);

NTSTATUS
AFSProcessControlRequest( IN PIRP Irp);

NTSTATUS
AFSInitIrpPool( void);

void
AFSCleanupIrpPool( void);

NTSTATUS 
AFSProcessIrpRequest( IN PIRP Irp);

NTSTATUS 
AFSProcessIrpResult( IN PIRP Irp);

NTSTATUS
AFSInsertRequest( IN AFSCommSrvcCB *CommSrvc,
                  IN AFSPoolEntry *Entry);

//
// AFSCreate.cpp Prototypes
//

NTSTATUS
AFSCreate( IN PDEVICE_OBJECT DeviceObject,
           IN PIRP Irp);

NTSTATUS
AFSCommonCreate( IN PDEVICE_OBJECT DeviceObject,
                 IN PIRP Irp);

NTSTATUS
AFSOpenAFSRoot( IN PIRP Irp,
                IN AFSFcb **Fcb,
                IN AFSCcb **Ccb);

NTSTATUS
AFSOpenRoot( IN PIRP Irp,
             IN AFSFcb *Fcb,
             IN AFSCcb **Ccb);

NTSTATUS
AFSProcessCreate( IN PIRP               Irp,
                  IN AFSFcb          *ParentDcb,
                  IN PUNICODE_STRING    FileName,
                  IN PUNICODE_STRING    ComponentName,
                  IN OUT AFSFcb      **Fcb,
                  IN OUT AFSCcb      **Ccb);

NTSTATUS
AFSOpenTargetDirectory( IN PDEVICE_OBJECT DeviceObject,
                        IN PIRP Irp,
                        IN AFSFcb *Fcb,
                        IN PUNICODE_STRING TargetName,
                        IN OUT AFSCcb **Ccb);

NTSTATUS
AFSProcessOpen( IN PIRP Irp,
                IN AFSFcb *ParentDcb,
                IN OUT AFSFcb *Fcb,
                IN OUT AFSCcb **Ccb);

NTSTATUS
AFSProcessOverwriteSupersede( IN PIRP             Irp,
                              IN AFSFcb        *ParentDcb,
                              IN AFSFcb        *Fcb,
                              IN AFSCcb       **Ccb);

NTSTATUS
AFSControlDeviceCreate( IN PIRP Irp);

NTSTATUS
AFSOpenIOCtlFcb( IN PIRP Irp,
                 IN AFSFcb *ParentDcb,
                 OUT AFSFcb **Fcb,
                 OUT AFSCcb **Ccb);

//
// AFSExtentsSupport.cpp Prototypes
//
VOID
AFSReferenceExtents( IN AFSFcb *Fcb);

VOID
AFSDereferenceExtents( IN AFSFcb *Fcb);

VOID 
AFSLockForExtentsTrim( IN AFSFcb *Fcb);

PAFSExtent
AFSExtentForOffset( IN AFSFcb *Fcb, 
                    IN PLARGE_INTEGER Offset,
                    IN BOOLEAN ReturnPrevious);
BOOLEAN
AFSExtentContains( IN AFSExtent *Extent, IN PLARGE_INTEGER Offset);


NTSTATUS
AFSRequestExtents( IN  AFSFcb *Fcb, 
                   IN  PLARGE_INTEGER Offset, 
                   IN  ULONG Size,
                   OUT BOOLEAN *FullyMapped,
                   OUT AFSExtent **FirstExtent);
    
NTSTATUS
AFSWaitForExtentMapping ( IN AFSFcb *Fcb );

NTSTATUS
AFSProcessSetFileExtents( IN AFSSetFileExtentsCB *SetExtents );

NTSTATUS
AFSProcessReleaseFileExtents( IN AFSReleaseFileExtentsCB *SetExtents );

NTSTATUS
AFSProcessReleaseFileExtentsByFcb( IN AFSReleaseFileExtentsCB *Extents,
                                   IN AFSFcb *Fcb);


NTSTATUS
AFSProcessSetExtents( IN AFSFcb *pFcb,
                      IN ULONG   Count,
                      IN AFSFileExtentCB *Result);

NTSTATUS
AFSFlushExtents( IN AFSFcb *pFcb);

VOID
AFSMarkDirty( IN AFSFcb *pFcb,
              IN PLARGE_INTEGER Offset,
              IN ULONG   Count);

NTSTATUS
AFSTearDownFcbExtents( IN AFSFcb *Fcb ) ;

//
//
// AFSIoSupp.cpp Prototypes
//
NTSTATUS
AFSGetExtents( IN  AFSFcb *pFcb,
               IN  PLARGE_INTEGER Offset,
               IN  ULONG Length,
               IN  AFSExtent *From,
               OUT ULONG *Count);

NTSTATUS
AFSSetupIoRun( IN PDEVICE_OBJECT CacheDevice,
               IN PIRP           MasterIrp,
               IN PVOID          SystemBuffer,
               IN OUT AFSIoRun  *IoRun,
               IN PLARGE_INTEGER Start,
               IN ULONG          Length,
               IN AFSExtent     *From,
               IN OUT ULONG     *Count);

NTSTATUS 
AFSStartIos( IN PFILE_OBJECT     CacheFileObject,
             IN UCHAR            FunctionCode,
             IN ULONG            IrpFlags,
             IN AFSIoRun        *IoRun,
             IN ULONG            Count,
             IN OUT AFSGatherIo *Gather);

VOID
AFSCompleteIo( IN AFSGatherIo *Gather, NTSTATUS Status);
//
// AFSClose.cpp Prototypes
//

NTSTATUS
AFSClose( IN PDEVICE_OBJECT DeviceObject,
          IN PIRP Irp);

//
// AFSFcbSupport.cpp Prototypes
//

NTSTATUS
AFSInitFcb( IN AFSFcb          *ParentFcb,
            IN PUNICODE_STRING    FileName,
            IN AFSDirEntryCB   *DirEntry,
            IN OUT AFSFcb     **Fcb);

NTSTATUS
AFSInitAFSRoot( void);

NTSTATUS
AFSRemoveAFSRoot( void);

NTSTATUS
AFSInitRootFcb( IN PDEVICE_OBJECT DeviceObject);

void
AFSRemoveRootFcb( IN AFSFcb *RootFcb);

NTSTATUS
AFSInitCcb( IN AFSFcb     *Fcb,
            IN OUT AFSCcb **Ccb);

void
AFSRemoveFcb( IN AFSFcb *Fcb);

NTSTATUS
AFSRemoveCcb( IN AFSFcb *Fcb,
              IN AFSCcb *Ccb);

NTSTATUS
AFSInitializeVolume( IN AFSDirEntryCB *VolumeDirEntry);

//
// AFSNameSupport.cpp Prototypes
//

NTSTATUS
AFSLocateNameEntry( IN AFSFcb *RootFcb,
                    IN PFILE_OBJECT FileObject,
                    IN UNICODE_STRING *FullPathName,
                    IN OUT AFSFcb **ParentFcb,
                    IN OUT AFSFcb **Fcb,
                    IN OUT PUNICODE_STRING ComponentName);

NTSTATUS
AFSCreateDirEntry( IN AFSFcb *ParentDcb,
                   IN PUNICODE_STRING FileName,
                   IN PUNICODE_STRING ComponentName,
                   IN ULONG Attributes,
                   IN OUT AFSDirEntryCB **DirEntry);

NTSTATUS
AFSGenerateShortName( IN AFSFcb *ParentDcb,
                      IN AFSDirEntryCB *DirNode);

void
AFSInsertDirectoryNode( IN AFSFcb *ParentDcb,
                        IN AFSDirEntryCB *DirEntry);

NTSTATUS
AFSDeleteDirEntry( IN AFSFcb *ParentDcb,
                   IN AFSDirEntryCB *DirEntry);

NTSTATUS
AFSRemoveDirNodeFromParent( IN AFSFcb *ParentDcb,
                            IN AFSDirEntryCB *DirEntry);

NTSTATUS
AFSFixupTargetName( IN OUT PUNICODE_STRING FileName,
                    IN OUT PUNICODE_STRING TargetFileName);

NTSTATUS
AFSGetFullName( IN AFSFcb *Fcb,
                IN OUT PUNICODE_STRING FullFileName);

NTSTATUS 
AFSParseName( IN PIRP Irp,
              OUT PUNICODE_STRING FileName,
              OUT BOOLEAN *FreeNameString,
              OUT AFSFcb **RootFcb);

NTSTATUS
AFSCheckCellName( IN UNICODE_STRING *CellName,
                  OUT AFSDirEntryCB **ShareDirEntry);

//
// AFSNetworkProviderSupport.cpp
//

NTSTATUS
AFSAddConnection( IN RedirConnectionCB *ConnectCB,
                  IN OUT PULONG ResultStatus,
                  IN OUT PULONG ReturnOutputBufferLength);

NTSTATUS
AFSCancelConnection( IN RedirConnectionCB *ConnectCB,
                     IN OUT PULONG ResultStatus,
                     IN OUT PULONG ReturnOutputBufferLength);

NTSTATUS
AFSGetConnection( IN RedirConnectionCB *ConnectCB,
                  IN OUT WCHAR *RemoteName,
                  IN ULONG RemoteNameBufferLength,
                  IN OUT PULONG ReturnOutputBufferLength);

NTSTATUS
AFSListConnections( IN OUT RedirConnectionCB *ConnectCB,
                    IN ULONG ConnectionBufferLength,
                    IN OUT PULONG ReturnOutputBufferLength);

//
// AFSRead.cpp Prototypes
//

NTSTATUS
AFSRead( IN PDEVICE_OBJECT DeviceObject,
         IN PIRP Irp);

NTSTATUS
AFSIOCtlRead( IN PDEVICE_OBJECT DeviceObject,
              IN PIRP Irp);

//
// AFSWrite.cpp Prototypes
//

NTSTATUS
AFSWrite( IN PDEVICE_OBJECT DeviceObject,
          IN PIRP Irp);

NTSTATUS
AFSCommonWrite( IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp);

NTSTATUS
AFSIOCtlWrite( IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp);

//
// AFSFileInfo.cpp Prototypes
//

NTSTATUS
AFSQueryFileInfo( IN PDEVICE_OBJECT DeviceObject,
                  IN PIRP Irp);

NTSTATUS
AFSQueryBasicInfo( IN PIRP Irp,
                   IN AFSFcb *Fcb,
                   IN OUT PFILE_BASIC_INFORMATION Buffer,
                   IN OUT PLONG Length);

NTSTATUS
AFSQueryStandardInfo( IN PIRP Irp,
                      IN AFSFcb *Fcb,
                      IN OUT PFILE_STANDARD_INFORMATION Buffer,
                      IN OUT PLONG Length);

NTSTATUS
AFSQueryInternalInfo( IN PIRP Irp,
                      IN AFSFcb *Fcb,
                      IN OUT PFILE_INTERNAL_INFORMATION Buffer,
                      IN OUT PLONG Length);

NTSTATUS
AFSQueryEaInfo( IN PIRP Irp,
                IN AFSFcb *Fcb,
                IN OUT PFILE_EA_INFORMATION Buffer,
                IN OUT PLONG Length);

NTSTATUS
AFSQueryPositionInfo( IN PIRP Irp,
                      IN AFSFcb *Fcb,
                      IN OUT PFILE_POSITION_INFORMATION Buffer,
                      IN OUT PLONG Length);

NTSTATUS
AFSQueryNameInfo( IN PIRP Irp,
                  IN AFSFcb *Fcb,
                  IN OUT PFILE_NAME_INFORMATION Buffer,
                  IN OUT PLONG Length);

NTSTATUS
AFSQueryShortNameInfo( IN PIRP Irp,
                       IN AFSFcb *Fcb,
                       IN OUT PFILE_NAME_INFORMATION Buffer,
                       IN OUT PLONG Length);

NTSTATUS
AFSQueryNetworkInfo( IN PIRP Irp,
                     IN AFSFcb *Fcb,
                     IN OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
                     IN OUT PLONG Length);


NTSTATUS
AFSQueryAccess( IN PIRP Irp,
                IN AFSFcb *Fcb,
                IN OUT PFILE_ACCESS_INFORMATION Buffer,
                IN OUT PLONG Length);

NTSTATUS
AFSQueryMode( IN PIRP Irp,
              IN AFSFcb *Fcb,
              IN OUT PFILE_MODE_INFORMATION Buffer,
              IN OUT PLONG Length);

NTSTATUS
AFSQueryAlignment( IN PIRP Irp,
                   IN AFSFcb *Fcb,
                   IN OUT PFILE_ALIGNMENT_INFORMATION Buffer,
                   IN OUT PLONG Length);

NTSTATUS
AFSSetFileInfo( IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp);

NTSTATUS
AFSSetBasicInfo( IN PIRP Irp,
                 IN AFSFcb *Fcb);

NTSTATUS
AFSSetDispositionInfo( IN PIRP Irp,
                       IN AFSFcb *Fcb);

NTSTATUS
AFSSetRenameInfo( IN PDEVICE_OBJECT DeviceObject,
                  IN PIRP Irp,
                  IN AFSFcb *Fcb);

NTSTATUS
AFSSetPositionInfo( IN PIRP Irp,
                    IN AFSFcb *Fcb);

NTSTATUS
AFSSetAllocationInfo( IN PIRP Irp,
                      IN AFSFcb *Fcb);

NTSTATUS
AFSSetEndOfFileInfo( IN PIRP Irp,
                     IN AFSFcb *Fcb);

//
// AFSEa.cpp Prototypes
//

NTSTATUS
AFSQueryEA( IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp);

NTSTATUS
AFSSetEA( IN PDEVICE_OBJECT DeviceObject,
          IN PIRP Irp);

//
// AFSFlushBuffers.cpp Prototypes
//

NTSTATUS
AFSFlushBuffers( IN PDEVICE_OBJECT DeviceObject,
                 IN PIRP Irp);

//
// AFSVolumeInfo.cpp Prototypes
//

NTSTATUS
AFSQueryVolumeInfo( IN PDEVICE_OBJECT DeviceObject,
                    IN PIRP Irp);

NTSTATUS
AFSSetVolumeInfo( IN PDEVICE_OBJECT DeviceObject,
                  IN PIRP Irp);

NTSTATUS
AFSQueryFsVolumeInfo( IN AFSVolumeInfoCB *VolumeInfo,
                      IN PFILE_FS_VOLUME_INFORMATION Buffer,
                      IN OUT PULONG Length);

NTSTATUS
AFSQueryFsSizeInfo( IN AFSVolumeInfoCB *VolumeInfo,
                    IN PFILE_FS_SIZE_INFORMATION Buffer,
                    IN OUT PULONG Length);

NTSTATUS
AFSQueryFsDeviceInfo( IN AFSVolumeInfoCB *VolumeInfo,
                      IN PFILE_FS_DEVICE_INFORMATION Buffer,
                      IN OUT PULONG Length);

NTSTATUS
AFSQueryFsAttributeInfo( IN AFSVolumeInfoCB *VolumeInfo,
                         IN PFILE_FS_ATTRIBUTE_INFORMATION Buffer,
                         IN OUT PULONG Length);

NTSTATUS
AFSQueryFsFullSizeInfo( IN AFSVolumeInfoCB *VolumeInfo,
                        IN PFILE_FS_FULL_SIZE_INFORMATION Buffer,
                        IN OUT PULONG Length);

//
// AFSDirControl.cpp Prototypes
//

NTSTATUS
AFSDirControl( IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp);

NTSTATUS 
AFSQueryDirectory( IN PIRP Irp);

NTSTATUS
AFSNotifyChangeDirectory( IN PIRP Irp);

//
// AFSFSControl.cpp Prototypes
//

NTSTATUS
AFSFSControl( IN PDEVICE_OBJECT DeviceObject,
              IN PIRP Irp);

NTSTATUS
AFSProcessUserFsRequest( IN PIRP Irp);

//
// AFSDevControl.cpp Prototypes
//

NTSTATUS
AFSDevControl( IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp);

//
// AFSInternalDevControl.cpp Prototypes
//

NTSTATUS
AFSInternalDevControl( IN PDEVICE_OBJECT DeviceObject,
                       IN PIRP Irp);

//
// AFSShutdown.cpp Prototypes
//

NTSTATUS
AFSShutdown( IN PDEVICE_OBJECT DeviceObject,
             IN PIRP Irp);


NTSTATUS
AFSShutdownFilesystem( void);

//
// AFSLockControl.cpp Prototypes
//

NTSTATUS
AFSLockControl( IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp);

//
// AFSCleanup.cpp Prototypes
//

NTSTATUS
AFSCleanup( IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp);

//
// AFSSecurity.cpp Prototypes
//

NTSTATUS
AFSQuerySecurity( IN PDEVICE_OBJECT DeviceObject,
                  IN PIRP Irp);

NTSTATUS
AFSSetSecurity( IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp);

//
// AFSSystemControl.cpp Prototypes
//

NTSTATUS
AFSSystemControl( IN PDEVICE_OBJECT DeviceObject,
                  IN PIRP Irp);

//
// AFSQuota.cpp Prototypes
//

NTSTATUS
AFSQueryQuota( IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp);

NTSTATUS
AFSSetQuota( IN PDEVICE_OBJECT DeviceObject,
             IN PIRP Irp);

//
// AFSGeneric.cpp Prototypes
//

ULONG
AFSExceptionFilter( IN ULONG Code,
                    IN PEXCEPTION_POINTERS ExceptPtrs);

BOOLEAN
AFSAcquireExcl( IN PERESOURCE Resource,
                IN BOOLEAN wait);

BOOLEAN
AFSAcquireShared( IN PERESOURCE Resource,
                  IN BOOLEAN wait);

void
AFSReleaseResource( IN PERESOURCE Resource);

void
AFSConvertToShared( IN PERESOURCE Resource);

void
AFSCompleteRequest( IN PIRP Irp,
                    IN ULONG Status);

void 
AFSBuildCRCTable( void);

ULONG
AFSGenerateCRC( IN PUNICODE_STRING FileName);

BOOLEAN 
AFSAcquireForLazyWrite( IN PVOID Context,
                        IN BOOLEAN Wait);

VOID 
AFSReleaseFromLazyWrite( IN PVOID Context);

BOOLEAN 
AFSAcquireForReadAhead( IN PVOID Context,
                        IN BOOLEAN Wait);

VOID 
AFSReleaseFromReadAhead( IN PVOID Context);

void *
AFSLockSystemBuffer( IN PIRP Irp,
                     IN ULONG Length);

void *
AFSMapToService( IN PIRP Irp,
                 IN ULONG ByteCount);

NTSTATUS
AFSUnmapServiceMappedBuffer( IN void *MappedBuffer,
                             IN PMDL Mdl);

NTSTATUS
AFSReadRegistry( IN PUNICODE_STRING RegistryPath);

NTSTATUS
AFSInitializeControlFilter( void);

NTSTATUS
AFSDefaultDispatch( IN PDEVICE_OBJECT DeviceObject,
                    IN PIRP Irp);

NTSTATUS
AFSInitializeDirectory( IN AFSFcb *Dcb);

NTSTATUS
AFSInitNonPagedDirEntry( IN AFSDirEntryCB *DirNode);

AFSDirEntryCB *
AFSInitDirEntry( IN AFSFileID *ParentFileID,
                 IN PUNICODE_STRING FileName,
                 IN PUNICODE_STRING TargetName,
                 IN AFSDirEnumEntry *DirEnumEntry,
                 IN ULONG FileIndex);

BOOLEAN
AFSCheckForReadOnlyAccess( IN ACCESS_MASK DesiredAccess);

NTSTATUS
AFSEvaluateNode( IN AFSFcb *Fcb);

NTSTATUS
AFSInvalidateCache( IN AFSInvalidateCacheCB *InvalidateCB);

BOOLEAN
AFSIsChildOfParent( IN AFSFcb *Dcb,
                    IN AFSFcb *Fcb);

//
// Prototypes in AFSFastIoSupprt.cpp
//

BOOLEAN
AFSFastIoCheckIfPossible( IN struct _FILE_OBJECT *FileObject,
                          IN PLARGE_INTEGER FileOffset,
                          IN ULONG Length,
                          IN BOOLEAN Wait,
                          IN ULONG LockKey,
                          IN BOOLEAN CheckForReadOperation,
                          OUT PIO_STATUS_BLOCK IoStatus,
                          IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoRead( IN struct _FILE_OBJECT *FileObject,
               IN PLARGE_INTEGER FileOffset,
               IN ULONG Length,
               IN BOOLEAN Wait,
               IN ULONG LockKey,
               OUT PVOID Buffer,
               OUT PIO_STATUS_BLOCK IoStatus,
               IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoWrite( IN struct _FILE_OBJECT *FileObject,
                IN PLARGE_INTEGER FileOffset,
                IN ULONG Length,
                IN BOOLEAN Wait,
                IN ULONG LockKey,
                IN PVOID Buffer,
                OUT PIO_STATUS_BLOCK IoStatus,
                IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoQueryBasicInfo( IN struct _FILE_OBJECT *FileObject,
                         IN BOOLEAN Wait,
                         OUT PFILE_BASIC_INFORMATION Buffer,
                         OUT PIO_STATUS_BLOCK IoStatus,
                         IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoQueryStandardInfo( IN struct _FILE_OBJECT *FileObject,
                            IN BOOLEAN Wait,
                            OUT PFILE_STANDARD_INFORMATION Buffer,
                            OUT PIO_STATUS_BLOCK IoStatus,
                            IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoLock( IN struct _FILE_OBJECT *FileObject,
               IN PLARGE_INTEGER FileOffset,
               IN PLARGE_INTEGER Length,
               IN PEPROCESS ProcessId,
               IN ULONG Key,
               IN BOOLEAN FailImmediately,
               IN BOOLEAN ExclusiveLock,
               OUT PIO_STATUS_BLOCK IoStatus,
               IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoUnlockSingle( IN struct _FILE_OBJECT *FileObject,
                       IN PLARGE_INTEGER FileOffset,
                       IN PLARGE_INTEGER Length,
                       IN PEPROCESS ProcessId,
                       IN ULONG Key,
                       OUT PIO_STATUS_BLOCK IoStatus,
                       IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoUnlockAll( IN struct _FILE_OBJECT *FileObject,
                    IN PEPROCESS ProcessId,
                    OUT PIO_STATUS_BLOCK IoStatus,
                    IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoUnlockAllByKey( IN struct _FILE_OBJECT *FileObject,
                         IN PVOID ProcessId,
                         IN ULONG Key,
                         OUT PIO_STATUS_BLOCK IoStatus,
                         IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoDevCtrl( IN struct _FILE_OBJECT *FileObject,
                  IN BOOLEAN Wait,
                  IN PVOID InputBuffer OPTIONAL,
                  IN ULONG InputBufferLength,
                  OUT PVOID OutputBuffer OPTIONAL,
                  IN ULONG OutputBufferLength,
                  IN ULONG IoControlCode,
                  OUT PIO_STATUS_BLOCK IoStatus,
                  IN struct _DEVICE_OBJECT *DeviceObject);

VOID
AFSFastIoAcquireFile( IN struct _FILE_OBJECT *FileObject);

VOID
AFSFastIoReleaseFile( IN struct _FILE_OBJECT *FileObject);

VOID
AFSFastIoDetachDevice( IN struct _DEVICE_OBJECT *SourceDevice,
                       IN struct _DEVICE_OBJECT *TargetDevice);

BOOLEAN
AFSFastIoQueryNetworkOpenInfo( IN struct _FILE_OBJECT *FileObject,
                               IN BOOLEAN Wait,
                               OUT struct _FILE_NETWORK_OPEN_INFORMATION *Buffer,
                               OUT struct _IO_STATUS_BLOCK *IoStatus,
                               IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoMdlRead( IN struct _FILE_OBJECT *FileObject,
                  IN PLARGE_INTEGER FileOffset,
                  IN ULONG Length,
                  IN ULONG LockKey,
                  OUT PMDL *MdlChain,
                  OUT PIO_STATUS_BLOCK IoStatus,
                  IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoMdlReadComplete( IN struct _FILE_OBJECT *FileObject,
                          IN PMDL MdlChain,
                          IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoPrepareMdlWrite( IN struct _FILE_OBJECT *FileObject,
                          IN PLARGE_INTEGER FileOffset,
                          IN ULONG Length,
                          IN ULONG LockKey,
                          OUT PMDL *MdlChain,
                          OUT PIO_STATUS_BLOCK IoStatus,
                          IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoMdlWriteComplete( IN struct _FILE_OBJECT *FileObject,
                           IN PLARGE_INTEGER FileOffset,
                           IN PMDL MdlChain,
                           IN struct _DEVICE_OBJECT *DeviceObject);

NTSTATUS
AFSFastIoAcquireForModWrite( IN struct _FILE_OBJECT *FileObject,
                             IN PLARGE_INTEGER EndingOffset,
                             OUT struct _ERESOURCE **ResourceToRelease,
                             IN struct _DEVICE_OBJECT *DeviceObject);

NTSTATUS
AFSFastIoReleaseForModWrite( IN struct _FILE_OBJECT *FileObject,
                             IN struct _ERESOURCE *ResourceToRelease,
                             IN struct _DEVICE_OBJECT *DeviceObject);

NTSTATUS
AFSFastIoAcquireForCCFlush( IN struct _FILE_OBJECT *FileObject,
                            IN struct _DEVICE_OBJECT *DeviceObject);

NTSTATUS
AFSFastIoReleaseForCCFlush( IN struct _FILE_OBJECT *FileObject,
                            IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoReadCompressed( IN struct _FILE_OBJECT *FileObject,
                         IN PLARGE_INTEGER FileOffset,
                         IN ULONG Length,
                         IN ULONG LockKey,
                         OUT PVOID Buffer,
                         OUT PMDL *MdlChain,
                         OUT PIO_STATUS_BLOCK IoStatus,
                         OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
                         IN ULONG CompressedDataInfoLength,
                         IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoWriteCompressed( IN struct _FILE_OBJECT *FileObject,
                          IN PLARGE_INTEGER FileOffset,
                          IN ULONG Length,
                          IN ULONG LockKey,
                          IN PVOID Buffer,
                          OUT PMDL *MdlChain,
                          OUT PIO_STATUS_BLOCK IoStatus,
                          IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
                          IN ULONG CompressedDataInfoLength,
                          IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoMdlReadCompleteCompressed( IN struct _FILE_OBJECT *FileObject,
                                    IN PMDL MdlChain,
                                    IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoMdlWriteCompleteCompressed( IN struct _FILE_OBJECT *FileObject,
                                     IN PLARGE_INTEGER FileOffset,
                                     IN PMDL MdlChain,
                                     IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSFastIoQueryOpen( IN struct _IRP *Irp,
                    OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
                    IN struct _DEVICE_OBJECT *DeviceObject);

BOOLEAN
AFSAcquireFcbForLazyWrite( IN PVOID Fcb,
                           IN BOOLEAN Wait);

VOID
AFSReleaseFcbFromLazyWrite( IN PVOID Fcb);

BOOLEAN
AFSAcquireFcbForReadAhead( IN PVOID Fcb,
                           IN BOOLEAN Wait);

VOID
AFSReleaseFcbFromReadAhead( IN PVOID Fcb);

//
// AFSWorker.cpp Prototypes
//

NTSTATUS
AFSInitializeWorkerPool( void);

NTSTATUS
AFSRemoveWorkerPool( void);

NTSTATUS
AFSInitWorkerThread( IN AFSWorkQueueContext *PoolContext);

NTSTATUS
AFSShutdownWorkerThread( IN AFSWorkQueueContext *PoolContext);

void
AFSWorkerThread( IN PVOID Context);

void
AFSVolumeWorkerThread( IN PVOID Context);

NTSTATUS
AFSInsertWorkitem( IN AFSWorkItem *WorkItem);

AFSWorkItem *
AFSRemoveWorkItem( void);

NTSTATUS
AFSQueueWorkerRequest( IN AFSWorkItem *WorkItem);

NTSTATUS
AFSInitVolumeWorker( void);

NTSTATUS
AFSShutdownVolumeWorker( void);

//
// AFSRDRSupport.cpp Prototypes
//

NTSTATUS
AFSInitRDRDevice( void);

void
AFSDeleteRDRDevice( void);

NTSTATUS
AFSRDRDeviceControl( IN PDEVICE_OBJECT DeviceObject,
                     IN PIRP Irp);

NTSTATUS
AFSInitializeRedirector( IN AFSCacheFileInfo *CacheFileInfo);

NTSTATUS
AFSCloseRedirector( void);

NTSTATUS
AFSShutdownRedirector( void);

};

#endif /* _AFS_COMMON_H */