/*++

Copyright (c) 1989-2002  Microsoft Corporation

Module Name:

    mspyKern.h

Abstract:
    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes that are
    only visible within the kernel.

Environment:

    Kernel mode

--*/
#ifndef __MSPYKERN_H__
#define __MSPYKERN_H__

#include <fltKernel.h>
//#include <dontuse.h>
#include <suppress.h>
#include "minispy.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//
//  Memory allocation tag
//

#define SPY_TAG 'ypSM'

//
//  Vista define for including transaction support
//

#define MINISPY_VISTA    (NTDDI_VERSION >= NTDDI_VISTA)
#define MINISPY_NOT_W2K  (OSVER(NTDDI_VERSION) > NTDDI_WIN2K)

//
//  Define callback types for Vista
//

#if MINISPY_VISTA

//
//  Dynamically imported Filter Mgr APIs
//

typedef NTSTATUS
(*PFLT_SET_TRANSACTION_CONTEXT)(
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __in FLT_SET_CONTEXT_OPERATION Operation,
    __in PFLT_CONTEXT NewContext,
    __deref_opt_out PFLT_CONTEXT *OldContext
    );

typedef NTSTATUS
(*PFLT_GET_TRANSACTION_CONTEXT)(
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __deref_out PFLT_CONTEXT *Context
    );

typedef NTSTATUS
(*PFLT_ENLIST_IN_TRANSACTION)(
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __in PFLT_CONTEXT TransactionContext,
    __in NOTIFICATION_MASK NotificationMask
    );

#endif

//---------------------------------------------------------------------------
//      Global variables
//---------------------------------------------------------------------------

typedef struct _MINISPY_DATA {

    //
    //  The object that identifies this driver.
    //

    PDRIVER_OBJECT DriverObject;

    //
    //  The filter that results from a call to
    //  FltRegisterFilter.
    //

    PFLT_FILTER Filter;

    //
    //  Server port: user mode connects to this port
    //

    PFLT_PORT ServerPort;

    //
    //  Client connection port: only one connection is allowed at a time.,
    //

    PFLT_PORT ClientPort;

    //
    //  List of buffers with data to send to user mode.
    //

    KSPIN_LOCK OutputBufferLock;
    LIST_ENTRY OutputBufferList;

    //
    //  Lookaside list used for allocating buffers.
    //

    NPAGED_LOOKASIDE_LIST FreeBufferList;

    //
    //  Variables used to throttle how many records buffer we can use
    //

    LONG MaxRecordsToAllocate;
    __volatile LONG RecordsAllocated;

    //
    //  static buffer used for sending an "out-of-memory" message
    //  to user mode.
    //

    __volatile LONG StaticBufferInUse;

    //
    //  We need to make sure this buffer aligns on a PVOID boundary because
    //  minispy casts this buffer to a RECORD_LIST structure.
    //  That can cause alignment faults unless the structure starts on the
    //  proper PVOID boundary
    //

    PVOID OutOfMemoryBuffer[RECORD_SIZE/sizeof( PVOID )];

    //
    //  Variable and lock for maintaining LogRecord sequence numbers.
    //

    __volatile LONG LogSequenceNumber;

    //
    //  The name query method to use.  By default, it is set to
    //  FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, but it can be overridden
    //  by a setting in the registery.
    //

    ULONG NameQueryMethod;

    //
    //  Global debug flags
    //

    ULONG DebugFlags;

//#if MINISPY_VISTA
//
//    //
//    //  Dynamically imported Filter Mgr APIs
//    //
//
//    PFLT_SET_TRANSACTION_CONTEXT PFltSetTransactionContext;
//
//    PFLT_GET_TRANSACTION_CONTEXT PFltGetTransactionContext;
//
//    PFLT_ENLIST_IN_TRANSACTION PFltEnlistInTransaction;
//
//#endif

} MINISPY_DATA, *PMINISPY_DATA;


//
//  Defines the minispy context structure
//

typedef struct _MINISPY_TRANSACTION_CONTEXT {
    ULONG Flags;
    ULONG Count;

}MINISPY_TRANSACTION_CONTEXT, *PMINISPY_TRANSACTION_CONTEXT;

//
//  This macro below is used to set the flags field in minispy's
//  MINISPY_TRANSACTION_CONTEXT structure once it has been
//  successfully enlisted in the transaction.
//

#define MINISPY_ENLISTED_IN_TRANSACTION 0x01

//
//  Minispy's global variables
//

extern MINISPY_DATA MiniSpyData;

#define DEFAULT_MAX_RECORDS_TO_ALLOCATE     500
#define MAX_RECORDS_TO_ALLOCATE             L"MaxRecords"

#define DEFAULT_NAME_QUERY_METHOD           FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP
#define NAME_QUERY_METHOD                   L"NameQueryMethod"

//
//  DebugFlag values
//

#define SPY_DEBUG_PARSE_NAMES   0x00000001

//---------------------------------------------------------------------------
//  Registration structure
//---------------------------------------------------------------------------

extern const FLT_REGISTRATION FilterRegistration;

//---------------------------------------------------------------------------
//  Function prototypes
//---------------------------------------------------------------------------

FLT_PREOP_CALLBACK_STATUS
SpyPreOperationCallback (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
SpyPostOperationCallback (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

NTSTATUS
SpyKtmNotificationCallback (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PFLT_CONTEXT TransactionContext,
    __in ULONG TransactionNotification
    );

NTSTATUS
SpyFilterUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
SpyQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

VOID
SpyReadDriverParameters (
    __in PUNICODE_STRING RegistryPath
    );

NTSTATUS
PtInstanceSetup(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType,
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS
PtInstanceSetup(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType,
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
PtInstanceTeardownStart(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_TEARDOWN_FLAGS Flags
);


VOID
PtInstanceTeardownComplete(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

//---------------------------------------------------------------------------
//  Memory allocation routines
//---------------------------------------------------------------------------

PRECORD_LIST
SpyAllocateBuffer (
    __out PULONG RecordType
    );

VOID
SpyFreeBuffer (
    __in PVOID Buffer
    );

//---------------------------------------------------------------------------
//  Logging routines
//---------------------------------------------------------------------------
PRECORD_LIST
SpyNewRecord (
    VOID
    );

VOID
SpyFreeRecord (
    __in PRECORD_LIST Record
    );

VOID
SpySetRecordName (
    __inout PLOG_RECORD LogRecord,
    __in PUNICODE_STRING Name
    );

VOID
SpyLogPreOperationData (
    __in PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout PRECORD_LIST RecordList
    );

VOID
SpyLogPostOperationData (
    __in PFLT_CALLBACK_DATA Data,
    __inout PRECORD_LIST RecordList
    );

VOID
SpyLogTransactionNotify (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout PRECORD_LIST RecordList,
    __in ULONG TransactionNotification
    );

VOID
SpyLog (
    __in PRECORD_LIST RecordList
    );

NTSTATUS
SpyGetLog (
    __out_bcount_part(OutputBufferLength,*ReturnOutputBufferLength) PUCHAR OutputBuffer,
    __in ULONG OutputBufferLength,
    __out PULONG ReturnOutputBufferLength
    );

VOID
SpyEmptyOutputBufferList (
    VOID
    );

VOID
SpyDeleteTxfContext (
    __inout PFLT_CONTEXT  Context,
    __in FLT_CONTEXT_TYPE  ContextType
    );

#define PROCESS_TERMINATE         (0x0001)  
#define PROCESS_CREATE_THREAD     (0x0002)  
#define PROCESS_SET_SESSIONID     (0x0004)  
#define PROCESS_VM_OPERATION      (0x0008)  
#define PROCESS_VM_READ           (0x0010)  
#define PROCESS_VM_WRITE          (0x0020)  
#define PROCESS_DUP_HANDLE        (0x0040)  
#define PROCESS_CREATE_PROCESS    (0x0080)  
#define PROCESS_SET_QUOTA         (0x0100)  
#define PROCESS_SET_INFORMATION   (0x0200)  
#define PROCESS_QUERY_INFORMATION (0x0400)  
#define PROCESS_SUSPEND_RESUME    (0x0800)  

extern PROCESS_WHITE_LIST gPidWhiteList;
extern PATH_LIST gFilePathList;
extern PATH_LIST gRegPathList;

void HookSSDTTable();
void UnHookSSDTTable();

NTSTATUS InitialCallBack();

NTSTATUS UnInitialCallBack();

NTSTATUS GlobalInitial();

VOID GlobalUnInitial();

OB_PREOP_CALLBACK_STATUS
ProcessObjectPreCallback(
	__in PVOID  RegistrationContext,
	__in POB_PRE_OPERATION_INFORMATION  OperationInformation
);

NTSTATUS
RegistryCallback(
	__in PVOID  CallbackContext,
	__in_opt PVOID  Argument1,
	__in_opt PVOID  Argument2
);

VOID LoadImageNotify(
	__in PUNICODE_STRING FullImageName,
	__in HANDLE ProcessId,                // pid into which image is being mapped
	__in PIMAGE_INFO ImageInfo
);

UNICODE_STRING*
AllocateAndGetFileName(
	__in PFLT_CALLBACK_DATA Data,
	__in NTSTATUS* pStatus);

BOOLEAN
PreCreateProcess(PFLT_CALLBACK_DATA Data, PFLT_IO_PARAMETER_BLOCK pIopb);

BOOLEAN
PreSetInforProcess(PFLT_CALLBACK_DATA Data, PFLT_IO_PARAMETER_BLOCK pIopb);

BOOLEAN
IsWhitePid(ULONG Pid);

BOOLEAN
IsProtectFile(__in WCHAR* pFileName, __in ULONG FileNameLeng);

BOOLEAN
IsProtectReg(__in WCHAR* pRegName, __in ULONG FileNameLeng);

UNICODE_STRING*
GetRegFullPath(__in PVOID pObject);

NTSTATUS
CreateCDO(PDEVICE_OBJECT* DeviceObject, WCHAR* pNtDeviceName, WCHAR* pLinkName);

VOID
DeleteCDO(PDEVICE_OBJECT DeviceObject, WCHAR* pLinkName);

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH CtrlDeviceCreate;
__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH CtrlDeviceClose;
__drv_dispatchType(IRP_MJ_CLEANUP)
DRIVER_DISPATCH CtrlDeviceCleanup;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH CtrlDeviceControl;
#endif  //__MSPYKERN_H__

