/*++

Copyright (c) 1989-2002  Microsoft Corporation

Module Name:

    MiniSpy.c

Abstract:

    This is the main module for the MiniSpy mini-filter.

Environment:

    Kernel mode

--*/

#include "mspyKern.h"
#include <stdio.h>

//
//  Global variables
//

MINISPY_DATA MiniSpyData;
NTSTATUS StatusToBreakOn = 0;

PVOID gRegistrationHandle = NULL;
LARGE_INTEGER  gCmRegCookie;

DEVICE_OBJECT* CtrlDeviceObject=NULL;
ULONG gFileProtect = 0;
ULONG gProcessProtect = 0;
ULONG gRegProtect = 0;

PROCESS_WHITE_LIST gPidWhiteList;
PATH_LIST gFilePathList;
PATH_LIST gRegPathList;

//---------------------------------------------------------------------------
//  Function prototypes
//---------------------------------------------------------------------------
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    );


NTSTATUS
SpyMessage (
    __in PVOID ConnectionCookie,
    __in_bcount_opt(InputBufferSize) PVOID InputBuffer,
    __in ULONG InputBufferSize,
    __out_bcount_part_opt(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferSize,
    __out PULONG ReturnOutputBufferLength
    );

NTSTATUS
SpyConnect(
    __in PFLT_PORT ClientPort,
    __in PVOID ServerPortCookie,
    __in_bcount(SizeOfContext) PVOID ConnectionContext,
    __in ULONG SizeOfContext,
    __deref_out_opt PVOID *ConnectionCookie
    );

VOID
SpyDisconnect(
    __in_opt PVOID ConnectionCookie
    );

NTSTATUS
SpyEnlistInTransaction (
    __in PCFLT_RELATED_OBJECTS FltObjects
    );

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
PreCreateProcess(PFLT_CALLBACK_DATA Data,PFLT_IO_PARAMETER_BLOCK pIopb);

BOOLEAN
PreSetInforProcess(PFLT_CALLBACK_DATA Data,PFLT_IO_PARAMETER_BLOCK pIopb);

BOOLEAN 
IsWhitePid(ULONG Pid);

BOOLEAN 
IsProtectFile(__in WCHAR* pFileName, __in ULONG FileNameLeng);

BOOLEAN 
IsProtectReg(__in WCHAR* pRegName, __in ULONG FileNameLeng);

UNICODE_STRING* 
GetRegFullPath(__in PVOID pObject);

NTSTATUS 
CreateCDO(PDEVICE_OBJECT* DeviceObject,WCHAR* pNtDeviceName,WCHAR* pLinkName);

VOID 
DeleteCDO(PDEVICE_OBJECT DeviceObject,WCHAR* pLinkName);

__drv_dispatchType(IRP_MJ_CREATE) 
DRIVER_DISPATCH CtrlDeviceCreate;
__drv_dispatchType(IRP_MJ_CLOSE) 
DRIVER_DISPATCH CtrlDeviceClose;
__drv_dispatchType(IRP_MJ_CLEANUP) 
DRIVER_DISPATCH CtrlDeviceCleanup;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) 
DRIVER_DISPATCH CtrlDeviceControl;

//---------------------------------------------------------------------------
//  Assign text sections for each routine.
//---------------------------------------------------------------------------

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(PAGE, SpyFilterUnload)
    #pragma alloc_text(PAGE, SpyQueryTeardown)
    #pragma alloc_text(PAGE, SpyConnect)
    #pragma alloc_text(PAGE, SpyDisconnect)
    #pragma alloc_text(PAGE, SpyMessage)
#endif


#define SetFlagInterlocked(_ptrFlags,_flagToSet) \
    ((VOID)InterlockedOr(((volatile LONG *)(_ptrFlags)),_flagToSet))
    
//---------------------------------------------------------------------------
//                      ROUTINES
//---------------------------------------------------------------------------

NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This routine is called when a driver first loads.  Its purpose is to
    initialize global state and then register with FltMgr to start filtering.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.
    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Status of the operation.

--*/
{
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    NTSTATUS status = STATUS_SUCCESS;

    try {
        //
        // Initialize global data structures.
        //

        MiniSpyData.LogSequenceNumber = 0;
        MiniSpyData.MaxRecordsToAllocate = DEFAULT_MAX_RECORDS_TO_ALLOCATE;
        MiniSpyData.RecordsAllocated = 0;
        MiniSpyData.NameQueryMethod = DEFAULT_NAME_QUERY_METHOD;

        MiniSpyData.DriverObject = DriverObject;

        InitializeListHead( &MiniSpyData.OutputBufferList );
        KeInitializeSpinLock( &MiniSpyData.OutputBufferLock );

        ExInitializeNPagedLookasideList( &MiniSpyData.FreeBufferList,
                                         NULL,
                                         NULL,
                                         0,
                                         RECORD_SIZE,
                                         SPY_TAG,
                                         0 );

        SpyReadDriverParameters(RegistryPath);

		gCmRegCookie.QuadPart = 0;
		status = GlobalInitial();
		if (!NT_SUCCESS(status))
		{
			leave;
		}

        //
        //  Now that our global configuration is complete, register with FltMgr.
        //

        status = FltRegisterFilter( DriverObject,
                                    &FilterRegistration,
                                    &MiniSpyData.Filter );

        if (!NT_SUCCESS( status ))
		{
           leave;
        }


        status  = FltBuildDefaultSecurityDescriptor( &sd,FLT_PORT_ALL_ACCESS );
        if (!NT_SUCCESS( status )) 
		{
            leave;
        }

        RtlInitUnicodeString( &uniString, MINISPY_PORT_NAME );

        InitializeObjectAttributes( &oa,
                                    &uniString,
                                    OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                    NULL,
                                    sd );

        status = FltCreateCommunicationPort( MiniSpyData.Filter,
                                             &MiniSpyData.ServerPort,
                                             &oa,
                                             NULL,
                                             SpyConnect,
                                             SpyDisconnect,
                                             SpyMessage,
                                             1 );

        FltFreeSecurityDescriptor( sd );

        if (!NT_SUCCESS( status )) 
		{
            leave;
        }

        //
        //  We are now ready to start filtering
        //

        status = FltStartFiltering( MiniSpyData.Filter );
    } 
	finally 
	{
        if (!NT_SUCCESS( status ) ) 
		{

			GlobalUnInitial();

			if (NULL != MiniSpyData.ServerPort) 
			{
				FltCloseCommunicationPort( MiniSpyData.ServerPort );
			}

			if (NULL != MiniSpyData.Filter) 
			{
				FltUnregisterFilter( MiniSpyData.Filter );
			}

			ExDeleteNPagedLookasideList( &MiniSpyData.FreeBufferList );
        }
    }

    return status;
}

NTSTATUS
SpyConnect(
    __in PFLT_PORT ClientPort,
    __in PVOID ServerPortCookie,
    __in_bcount(SizeOfContext) PVOID ConnectionContext,
    __in ULONG SizeOfContext,
    __deref_out_opt PVOID *ConnectionCookie
    )
/*++

Routine Description

    This is called when user-mode connects to the server
    port - to establish a connection

Arguments

    ClientPort - This is the pointer to the client port that
        will be used to send messages from the filter.
    ServerPortCookie - unused
    ConnectionContext - unused
    SizeofContext   - unused
    ConnectionCookie - unused

Return Value

    STATUS_SUCCESS - to accept the connection
--*/
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext);
    UNREFERENCED_PARAMETER( ConnectionCookie );

    ASSERT( MiniSpyData.ClientPort == NULL );
    MiniSpyData.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}


VOID
SpyDisconnect(
    __in_opt PVOID ConnectionCookie
   )
/*++

Routine Description

    This is called when the connection is torn-down. We use it to close our handle to the connection

Arguments

    ConnectionCookie - unused

Return value

    None
--*/
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ConnectionCookie );

    //
    //  Close our handle
    //

    FltCloseClientPort( MiniSpyData.Filter, &MiniSpyData.ClientPort );
}

NTSTATUS
SpyFilterUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is called when a request has been made to unload the filter.  Unload
    requests from the Operation System (ex: "sc stop minispy" can not be
    failed.  Other unload requests may be failed.

    You can disallow OS unload request by setting the
    FLTREGFL_DO_NOT_SUPPORT_SERVICE_STOP flag in the FLT_REGISTARTION
    structure.

Arguments:

    Flags - Flags pertinent to this operation

Return Value:

    Always success

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    //
    //  Close the server port. This will stop new connections.
    //

	GlobalUnInitial();

    FltCloseCommunicationPort( MiniSpyData.ServerPort );

    FltUnregisterFilter( MiniSpyData.Filter );

    SpyEmptyOutputBufferList();
    ExDeleteNPagedLookasideList( &MiniSpyData.FreeBufferList );

    return STATUS_SUCCESS;
}


NTSTATUS
SpyQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This allows our filter to be manually detached from a volume.

Arguments:

    FltObjects - Contains pointer to relevant objects for this operation.
        Note that the FileObject field will always be NULL.

    Flags - Flags pertinent to this operation

Return Value:

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    PAGED_CODE();
    return STATUS_SUCCESS;
}


NTSTATUS
SpyMessage (
    __in PVOID ConnectionCookie,
    __in_bcount_opt(InputBufferSize) PVOID InputBuffer,
    __in ULONG InputBufferSize,
    __out_bcount_part_opt(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferSize,
    __out PULONG ReturnOutputBufferLength
    )
/*++

Routine Description:

    This is called whenever a user mode application wishes to communicate
    with this minifilter.

Arguments:

    ConnectionCookie - unused

    OperationCode - An identifier describing what type of message this
        is.  These codes are defined by the MiniFilter.
    InputBuffer - A buffer containing input data, can be NULL if there
        is no input data.
    InputBufferSize - The size in bytes of the InputBuffer.
    OutputBuffer - A buffer provided by the application that originated
        the communication in which to store data to be returned to this
        application.
    OutputBufferSize - The size in bytes of the OutputBuffer.
    ReturnOutputBufferSize - The size in bytes of meaningful data
        returned in the OutputBuffer.

Return Value:

    Returns the status of processing the message.

--*/
{
    MINISPY_COMMAND command;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ConnectionCookie );

    //
    //                      **** PLEASE READ ****
    //
    //  The INPUT and OUTPUT buffers are raw user mode addresses.  The filter
    //  manager has already done a ProbedForRead (on InputBuffer) and
    //  ProbedForWrite (on OutputBuffer) which guarentees they are valid
    //  addresses based on the access (user mode vs. kernel mode).  The
    //  minifilter does not need to do their own probe.
    //
    //  The filter manager is NOT doing any alignment checking on the pointers.
    //  The minifilter must do this themselves if they care (see below).
    //
    //  The minifilter MUST continue to use a try/except around any access to
    //  these buffers.
    //

    if ((InputBuffer != NULL) &&
        (InputBufferSize >= (FIELD_OFFSET(COMMAND_MESSAGE,Command) +
                             sizeof(MINISPY_COMMAND)))) {

        try  {

            //
            //  Probe and capture input message: the message is raw user mode
            //  buffer, so need to protect with exception handler
            //

            command = ((PCOMMAND_MESSAGE) InputBuffer)->Command;

        } except( EXCEPTION_EXECUTE_HANDLER ) {

            return GetExceptionCode();
        }

        switch (command) {

            case GetMiniSpyLog:

                //
                //  Return as many log records as can fit into the OutputBuffer
                //

                if ((OutputBuffer == NULL) || (OutputBufferSize == 0)) {

                    status = STATUS_INVALID_PARAMETER;
                    break;
                }

                //
                //  We want to validate that the given buffer is POINTER
                //  aligned.  But if this is a 64bit system and we want to
                //  support 32bit applications we need to be careful with how
                //  we do the check.  Note that the way SpyGetLog is written
                //  it actually does not care about alignment but we are
                //  demonstrating how to do this type of check.
                //

#if defined(_WIN64)
                if (IoIs32bitProcess( NULL )) {

                    //
                    //  Validate alignment for the 32bit process on a 64bit
                    //  system
                    //

                    if (!IS_ALIGNED(OutputBuffer,sizeof(ULONG))) {

                        status = STATUS_DATATYPE_MISALIGNMENT;
                        break;
                    }

                } else {
#endif

                    if (!IS_ALIGNED(OutputBuffer,sizeof(PVOID))) {

                        status = STATUS_DATATYPE_MISALIGNMENT;
                        break;
                    }

#if defined(_WIN64)
                }
#endif
                //
                //  Get the log record.
                //

                status = SpyGetLog( OutputBuffer,
                                    OutputBufferSize,
                                    ReturnOutputBufferLength );
                break;


            case GetMiniSpyVersion:

                //
                //  Return version of the MiniSpy filter driver.  Verify
                //  we have a valid user buffer including valid
                //  alignment
                //

                if ((OutputBufferSize < sizeof( MINISPYVER )) ||
                    (OutputBuffer == NULL)) {

                    status = STATUS_INVALID_PARAMETER;
                    break;
                }

                //
                //  Validate Buffer alignment.  If a minifilter cares about
                //  the alignment value of the buffer pointer they must do
                //  this check themselves.  Note that a try/except will not
                //  capture alignment faults.
                //

                if (!IS_ALIGNED(OutputBuffer,sizeof(ULONG))) {

                    status = STATUS_DATATYPE_MISALIGNMENT;
                    break;
                }

                //
                //  Protect access to raw user-mode output buffer with an
                //  exception handler
                //

                try {

                    ((PMINISPYVER)OutputBuffer)->Major = MINISPY_MAJ_VERSION;
                    ((PMINISPYVER)OutputBuffer)->Minor = MINISPY_MIN_VERSION;

                } except( EXCEPTION_EXECUTE_HANDLER ) {

                      return GetExceptionCode();
                }

                *ReturnOutputBufferLength = sizeof( MINISPYVER );
                status = STATUS_SUCCESS;
                break;

            default:
                status = STATUS_INVALID_PARAMETER;
                break;
        }

    } else {

        status = STATUS_INVALID_PARAMETER;
    }

    return status;
}


//---------------------------------------------------------------------------
//              Operation filtering routines
//---------------------------------------------------------------------------


FLT_PREOP_CALLBACK_STATUS
SpyPreOperationCallback (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine receives ALL pre-operation callbacks for this filter.  It then
    tries to log information about the given operation.  If we are able
    to log information then we will call our post-operation callback  routine.

    NOTE:  This routine must be NON-PAGED because it can be called on the
           paging path.

Arguments:

    Data - Contains information about the given operation.

    FltObjects - Contains pointers to the various objects that are pertinent
        to this operation.

    CompletionContext - This receives the address of our log buffer for this
        operation.  Our completion routine then receives this buffer address.

Return Value:

    Identifies how processing should continue for this operation

--*/
{
	NTSTATUS status;
	BOOLEAN  bForbid = FALSE;
	PFLT_IO_PARAMETER_BLOCK pIopb = Data->Iopb;

	UNREFERENCED_PARAMETER( CompletionContext );

	if (Data->RequestorMode == KernelMode)
	{
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}

	if (gFileProtect)
	{
		if (pIopb->MajorFunction == IRP_MJ_CREATE)
		{
			bForbid = PreCreateProcess(Data,pIopb);
		}
		else if(pIopb->MajorFunction == IRP_MJ_SET_INFORMATION)
		{
			bForbid = PreSetInforProcess(Data,pIopb);
		}
	}

	if(bForbid)
	{
		KdPrint(("SpyPreOperationCallback: forbid pre oper\n"));
		Data->IoStatus.Information = 0;
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		return FLT_PREOP_COMPLETE;
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
SpyPostOperationCallback (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine receives ALL post-operation callbacks.  This will take
    the log record passed in the context parameter and update it with
    the completion information.  It will then insert it on a list to be
    sent to the usermode component.

    NOTE:  This routine must be NON-PAGED because it can be called at DPC level

Arguments:

    Data - Contains information about the given operation.

    FltObjects - Contains pointers to the various objects that are pertinent
        to this operation.

    CompletionContext - Pointer to the RECORD_LIST structure in which we
        store the information we are logging.  This was passed from the
        pre-operation callback

    Flags - Contains information as to why this routine was called.

Return Value:

    Identifies how processing should continue for this operation

--*/
{
	UNREFERENCED_PARAMETER( Data );
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( CompletionContext );
	UNREFERENCED_PARAMETER( Flags );

    return FLT_POSTOP_FINISHED_PROCESSING;
}

UNICODE_STRING*  AllocateAndGetFileName(PFLT_CALLBACK_DATA Data,NTSTATUS* pStatus)
{
	UNICODE_STRING* pUnicodeName = NULL;
	PFLT_FILE_NAME_INFORMATION FileNameInformation = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	status = FltGetFileNameInformation( Data,
		FLT_FILE_NAME_NORMALIZED | 
		FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
		&FileNameInformation);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("AllocateAndGetFileName: FltGetFileNameInformation(FLT_FILE_NAME_NORMALIZED) faild,status=0x%x\n",status));
		status = FltGetFileNameInformation( Data,
			FLT_FILE_NAME_OPENED |
			FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
			&FileNameInformation );
		if (!NT_SUCCESS(status))
		{
			KdPrint(("AllocateAndGetFileName: FltGetFileNameInformation(FLT_FILE_NAME_OPENED) faild,status=0x%x\n",status));
		}
	}

	if (NT_SUCCESS(status))
	{
		UNICODE_STRING DosName = {0};
		status = FltParseFileNameInformation(FileNameInformation);
		if (NT_SUCCESS(status))
		{
			if (FileNameInformation->Name.Length )
			{
				USHORT NameLeng = FileNameInformation->Name.Length+sizeof(UNICODE_STRING);
				//ASSERT(!KeAreAllApcsDisabled());
				//status = IoVolumeDeviceToDosName((PVOID)(FileNameInformation->Volume.Buffer),&DosName);
				//if (NT_SUCCESS(status))
				//{
					pUnicodeName = (UNICODE_STRING*)ExAllocatePoolWithTag(NonPagedPool,NameLeng,'EMAN');
					if (pUnicodeName)
					{
						RtlZeroMemory(pUnicodeName,NameLeng);
						pUnicodeName->Buffer = (WCHAR*)(pUnicodeName+1);
						pUnicodeName->Length = 0;
						pUnicodeName->MaximumLength = NameLeng-sizeof(UNICODE_STRING);

						//RtlAppendUnicodeStringToString(pUnicodeName,&DosName);
						//RtlAppendUnicodeStringToString(pUnicodeName,&FileNameInformation->ParentDir);
						//RtlAppendUnicodeStringToString(pUnicodeName,&FileNameInformation->Name);
						RtlCopyUnicodeString(pUnicodeName, &FileNameInformation->Name);
						KdPrint(("AllocateAndGetFileName: %wZ\n",pUnicodeName));
					}
					else
					{
						KdPrint(("AllocateAndGetFileName: ExAllocatePoolWithTag faild,status=0x%x\n", status));
					}
				//}
				//else
				//{
				//	KdPrint(("AllocateAndGetFileName: IoVolumeDeviceToDosName faild,status=0x%x\n",status));
				//}
			}
			else
			{
				KdPrint(("AllocateAndGetFileName: Volume.Length=%d,Name.Length=%d,ParentDir.Length=%d\n",
					FileNameInformation->Volume.Length,FileNameInformation->Name.Length,FileNameInformation->ParentDir.Length));
			}
		}
	}

	if (FileNameInformation)
	{
		FltReleaseFileNameInformation(FileNameInformation);
	}

	*pStatus = status;
	return pUnicodeName;
}

NTSTATUS GlobalInitial()
{
	NTSTATUS status = STATUS_SUCCESS;
	RtlZeroMemory(&gPidWhiteList, sizeof(PROCESS_WHITE_LIST));
	RtlZeroMemory(&gFilePathList,sizeof(PATH_LIST));
	RtlZeroMemory(&gRegPathList,sizeof(PATH_LIST));

	status = CreateCDO(&CtrlDeviceObject, CTRLNTDEVICE_STRING,CTRLLINKNAME_STRING);
	if (NT_SUCCESS(status))
	{
		status = InitialCallBack();
	}

	return status;
}

VOID GlobalUnInitial()
{
	DeleteCDO(CtrlDeviceObject,CTRLNTDEVICE_STRING);
	UnInitialCallBack();
}

NTSTATUS InitialCallBack()
{
	NTSTATUS status = STATUS_SUCCESS;

	status = CmRegisterCallback(RegistryCallback,NULL,&gCmRegCookie);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("InitialCallBack: CmRegisterCallback faild status=0x%x\n", status));
		return status;
	}

	status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("InitialCallBack: PsSetLoadImageNotifyRoutine faild status=0x%x\n", status));
		return status;
	}

	return status;
}

NTSTATUS UnInitialCallBack()
{
	NTSTATUS status = STATUS_SUCCESS;

	status = CmUnRegisterCallback(gCmRegCookie);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("UnInitialCallBack: CmUnRegisterCallback faild status=0x%x\n", status));
	}

	status = PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("UnInitialCallBack: PsRemoveLoadImageNotifyRoutine faild status=0x%x\n", status));
	}

	return status;
}

UNICODE_STRING* GetRegFullPath(__in PVOID pObject)
{
	UNICODE_STRING* pRegPath = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	POBJECT_NAME_INFORMATION pObjectNameInfor = NULL;
	ULONG Length = sizeof(UNICODE_STRING)+1024;

	if (pObject == NULL)
	{
		return NULL;
	}

	pObjectNameInfor = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,Length,'NGER');
	if (pObjectNameInfor)
	{ 
		ULONG RetLeng = 0;
		RtlZeroMemory(pObjectNameInfor,Length);
		status = ObQueryNameString(pObject,pObjectNameInfor,Length,&RetLeng);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(pObjectNameInfor);
			pObjectNameInfor = NULL;
			pObjectNameInfor = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,RetLeng,'NGER');
			RtlZeroMemory(pObjectNameInfor,RetLeng);
			status = ObQueryNameString(pObject,pObjectNameInfor,RetLeng,&RetLeng);
		}

		if (status == STATUS_SUCCESS)
		{
			return (&pObjectNameInfor->Name);
		}
		else
		{
			ExFreePool(pObjectNameInfor);
			pObjectNameInfor = NULL;
		}
	}

	return NULL;
}

NTSTATUS
RegistryCallback(
	__in PVOID  CallbackContext,
	__in_opt PVOID  Argument1,
	__in_opt PVOID  Argument2
	)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING* pRegName = NULL;
	REG_NOTIFY_CLASS RegNotifyClass = (REG_NOTIFY_CLASS)Argument1;

	ULONG CurrPid = HandleToUlong(PsGetCurrentProcessId());
	if (IsWhitePid(CurrPid) ||
		!gRegProtect)
	{
		return status;
	}

	switch(RegNotifyClass)
	{
	case RegNtPreDeleteKey:
		{
			REG_DELETE_KEY_INFORMATION* pRegDeleteKeyInfor = (REG_DELETE_KEY_INFORMATION*)Argument2;
			if ( pRegDeleteKeyInfor && 
				pRegDeleteKeyInfor->Object && 
				(pRegName = GetRegFullPath(pRegDeleteKeyInfor->Object)))
			{
				if (IsProtectReg(pRegName->Buffer,pRegName->Length))
				{
					KdPrint(("RegistryCallback: RegNtPreDeleteKey forbid(%wZ)\n",pRegName));
					status = STATUS_ACCESS_DENIED;
				}
				KdPrint(("RegistryCallback: RegNtPreDeleteKey (%wZ)\n",pRegName));
			}
			break;
		}
	case  RegNtDeleteValueKey:
		{
			PREG_DELETE_VALUE_KEY_INFORMATION pDeleteValueKeyInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
			if ( pDeleteValueKeyInfo && 
				pDeleteValueKeyInfo->Object &&
				(pRegName = GetRegFullPath(pDeleteValueKeyInfo->Object)))
			{
				
				if (IsProtectReg(pRegName->Buffer, pRegName->Length))
				{
					KdPrint(("RegistryCallback: RegNtDeleteValueKey forbid(%wZ)\n",pRegName));
					status = STATUS_ACCESS_DENIED;
				}
				KdPrint(("RegistryCallback: RegNtDeleteValueKey (%wZ)\n",pRegName));
			}
			break;
		}
	case RegNtSetValueKey:
		{
			PREG_SET_VALUE_KEY_INFORMATION pSetValueKeyInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
			if ( pSetValueKeyInfo && 
				pSetValueKeyInfo->Object &&
				(pRegName = GetRegFullPath(pSetValueKeyInfo->Object)))
			{
				
				if (IsProtectReg(pRegName->Buffer, pRegName->Length))
				{
					KdPrint(("RegistryCallback: RegNtSetValueKey forbid(%wZ)\n",pRegName));
					status = STATUS_ACCESS_DENIED;
				}
				KdPrint(("RegistryCallback: RegNtSetValueKey (%wZ)\n",pRegName));
			}
			break;
		}
	case RegNtRenameKey:
		{
			PREG_RENAME_KEY_INFORMATION pRenameKeyInfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
			if ( pRenameKeyInfo && 
				pRenameKeyInfo->Object &&
				(pRegName = GetRegFullPath(pRenameKeyInfo->Object)))
			{
				
				if (IsProtectReg(pRegName->Buffer, pRegName->Length))
				{
					KdPrint(("RegistryCallback: RegNtRenameKey forbid(%wZ)\n",pRegName));
					status = STATUS_ACCESS_DENIED;
				}
				KdPrint(("RegistryCallback: RegNtRenameKey (%wZ)\n",pRegName));
			}
			break;
		}
	default:
		break;
	}

	if (pRegName)
	{
		ExFreePool(pRegName);
	}

	return status;
}

VOID LoadImageNotify(
	__in PUNICODE_STRING FullImageName,
	__in HANDLE ProcessId,                // pid into which image is being mapped
	__in PIMAGE_INFO ImageInfo)
{
	do 
	{
		if (0==ProcessId)
		{
			ULONG CurrPid = HandleToUlong(PsGetCurrentProcessId());
			KdPrint(("LoadImageNotify:    \n"));
			if (IsWhitePid(CurrPid))
			{
				break;
			}
				
			if(FullImageName!=NULL && MmIsAddressValid(FullImageName))
			{
				KdPrint(("LoadImageNotify: Pid(%d),%wZ\n",CurrPid,FullImageName));
			}
		}
	}while(FALSE);
}

static int __inline Lower(int c)
{
	if ((c >= L'A') && (c <= L'Z'))
	{
		return(c + (L'a' - L'A'));
	}
	else
	{
		return(c);
	}
}

BOOLEAN RtlStringMatch(WCHAR * pat, WCHAR * str, ULONG Leng)
{
	BOOLEAN bRet = TRUE;
	register WCHAR * s;
	register WCHAR * p;

	for (s = str, p = pat; Leng > 0; ++s, ++p, Leng--)
	{
		if (Lower(*s) != Lower(*p))
		{
			bRet = FALSE;
			break;
		}
	}

	return bRet;
}

//
BOOLEAN IsWhitePid(ULONG Pid)
{
	BOOLEAN bRet = FALSE;
	ULONG i = 0;
	for (;i<gPidWhiteList.WhiteProcessNum;i++)
	{
		if (Pid==gPidWhiteList.PidArray[i])
		{
			bRet = TRUE;
			break;
		}
	}

	return bRet;
}

//FileNameLeng, in bytes
BOOLEAN IsProtectFile(__in WCHAR* pFileName,__in ULONG FileNameLeng)
{
	BOOLEAN bRet = FALSE;
	ULONG i = 0;
	for (;i<gFilePathList.PathNum;i++)
	{
		if (FileNameLeng >= gFilePathList.PathArray[i].PathLeng &&
			RtlStringMatch(pFileName,gFilePathList.PathArray[i].Path, gFilePathList.PathArray[i].PathLeng/2))
		{
			bRet = TRUE;
			break;
		}
	}
	return bRet;
}

//
BOOLEAN IsProtectReg(__in WCHAR* pRegName, __in ULONG FileNameLeng)
{
	BOOLEAN bRet = FALSE;
	ULONG i = 0;
	for (; i < gRegPathList.PathNum; i++)
	{
		if (FileNameLeng >= gRegPathList.PathArray[i].PathLeng &&
			RtlStringMatch(pRegName, gRegPathList.PathArray[i].Path, gRegPathList.PathArray[i].PathLeng/2))
		{
			bRet = TRUE;
			break;
		}
	}
	return bRet;
}

//
BOOLEAN PreCreateProcess(PFLT_CALLBACK_DATA Data,PFLT_IO_PARAMETER_BLOCK pIopb)
{
	BOOLEAN bRet = FALSE;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG CreateOptions = 0;
	ULONG DispositionOptions = 0;
	ULONG DesireAccess = 0;
	ULONG ModifyDesireAccess = DELETE|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA|FILE_APPEND_DATA;
	PUNICODE_STRING pUnicodeName = NULL;
	ULONG CurrPid = HandleToUlong(PsGetCurrentProcessId());

	do 
	{
		if (IsWhitePid(CurrPid))
		{
			break;
		}

		DesireAccess = pIopb->Parameters.Create.SecurityContext->DesiredAccess;
		CreateOptions = pIopb->Parameters.Create.Options & 0x00FFFFFF;
		DispositionOptions = (pIopb->Parameters.Create.Options) >> 24;

		if ((DesireAccess&ModifyDesireAccess) ||
			(DispositionOptions&FILE_CREATE) ||
			(CreateOptions&FILE_DELETE_ON_CLOSE))
		{
			pUnicodeName = AllocateAndGetFileName(Data,&status);
			if (NULL == pUnicodeName)
			{
				break;
			}

			if(bRet= IsProtectFile(pUnicodeName->Buffer,pUnicodeName->Length))
			{
				break;
			}
		}
	} while (FALSE);

	if (pUnicodeName)
	{
		ExFreePool(pUnicodeName);
	}

	return bRet;
}

//
BOOLEAN PreSetInforProcess(PFLT_CALLBACK_DATA Data,PFLT_IO_PARAMETER_BLOCK pIopb)
{
	BOOLEAN bRet = FALSE;
	USHORT FileInforClass = pIopb->Parameters.SetFileInformation.FileInformationClass;
	if (FileInforClass == FileRenameInformation ||
		FileInforClass == FileDispositionInformation)
	{
		NTSTATUS status;
		PUNICODE_STRING pUnicodeName = NULL;
		ULONG CurrPid = HandleToUlong(PsGetCurrentProcessId());

		do
		{
			if (IsWhitePid(CurrPid))
			{
				break;
			}

			pUnicodeName = AllocateAndGetFileName(Data, &status);
			if (NULL == pUnicodeName)
			{
				break;
			}

			if (bRet = IsProtectFile(pUnicodeName->Buffer,pUnicodeName->Length))
			{
				break;
			}

			if (FileInforClass== FileRenameInformation)
			{
				FILE_RENAME_INFORMATION* lpRenameInfor = (FILE_RENAME_INFORMATION*)pIopb->Parameters.SetFileInformation.InfoBuffer;
				if (lpRenameInfor && 
					lpRenameInfor->FileName && 
					lpRenameInfor->FileNameLength)
				{
					KdPrint(("PreSetInforProcess: Rename %S\n",lpRenameInfor->FileName));
					if (bRet = IsProtectFile(lpRenameInfor->FileName, lpRenameInfor->FileNameLength))
					{
						break;
					}
				}
			}

		} while (FALSE);

		if (pUnicodeName)
		{
			ExFreePool(pUnicodeName);
		}
	}

	return bRet;
}

//
NTSTATUS CreateCDO(PDEVICE_OBJECT* DeviceObject,WCHAR* pNtDeviceName,WCHAR* pLinkName)
{
	NTSTATUS Status;
	UNICODE_STRING NtDeviceName;
	UNICODE_STRING DosDevicesLinkName;

	RtlInitUnicodeString(&NtDeviceName,pNtDeviceName);
	RtlInitUnicodeString(&DosDevicesLinkName,pLinkName);

	do 
	{
		Status = IoCreateDevice (                    
			MiniSpyData.DriverObject,                 // pointer to driver object
			0,                            // device extension size
			&NtDeviceName,                // device name
			FILE_DEVICE_UNKNOWN,          // device type
			0,                            // device characteristics
			FALSE,                        // not exclusive
			DeviceObject);                     // returned device object pointer

		if (NT_SUCCESS(Status))
		{
			Status = IoCreateSymbolicLink (&DosDevicesLinkName, &NtDeviceName);
			if (!NT_SUCCESS(Status))
			{
				IoDeleteDevice(*DeviceObject);
				break;
			}

			MiniSpyData.DriverObject->MajorFunction[IRP_MJ_CREATE]         = CtrlDeviceCreate;
			MiniSpyData.DriverObject->MajorFunction[IRP_MJ_CLOSE]          = CtrlDeviceClose;
			MiniSpyData.DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = CtrlDeviceCleanup;
			MiniSpyData.DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CtrlDeviceControl;
		}
	} while (FALSE);

	return Status;
}

VOID DeleteCDO(PDEVICE_OBJECT DeviceObject,WCHAR* pLinkName)
{
	UNICODE_STRING DosDevicesLinkName;
	if (DeviceObject)
	{
		RtlInitUnicodeString(&DosDevicesLinkName,pLinkName);
		IoDeleteSymbolicLink(&DosDevicesLinkName);
		IoDeleteDevice(DeviceObject);
	}
}

//
NTSTATUS
CtrlDeviceCreate (
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp
	)
{
	UNREFERENCED_PARAMETER (DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest (Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
CtrlDeviceClose (
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp
	)
{
	UNREFERENCED_PARAMETER (DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest (Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
CtrlDeviceCleanup (
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp
	)
{
	UNREFERENCED_PARAMETER (DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest (Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
CtrlDeviceControl (
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp
	)
{
	PIO_STACK_LOCATION IrpStack;
	ULONG Ioctl;
	NTSTATUS Status;
	ULONG InPutBufferLength;

	Status = STATUS_SUCCESS;

	IrpStack = IoGetCurrentIrpStackLocation (Irp);
	Ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;
	InPutBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

	DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "CtrlDeviceControl: entering - ioctl code 0x%x\n", Ioctl);

	switch (Ioctl)
	{
	case IOCTL_SET_PROCESS_PROTECT_ONOFF:

		DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "CtrlDeviceControl: IOCTL_SET_PROCESS_PROTECT_ONOFF\n");
		if (InPutBufferLength<sizeof(ULONG)||Irp->AssociatedIrp.SystemBuffer==NULL)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		gProcessProtect = *((ULONG*)Irp->AssociatedIrp.SystemBuffer);
		break;

	case IOCTL_SET_FILE_PROTECT_ONOFF:

		DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "CtrlDeviceControl: IOCTL_SET_FILE_PROTECT_ONOFF\n");
		if (InPutBufferLength<sizeof(ULONG)||Irp->AssociatedIrp.SystemBuffer==NULL)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		gFileProtect = *((ULONG*)Irp->AssociatedIrp.SystemBuffer);
		break;

	case IOCTL_SET_REG_PROTECT_ONOFF:

		DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "CtrlDeviceControl: IOCTL_SET_REG_PROTECT_ONOFF\n");
		if (InPutBufferLength<sizeof(ULONG)||Irp->AssociatedIrp.SystemBuffer==NULL)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		gRegProtect = *((ULONG*)Irp->AssociatedIrp.SystemBuffer);
		break;

	case IOCTL_SET_PROTECT_FILE_PATH:
		{
			PATH_LIST* pFileList = NULL;
			DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "CtrlDeviceControl: IOCTL_SET_PROTECT_FILE_PATH\n");
			if (InPutBufferLength<sizeof(PATH_LIST)||Irp->AssociatedIrp.SystemBuffer==NULL)
			{
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			pFileList = (PATH_LIST*)Irp->AssociatedIrp.SystemBuffer;
			if (pFileList->PathNum==0 || pFileList->PathNum >MAX_FILE_NUM)
			{
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			RtlCopyMemory(&gFilePathList,pFileList,sizeof(PATH_LIST));
			break;
		}


	case IOCTL_SET_PROTECT_REG_PATH:
		{
			PATH_LIST* pRegList = NULL;
			DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "CtrlDeviceControl: IOCTL_SET_PROTECT_REG_PATH\n");
			if (InPutBufferLength<sizeof(PATH_LIST)||Irp->AssociatedIrp.SystemBuffer==NULL)
			{
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			pRegList = (PATH_LIST*)Irp->AssociatedIrp.SystemBuffer;
			if (pRegList->PathNum==0 || pRegList->PathNum >MAX_FILE_NUM)
			{
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			RtlCopyMemory(&gRegPathList,pRegList,sizeof(PATH_LIST));
			break;
		}

	case IOCTL_SET_TRUST_PID:
		{
			PROCESS_WHITE_LIST* pPidList = NULL;
			DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "CtrlDeviceControl: IOCTL_SET_TRUST_PID\n");
			if (InPutBufferLength<sizeof(PROCESS_WHITE_LIST)||Irp->AssociatedIrp.SystemBuffer==NULL)
			{
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			pPidList = (PROCESS_WHITE_LIST*)Irp->AssociatedIrp.SystemBuffer;
			if (pPidList->WhiteProcessNum==0 || pPidList->WhiteProcessNum >MAX_WHITE_PROCESS_NUM)
			{
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			RtlCopyMemory(&gPidWhiteList,pPidList,sizeof(PROCESS_WHITE_LIST));
			break;
		}

	default:
		DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CtrlDeviceControl: unrecognized ioctl code 0x%x\n", Ioctl);
		break;
	}

	//
	// Complete the irp and return.
	//

	Irp->IoStatus.Status = Status;
	IoCompleteRequest (Irp, IO_NO_INCREMENT);

	DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "CtrlDeviceControl leaving - status 0x%x\n", Status);
	return Status;
}

//void InitObjectAttributes(POBJECT_ATTRIBUTES ObjAttr, PUNICODE_STRING UniStr, LPWSTR Name)
//// initialization of some structures for file access
//{
//	RtlInitUnicodeString(UniStr, Name);
//	ObjAttr->Length = sizeof(OBJECT_ATTRIBUTES);
//	ObjAttr->RootDirectory = 0;
//	ObjAttr->ObjectName = UniStr;
//	ObjAttr->Attributes = 0x240;  // OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE
//	ObjAttr->SecurityDescriptor = NULL;
//	ObjAttr->SecurityQualityOfService = NULL;
//}
////void DeviceNameToDosName(WCHAR *Buf, ULONG BufLen)
//// "\Device\HarddiskVolume1\Some Folder\Hook.dll" -> "C:\Some Folder\Some.dll"
//{
//	OBJECT_ATTRIBUTES oa;
//	UNICODE_STRING    us;
//	IO_STATUS_BLOCK   isb;
//	HANDLE            fh;
//	PFILE_OBJECT      fo;
//
//	InitObjectAttributes(&oa, &us, Buf);
//	if (NT_SUCCESS(ZwCreateFile(&fh, FILE_READ_DATA, &oa, &isb, NULL, 0, FILE_SHARE_READ, FILE_OPEN, 0, NULL, 0)))
//	{
//		if (NT_SUCCESS(ObReferenceObjectByHandle(fh, FILE_ALL_ACCESS, 0, KernelMode, &fo, 0)))
//		{
//			POBJECT_NAME_INFORMATION dosstr;
//			if (NT_SUCCESS(IoQueryFileDosDeviceName(fo, &dosstr)))
//			{
//				if ((ULONG)dosstr->Name.Length >= BufLen * 2)
//					dosstr->Name.Length = (USHORT)BufLen * 2 - 2;
//				wcsncpy(Buf, dosstr->Name.Buffer, dosstr->Name.Length / 2);
//				Buf[dosstr->Name.Length / 2] = 0;
//
//				ExFreePool(dosstr);
//			}
//			ObDereferenceObject(fo);
//		}
//		ZwClose(fh);
//	}
//}

NTSTATUS
PtInstanceSetup(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType,
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	return STATUS_SUCCESS;
}

VOID
PtInstanceTeardownStart(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();
}


VOID
PtInstanceTeardownComplete(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();
}