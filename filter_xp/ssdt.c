#include "mspyKern.h"

//used for SSDT hook
PMDL  g_pmdlSystemCall;
PVOID *MappedSystemCallTable;

typedef NTSTATUS (*PZwTerminateProcess)(
	IN HANDLE ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus
	);
typedef NTSTATUS (*PZwOpenProcess)(
	IN PHANDLE ProcessHandle,
	ACCESS_MASK MASK,
	POBJECT_ATTRIBUTES attr,
	PCLIENT_ID cid1
	);

//保存原函数地址的变量
PZwTerminateProcess         Old_ZwTerminateProcess = NULL;
PZwOpenProcess				Old_ZwOpenProcess = NULL;

typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

NTSYSAPI  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

//
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]
//
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
//
#define HOOK_SYSCALL(_Function, _Hook, _Orig )       \
	_Orig = (PVOID) InterlockedExchange( (PLONG) \
	&MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)
//
#define UNHOOK_SYSCALL(_Func, _Hook, _Orig )  \
	InterlockedExchange((PLONG)           \
	&MappedSystemCallTable[SYSCALL_INDEX(_Func)], (LONG) _Hook)

NTSTATUS
NTAPI
NewZwTerminateProcess(
	IN HANDLE ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus
)
{
	ULONG CurrPid = HandleToUlong(PsGetCurrentProcessId());
	PEPROCESS process_to_kill;
	NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, GENERIC_READ, *PsProcessType, KernelMode, &process_to_kill, 0);
	if (NT_SUCCESS(status))
	{
		ULONG TargetPid = HandleToUlong(PsGetProcessId(process_to_kill));
		ObDereferenceObject(process_to_kill);
		if ((TargetPid != CurrPid) &&
			IsWhitePid(TargetPid) && 
			!IsWhitePid(CurrPid))
		{
			return STATUS_ACCESS_DENIED;
		}
	}
	return  Old_ZwTerminateProcess(ProcessHandle, ExitStatus);
}
NTSTATUS
NTAPI
NewZwOpenProcess(
	IN PHANDLE ProcessHandle,
	ACCESS_MASK MASK,
	POBJECT_ATTRIBUTES attr,
	PCLIENT_ID cid1
)
{
	//*(ULONG *)cid1
	ULONG dwMask = (PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE);
	ULONG CurrPid = HandleToUlong(PsGetCurrentProcessId());
	if (gProcessProtect &&
		NULL != cid1 &&
		(CurrPid != HandleToUlong(cid1)))
	{
		if (IsWhitePid(HandleToUlong(cid1))&&
			!IsWhitePid(CurrPid)&&
			(MASK&dwMask))
		{
			return STATUS_ACCESS_DENIED;
		}
	}

	return Old_ZwOpenProcess(ProcessHandle, MASK, attr, cid1);
}

void HookSSDTTable()
{
	KdPrint(("[SelfProtect]HookSSDTTable: Enter.......\n"));

	g_pmdlSystemCall = MmCreateMdl(NULL, KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices * 4);

	if (!g_pmdlSystemCall)
	{
		DbgPrint("[SelfProtect]HookSSDTTable: MmCreateMdl False!!!!\n");
		return;
	}
	MmBuildMdlForNonPagedPool(g_pmdlSystemCall);
	g_pmdlSystemCall->MdlFlags = g_pmdlSystemCall->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;

	MappedSystemCallTable = MmMapLockedPages(g_pmdlSystemCall, KernelMode);

	HOOK_SYSCALL(ZwTerminateProcess, NewZwTerminateProcess, Old_ZwTerminateProcess);
	HOOK_SYSCALL(ZwOpenProcess, NewZwOpenProcess, Old_ZwOpenProcess);

	KdPrint(("[SelfProtect]HookSSDTTable: Leaving.......\n"));
}

void UnHookSSDTTable()
{
	KdPrint(("[IMSProtect]UnHookSSDTTable: Enter.......\n"));

	if (Old_ZwTerminateProcess&&Old_ZwOpenProcess)
	{
		UNHOOK_SYSCALL(ZwTerminateProcess, Old_ZwTerminateProcess, NewZwTerminateProcess);
		UNHOOK_SYSCALL(ZwOpenProcess, Old_ZwOpenProcess, NewZwOpenProcess);
	}

	Old_ZwTerminateProcess = NULL;
	Old_ZwOpenProcess = NULL;

	if (g_pmdlSystemCall)
	{
		MmUnmapLockedPages(MappedSystemCallTable, g_pmdlSystemCall);
		IoFreeMdl(g_pmdlSystemCall);
	}

	KdPrint(("[SelfProtect]UnHookSSDTTable: Leaving.......\n"));
}