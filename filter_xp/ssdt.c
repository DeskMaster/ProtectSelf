#include "mspyKern.h"

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

typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

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

NTSYSAPI  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

//used for SSDT hook
PMDL  g_pmdlSystemCall;
PVOID *MappedSystemCallTable;

//保存原函数地址的变量
PZwTerminateProcess         Old_ZwTerminateProcess = NULL;
PZwOpenProcess				Old_ZwOpenProcess = NULL;