#pragma once
#include "minispy.h"

#define CloudSelfpDriverServiceName				L"SelfProtect"
#define CloudSelfpDriverDependencies			L"FltMgr"
#define CloudSelfpDriverLoadOrderGroup			L"FSFilter Activity Monitor"
#define SubKey									"SYSTEM\\CurrentControlSet\\Services\\SelfProtect\\Instances"

HANDLE _OpenDevice();
BOOL _SetOnOFF(DWORD dwCtrlCode,BOOL bEnable);
BOOL _SendDataToDriver(DWORD dwCtrlCode,PVOID InPutBuffer,DWORD dwInPutBufferLeng);
BOOL _InstallMiniFilterDriver(LPCWSTR lpBinaryName);
BOOL _InstallService(__in LPCWSTR lpServiceName,
	__in DWORD dwServiceType,
	__in DWORD dwStartType,
	__in LPCWSTR lpBinaryPathName,
	__in LPCWSTR lpDependencies,
	__in LPCWSTR lpLoadOrderGroup);
BOOL _IsVistaAndLater();
BOOL _StartFsFilterService(IN LPCTSTR lpServiceName);
BOOL _UnInstallService(IN LPCTSTR lpServiceName);
BOOL _IsVistaAndLater();
CString _GetDllPath();
