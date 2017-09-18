#pragma once
#include <vector>
#include "minispy.h"

#define CloudSelfpDriverServiceName				L"SelfProtect"
#define CloudSelfpDriverDependencies			L"FltMgr"
#define CloudSelfpDriverLoadOrderGroup			L"FSFilter Activity Monitor"
#define SubKey									"SYSTEM\\CurrentControlSet\\Services\\SelfProtect\\Instances"

typedef std::vector <PROTECT_PATH_NODE>	Path_Node_Vector;
typedef std::vector <DWORD>	Trust_Pid_Vector;

BOOL EnablePidProctect();
BOOL DisablePidProctect();
BOOL EnableFileProctect();
BOOL DisableFileProctect();
BOOL EnableRegProctect();
BOOL DisableRegProctect();
BOOL SetProctFilePath(Path_Node_Vector& FilePathVector);
BOOL SetProctRegPath(Path_Node_Vector& RegPathVector);
BOOL SetTrustPid(Trust_Pid_Vector& FilePathVector);
HANDLE OpenDevice();
BOOL SetOnOFF(DWORD dwCtrlCode,BOOL bEnable);
BOOL SendDataToDriver(DWORD dwCtrlCode,PVOID InPutBuffer,DWORD dwInPutBufferLeng);

BOOL InstallMiniFilterDriver(LPCWSTR lpBinaryName);
BOOL InstallService(__in LPCWSTR lpServiceName,
	__in DWORD dwServiceType,
	__in DWORD dwStartType,
	__in LPCWSTR lpBinaryPathName,
	__in LPCWSTR lpDependencies,
	__in LPCWSTR lpLoadOrderGroup);
BOOL IsVistaAndLater();
BOOL StartFsFilterService(IN LPCTSTR lpServiceName);
BOOL UnInstallService(IN LPCTSTR lpServiceName);
BOOL InstallMiniFilerDriver();
BOOL UnInstallMiniFilerDriver();