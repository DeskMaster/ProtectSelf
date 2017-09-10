#include "StdAfx.h"
#include <winioctl.h>
#include <Winsvc.h>
#include "DriverInterface.h"

#pragma comment(lib,"Advapi32.lib")

BOOL EnablePidProctect()
{
	BOOL bRet = SetOnOFF(IOCTL_SET_PROCESS_PROTECT_ONOFF,TRUE);
	if(!bRet)
		OutputDebugString(_T("EnablePidProctect: Enable process protect faild\n"));

	return bRet;
}
BOOL DisablePidProctect()
{
	BOOL bRet = SetOnOFF(IOCTL_SET_PROCESS_PROTECT_ONOFF,FALSE);
	if(!bRet)
		OutputDebugString(_T("EnablePidProctect: Disable process protect faild\n"));

	return bRet;
}

BOOL EnableFileProctect()
{
	BOOL bRet = SetOnOFF(IOCTL_SET_FILE_PROTECT_ONOFF,TRUE);
	if(!bRet)
		OutputDebugString(_T("EnableFileProctect: Enable file protect faild\n"));

	return bRet;
}
BOOL DisableFileProctect()
{
	BOOL bRet = SetOnOFF(IOCTL_SET_FILE_PROTECT_ONOFF,FALSE);
	if(!bRet)
		OutputDebugString(_T("EnableFileProctect: Disable file protect faild\n"));

	return bRet;
}

BOOL EnableRegProctect()
{
	BOOL bRet = SetOnOFF(IOCTL_SET_REG_PROTECT_ONOFF,TRUE);
	if(!bRet)
		OutputDebugString(_T("EnableFileProctect: Enable Reg protect faild\n"));

	return bRet;
}
BOOL DisableRegProctect()
{
	BOOL bRet = SetOnOFF(IOCTL_SET_REG_PROTECT_ONOFF,FALSE);
	if(!bRet)
		OutputDebugString(_T("EnableFileProctect: Enable Reg protect faild\n"));

	return bRet;
}

BOOL SetProctFilePath(Path_Node_Vector& FilePathVector)
{
	BOOL bRet = FALSE;
	size_t Counts = FilePathVector.size();
	if (Counts==0)
	{
		return bRet;
	}

	PATH_LIST FilePathList;
	memset(&FilePathList,0,sizeof(PATH_LIST));
	FilePathList.PathNum = Counts;
	for (int i=0;i<Counts;i++)
	{
		memcpy(&FilePathList.PathArray[i],&FilePathVector[i],sizeof(PROTECT_PATH_NODE));
	}

	bRet = SendDataToDriver(IOCTL_SET_PROTECT_FILE_PATH,&FilePathList,sizeof(PATH_LIST));

	return bRet;
}

BOOL SetProctRegPath(Path_Node_Vector& RegPathVector)
{
	BOOL bRet = FALSE;
	size_t Counts = RegPathVector.size();
	if (Counts==0)
	{
		return bRet;
	}

	PATH_LIST RegPathList;
	memset(&RegPathList,0,sizeof(PATH_LIST));
	RegPathList.PathNum = Counts;
	for (int i=0;i<Counts;i++)
	{
		memcpy(&RegPathList.PathArray[i],&RegPathVector[i],sizeof(PROTECT_PATH_NODE));
	}

	bRet = SendDataToDriver(IOCTL_SET_PROTECT_REG_PATH,&RegPathList,sizeof(PATH_LIST));

	return bRet;
}

BOOL SetTrustPid(Trust_Pid_Vector& TrustPidVector)
{
	BOOL bRet = FALSE;
	size_t Counts = TrustPidVector.size();
	if (Counts==0)
	{
		return bRet;
	}

	PROCESS_WHITE_LIST TrustPidList;
	memset(&TrustPidList,0,sizeof(PROCESS_WHITE_LIST));
	TrustPidList.WhiteProcessNum = Counts;
	for (int i=0;i<Counts;i++)
	{
		TrustPidList.PidArray[i]=TrustPidVector[i];
	}

	bRet = SendDataToDriver(IOCTL_SET_TRUST_PID,&TrustPidList,sizeof(PROCESS_WHITE_LIST));

	return bRet;
}

HANDLE OpenDevice()
{
	HANDLE hFile = CreateFile(WIN32_STRING,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED,
		NULL);
	if (hFile==INVALID_HANDLE_VALUE)
	{
		CString strDbg;
		strDbg.Format(_T("OpenDevice: CreateFile %s faild,errorcode=%d\n"),
			WIN32_STRING,GetLastError());

		OutputDebugString(strDbg);
	}

	return hFile;
}

BOOL SetOnOFF(DWORD dwCtrlCode,BOOL bEnable)
{
	BOOL bRet = FALSE;
	HANDLE hFile = OpenDevice();
	if (hFile)
	{
		return bRet;
	}

	DWORD dwInPut = bEnable;
	DWORD dwRet = 0;
	bRet = DeviceIoControl(hFile,dwCtrlCode,&dwInPut,sizeof(DWORD),NULL,0,&dwRet,NULL);
	if (!bRet)
	{
		CString strDbg;
		strDbg.Format(_T("SetOnOFF: DeviceIoControl(%d) faild ,ErrorCode=%d\n"),
			dwCtrlCode,GetLastError());
		OutputDebugString(strDbg);
	}

	CloseHandle(hFile);

	return bRet;
}

BOOL SendDataToDriver(DWORD dwCtrlCode,PVOID InPutBuffer,DWORD dwInPutBufferLeng)
{
	BOOL bRet = FALSE;
	HANDLE hFile = OpenDevice();
	if (hFile)
	{
		return bRet;
	}

	DWORD dwRet = 0;
	bRet = DeviceIoControl(hFile,dwCtrlCode,InPutBuffer,dwInPutBufferLeng,NULL,0,&dwRet,NULL);
	if (!bRet)
	{
		CString strDbg;
		strDbg.Format(_T("SetOnOFF: DeviceIoControl(%d) faild ,ErrorCode=%d\n"),
			dwCtrlCode,GetLastError());
		OutputDebugString(strDbg);
	}

	CloseHandle(hFile);

	return bRet;
}

BOOL InstallMiniFilterDriver(LPCWSTR lpBinaryName)
{
	BOOL bRet = InstallService(CloudSelfpDriverServiceName,
		SERVICE_FILE_SYSTEM_DRIVER,
		SERVICE_SYSTEM_START,
		lpBinaryName,
		CloudSelfpDriverDependencies,
		CloudSelfpDriverLoadOrderGroup);

	if (bRet)
	{
		OutputDebugString(_T("InstallMiniFilterDriver: Minifilter service install sucess\n"));
		BYTE DataBuffer[512]={0};
		DWORD cbDataBuffer = 0;
		HKEY hSubKey;
		DWORD dwDisp = 0;
		LONG lResult = RegCreateKeyExA(HKEY_LOCAL_MACHINE, SubKey, 
			0, NULL, REG_OPTION_NON_VOLATILE,
			KEY_WRITE, NULL, &hSubKey, &dwDisp);
		if (lResult == ERROR_SUCCESS)
		{
			cbDataBuffer = sizeof("SelfProtect Instance");
			memcpy(DataBuffer,"SelfProtect Instance",cbDataBuffer);

			lResult = RegSetValueExA(hSubKey,"DefaultInstance",0,REG_SZ,DataBuffer,cbDataBuffer);
			if (lResult == ERROR_SUCCESS)
			{
				HKEY hSubKey_1;
				lResult = RegCreateKeyExA(hSubKey, "SelfProtect Instance", 
					0, NULL, REG_OPTION_NON_VOLATILE,
					KEY_WRITE, NULL, &hSubKey_1, &dwDisp);
				if (lResult == ERROR_SUCCESS)
				{
					memset(DataBuffer,0,512);
					cbDataBuffer = sizeof("443220");
					memcpy(DataBuffer,"443220",cbDataBuffer);

					lResult = RegSetValueExA(hSubKey_1,"Altitude",0,REG_SZ,DataBuffer,cbDataBuffer);

					memset(DataBuffer,0,512);
					cbDataBuffer = sizeof(DWORD);
					lResult = RegSetValueExA(hSubKey_1,"Flags",0,REG_DWORD,DataBuffer,cbDataBuffer);

					RegCloseKey(hSubKey_1);
				}
			}

			RegCloseKey(hSubKey);

			if (lResult == ERROR_SUCCESS)
			{
				bRet = StartFsFilterService(CloudSelfpDriverServiceName);
			}
		}
	}
	else
	{
		OutputDebugString(_T("InstallMiniFilterDriver: Minifilter install fail\n"));
	}

	return bRet;
}

BOOL InstallService(__in LPCWSTR lpServiceName,
	__in DWORD dwServiceType,
	__in DWORD dwStartType,
	__in LPCWSTR lpBinaryPathName,
	__in LPCWSTR lpDependencies,
	__in LPCWSTR lpLoadOrderGroup)
{
	BOOL		bRet = FALSE;
	SC_HANDLE   schSCManager = NULL;
	SC_HANDLE   schService = NULL;
	DWORD		dwErrorCode = 0;

	if(NULL == lpServiceName || NULL == lpBinaryPathName)
	{
		return bRet;
	}

	schSCManager = OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		dwErrorCode = ::GetLastError();
		return bRet;
	}

	schService = CreateServiceW(schSCManager,           // handle of service control manager database
		lpServiceName,             // address of name of service to start
		lpServiceName,             // address of display name
		SERVICE_ALL_ACCESS,     // type of access to service
		dwServiceType,  // type of service
		dwStartType,   // when to start service
		SERVICE_ERROR_NORMAL,   // severity if service fails to start
		lpBinaryPathName,       // address of name of binary file
		lpLoadOrderGroup,            // service belong to a group
		NULL,                   // no tag requested
		lpDependencies,                   // no dependency names
		NULL,                   // use LocalSystem account
		NULL                    // no password for service account
		);

	if (NULL == schSCManager)
	{
		dwErrorCode = ::GetLastError();
		OutputDebugString(_T("InstallServiceAndStart 创建服务失败！！！！！\n"));
	}
	else
	{
		bRet = TRUE;
	}

	if (schService)
	{
		CloseServiceHandle(schService);
	}

	if (schSCManager)
	{
		CloseServiceHandle(schSCManager);
	}

	return bRet;
}

BOOL StartFsFilterService(IN LPCTSTR lpServiceName)
{
	BOOL		bRet = FALSE;
	SC_HANDLE   schSCManager = NULL;
	SC_HANDLE   schService = NULL;
	DWORD		dwErrorCode = 0;

	schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		dwErrorCode = ::GetLastError();
		return FALSE;
	}

	schService = OpenService(schSCManager,lpServiceName,SERVICE_ALL_ACCESS);
	if (NULL == schService)
	{
		dwErrorCode = ::GetLastError();
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	bRet = ::StartService(schService,0,NULL);
	if (!bRet)
	{
		dwErrorCode = ::GetLastError();
		if (ERROR_SERVICE_ALREADY_RUNNING == dwErrorCode)
		{
			OutputDebugString(_T("StartService 启动指定的服务已经启动了，不需要再次启动\n"));
			bRet = TRUE;
		}
		else
		{
			OutputDebugString(_T("StartService 启动指定的服务失败\n"));
		}
	}

	if (schService)
	{
		CloseServiceHandle(schService);
	}

	if (schSCManager)
	{
		CloseServiceHandle(schSCManager);
	}

	return bRet;
}

BOOL UnInstallService(IN LPCTSTR lpServiceName)
{
	BOOL		bRet = FALSE;
	SC_HANDLE   schSCManager = NULL;
	SC_HANDLE   schService = NULL;
	wchar_t     dbgMess[512]={0};
	DWORD		dwErrorCode = 0;

	OutputDebugString(_T("UnInstallService:  begin.................................\n"));
	schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		dwErrorCode = ::GetLastError();
		return FALSE;
	}

	schService = OpenService(schSCManager,lpServiceName,SERVICE_ALL_ACCESS);
	if (NULL == schService)
	{
		dwErrorCode = ::GetLastError();
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	SERVICE_STATUS_PROCESS ssp;
	if (bRet=ControlService(schService,SERVICE_CONTROL_STOP,(LPSERVICE_STATUS) &ssp))
	{
		swprintf(dbgMess,L"UnInstallService: ControlService sucess,ServiceName=%s\n", lpServiceName);
		OutputDebugString( dbgMess);
	}
	else
	{
		swprintf(dbgMess,L"UnInstallService: ControlService err:%d,ServiceName=%s\n", GetLastError(),lpServiceName);
		OutputDebugString( dbgMess);
	}

	if(bRet = DeleteService(schService))
	{
		swprintf(dbgMess,L"UnInstallService: delete service success,ServiceName=%s\n",lpServiceName);
		OutputDebugString(dbgMess);
	}
	else
	{
		swprintf(dbgMess, L"UnInstallService: DeleteService err:%d,ServiceName=%s\n", GetLastError(),lpServiceName);
		OutputDebugString( dbgMess);
	}

	if (schService)
	{
		CloseServiceHandle(schService);
	}

	if (schSCManager)
	{
		CloseServiceHandle(schSCManager);
	}

	return bRet;
}