#include "StdAfx.h"
#include <winioctl.h>
#include <Winsvc.h>
#include "DriverInterface.h"
#include "drvcommon.h"

#pragma comment(lib,"Advapi32.lib")

BOOL InstallMiniFilerDriver()
{
	BOOL bRet = FALSE;
	BOOL bVistaAndLater = _IsVistaAndLater();
	TCHAR SystemDir[MAX_PATH]={0};
	::GetSystemDirectory(SystemDir,MAX_PATH);
	CString strDesDriverPath=SystemDir;
	strDesDriverPath +=_T("\\drivers\\SelfProtect.sys");

	CString strBinaryName = strDesDriverPath;
	CString strDriverName;

#ifdef _AMD64_
	strDriverName = _T("\\SelfProtect_x64.sys");
#else
	if (bVistaAndLater)
	{
		strDriverName = _T("\\SelfProtect_x86.sys");
	}
	else
	{
		strDriverName = _T("\\SelfProtect_xp_x86.sys");
	}

#endif

	CString strSrcDriverPath = _GetDllPath();
	strSrcDriverPath += strDriverName;
	OutputDebugString(strSrcDriverPath);
	OutputDebugString(_T("\n"));
	OutputDebugString(strDesDriverPath);
	bRet = ::CopyFile(strSrcDriverPath.GetBuffer(),strDesDriverPath.GetBuffer(),FALSE);
	if (!bRet)
	{
		CString strdbg;
		strdbg.Format(_T("InstallVsecDriver: driver copy falid,ErrorCode=%d\n"),GetLastError());
		OutputDebugString(strdbg);
	}

	bRet = _InstallMiniFilterDriver(strBinaryName.GetBuffer());
	if (bRet)
	{
		OutputDebugString(_T("InstallVsecDriver: install vsec driver sucess!!\n"));
	}
	else
	{
		OutputDebugString(_T("InstallVsecDriver: install vsec driver faild!!!!!\n"));
	}

	return bRet;
}

BOOL UnInstallMiniFilerDriver()
{
	return _UnInstallService(CloudSelfpDriverServiceName);
}

BOOL EnablePidProctect()
{
	BOOL bRet = _SetOnOFF(IOCTL_SET_PROCESS_PROTECT_ONOFF,TRUE);
	if(!bRet)
		OutputDebugString(_T("EnablePidProctect: Enable process protect faild\n"));

	return bRet;
}
BOOL DisablePidProctect()
{
	BOOL bRet = _SetOnOFF(IOCTL_SET_PROCESS_PROTECT_ONOFF,FALSE);
	if(!bRet)
		OutputDebugString(_T("EnablePidProctect: Disable process protect faild\n"));

	return bRet;
}

BOOL EnableFileProctect()
{
	BOOL bRet = _SetOnOFF(IOCTL_SET_FILE_PROTECT_ONOFF,TRUE);
	if(!bRet)
		OutputDebugString(_T("EnableFileProctect: Enable file protect faild\n"));

	return bRet;
}
BOOL DisableFileProctect()
{
	BOOL bRet = _SetOnOFF(IOCTL_SET_FILE_PROTECT_ONOFF,FALSE);
	if(!bRet)
		OutputDebugString(_T("EnableFileProctect: Disable file protect faild\n"));

	return bRet;
}

BOOL EnableRegProctect()
{
	BOOL bRet = _SetOnOFF(IOCTL_SET_REG_PROTECT_ONOFF,TRUE);
	if(!bRet)
		OutputDebugString(_T("EnableFileProctect: Enable Reg protect faild\n"));

	return bRet;
}
BOOL DisableRegProctect()
{
	BOOL bRet = _SetOnOFF(IOCTL_SET_REG_PROTECT_ONOFF,FALSE);
	if(!bRet)
		OutputDebugString(_T("EnableFileProctect: Enable Reg protect faild\n"));

	return bRet;
}

//
BOOL SetProctFilePath(PVOID Buffer,DWORD dwBufferLength)
{
	BOOL bRet = _SendDataToDriver(IOCTL_SET_PROTECT_FILE_PATH,Buffer,dwBufferLength);

	return bRet;
}

BOOL SetProctRegPath(PVOID Buffer,DWORD dwBufferLength)
{
	BOOL bRet = _SendDataToDriver(IOCTL_SET_PROTECT_REG_PATH,Buffer,dwBufferLength);

	return bRet;
}

BOOL SetTrustPid(PVOID Buffer,DWORD dwBufferLength)
{
	BOOL bRet = FALSE;

	bRet = _SendDataToDriver(IOCTL_SET_TRUST_PID,Buffer,dwBufferLength);

	return bRet;
}

HANDLE _OpenDevice()
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

BOOL _SetOnOFF(DWORD dwCtrlCode,BOOL bEnable)
{
	BOOL bRet = FALSE;
	HANDLE hFile = _OpenDevice();
	if (hFile == INVALID_HANDLE_VALUE)
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

BOOL _SendDataToDriver(DWORD dwCtrlCode,PVOID InPutBuffer,DWORD dwInPutBufferLeng)
{
	BOOL bRet = FALSE;
	HANDLE hFile = _OpenDevice();
	if (hFile == INVALID_HANDLE_VALUE)
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

BOOL _InstallMiniFilterDriver(LPCWSTR lpBinaryName)
{
	BOOL bRet = _InstallService(CloudSelfpDriverServiceName,
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
					cbDataBuffer = sizeof("320320");
					memcpy(DataBuffer,"320320",cbDataBuffer);

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
				bRet = _StartFsFilterService(CloudSelfpDriverServiceName);
			}
		}
	}
	else
	{
		CString strdbg;
		strdbg.Format(_T("InstallMiniFilterDriver: InstallService faild,errorcode=%d,(%s)\n"),GetLastError(),lpBinaryName);
		OutputDebugString(strdbg);
	}

	return bRet;
}

BOOL _InstallService(__in LPCWSTR lpServiceName,
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
		OutputDebugString(_T("InstallService: NULL == lpServiceName || NULL == lpBinaryPathName\n"));
		return bRet;
	}

	schSCManager = OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		CString strdbg;
		strdbg.Format(_T("InstallService: OpenSCManagerW faild,ErrorCode=%d\n"),::GetLastError());
		OutputDebugString(strdbg);
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
		OutputDebugString(_T("InstallServiceAndStart ��������ʧ�ܣ���������\n"));
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

BOOL _StartFsFilterService(IN LPCTSTR lpServiceName)
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
			OutputDebugString(_T("StartService ����ָ���ķ����Ѿ������ˣ�����Ҫ�ٴ�����\n"));
			bRet = TRUE;
		}
		else
		{
			OutputDebugString(_T("StartService ����ָ���ķ���ʧ��\n"));
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

BOOL _UnInstallService(IN LPCTSTR lpServiceName)
{
	BOOL		bRet = FALSE;
	SC_HANDLE   schSCManager = NULL;
	SC_HANDLE   schService = NULL;
	DWORD		dwErrorCode = 0;
	CString strdbgMess;

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
		strdbgMess.Format(_T("UnInstallService: ControlService sucess,ServiceName=%s\n"), lpServiceName);
		OutputDebugString(strdbgMess);
	}
	else
	{
		strdbgMess.Format(_T("UnInstallService: ControlService err:%d,ServiceName=%s\n"), GetLastError(),lpServiceName);
		OutputDebugString( strdbgMess);
	}

	if(bRet = DeleteService(schService))
	{
		strdbgMess.Format(_T("UnInstallService: delete service success,ServiceName=%s\n"),lpServiceName);
		OutputDebugString(strdbgMess);
	}
	else
	{
		strdbgMess.Format(_T("UnInstallService: DeleteService err:%d,ServiceName=%s\n"), GetLastError(),lpServiceName);
		OutputDebugString( strdbgMess);
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

BOOL _IsVistaAndLater()
{
	BOOL bRet = FALSE;
	OSVERSIONINFO osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);
	if (osvi.dwMajorVersion >= 6)
	{
		bRet = TRUE;
	}

	return bRet;
}

CString _GetDllPath()
{
	TCHAR	szBuff[MAX_PATH] = {0};  
	HMODULE hModuleInstance = _AtlBaseModule.GetModuleInstance();  
	GetModuleFileName(hModuleInstance,szBuff, MAX_PATH);  
	CString strTmp = szBuff;
	CString strDllPath;
	strDllPath = strTmp.Mid(0, strTmp.ReverseFind('\\'));

	return strDllPath;
}