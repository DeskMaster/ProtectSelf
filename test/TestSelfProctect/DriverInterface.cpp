#include "StdAfx.h"
#include <winioctl.h>
#include <Winsvc.h>

#include<algorithm>
#include <Mscat.h>
#include <Wintrust.h>
#include <Softpub.h>
#include <Wincrypt.h>
#include <Psapi.h>

#include "DriverInterface.h"
#include "drvcommon.h"

#pragma comment(lib,"Wintrust.lib")
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"Psapi.lib")
#pragma comment(lib,"Advapi32.lib")

HANDLE g_EnginePort = INVALID_HANDLE_VALUE;
ULONGLONG g_MessageId = 0;

BOOL VerifyEmbeddedSignature(LPCTSTR pwszSourceFile)
{
    LONG lStatus;
    DWORD dwLastError;

    // Initialize the WINTRUST_FILE_INFO structure.

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:
    
    1) The certificate used to sign the file chains up to a root 
    certificate located in the trusted root certificate store. This 
    implies that the identity of the publisher has been verified by 
    a certification authority.
    
    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the  
    end entity certificate is stored in the trusted publisher store,  
    implying that the user trusts content from this publisher.
    
    3) The end entity certificate has sufficient permission to sign 
    code, as indicated by the presence of a code signing EKU or no 
    EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);
    
    // Use default code signing EKU.
    WinTrustData.pPolicyCallbackData = NULL;

    // No data to pass to SIP.
    WinTrustData.pSIPClientData = NULL;

    // Disable WVT UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 

    // Verify an embedded signature on a file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    WinTrustData.hWVTStateData = NULL;

    // Not used.
    WinTrustData.pwszURLReference = NULL;

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of 
    // installing applications.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus) 
    {
        case ERROR_SUCCESS:
            /*
            Signed file:
                - Hash that represents the subject is trusted.

                - Trusted publisher without any verification errors.

                - UI was disabled in dwUIChoice. No publisher or 
                    time stamp chain errors.

                - UI was enabled in dwUIChoice and the user clicked 
                    "Yes" when asked to install and run the signed 
                    subject.
            */
            wprintf_s(L"The file \"%s\" is signed and the signature "
                L"was verified.\n",
                pwszSourceFile);
            break;
        
        case TRUST_E_NOSIGNATURE:
            // The file was not signed or had a signature 
            // that was not valid.

            // Get the reason for no signature.
            dwLastError = GetLastError();
            if (TRUST_E_NOSIGNATURE == dwLastError ||
                    TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
                    TRUST_E_PROVIDER_UNKNOWN == dwLastError) 
            {
                // The file was not signed.
                wprintf_s(L"The file \"%s\" is not signed.\n",
                    pwszSourceFile);
            } 
            else 
            {
                // The signature was not valid or there was an error 
                // opening the file.
                wprintf_s(L"An unknown error occurred trying to "
                    L"verify the signature of the \"%s\" file.\n",
                    pwszSourceFile);
            }

            break;

        case TRUST_E_EXPLICIT_DISTRUST:
            // The hash that represents the subject or the publisher 
            // is not allowed by the admin or user.
            wprintf_s(L"The signature is present, but specifically "
                L"disallowed.\n");
            break;

        case TRUST_E_SUBJECT_NOT_TRUSTED:
            // The user clicked "No" when asked to install and run.
            wprintf_s(L"The signature is present, but not "
                L"trusted.\n");
            break;

        case CRYPT_E_SECURITY_SETTINGS:
            /*
            The hash that represents the subject or the publisher 
            was not explicitly trusted by the admin and the 
            admin policy has disabled user trust. No signature, 
            publisher or time stamp errors.
            */
            wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
                L"representing the subject or the publisher wasn't "
                L"explicitly trusted by the admin and admin policy "
                L"has disabled user trust. No signature, publisher "
                L"or timestamp errors.\n");
            break;

        default:
            // The UI was disabled in dwUIChoice or the admin policy 
            // has disabled user trust. lStatus contains the 
            // publisher or time stamp chain error.
            wprintf_s(L"Error is: 0x%x.\n",
                lStatus);
            break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    return true;
}

BOOL EmbedSigVerify(__in LPTSTR strFileName)
{
	BOOL bRet = FALSE;
	LONG  lStatus;
	WINTRUST_FILE_INFO FileData;
	CString strDbg;

	ZeroMemory(&FileData,sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = strFileName;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	ZeroMemory(&WinTrustData, sizeof(WinTrustData));
	WinTrustData.cbStruct = sizeof(WinTrustData);        
	WinTrustData.pPolicyCallbackData	= NULL;    
	WinTrustData.pSIPClientData			= NULL;    
	WinTrustData.dwUIChoice				= WTD_UI_NONE;    
	WinTrustData.fdwRevocationChecks	= WTD_REVOKE_NONE;     
	WinTrustData.dwUnionChoice			= WTD_CHOICE_FILE;    
	WinTrustData.dwStateAction			= WTD_STATEACTION_VERIFY;   
	WinTrustData.hWVTStateData			= NULL;    
	WinTrustData.pwszURLReference		= NULL;    
	WinTrustData.dwProvFlags			= 0;
	WinTrustData.dwUIContext			= 0;    
	WinTrustData.pFile					= &FileData;
	
	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	strDbg.Format(_T("EmbedSigVerify: %s WinVerifyTrust(%d),ErrorCode=%d\n"),lStatus,GetLastError());
	OutputDebugString(strDbg);

	if (lStatus == ERROR_SUCCESS) 
	{
		bRet = FALSE;			
	}

	return bRet;
}

BOOL GetCertNameOfMsSign(LPCWSTR wszFileName,LPTSTR strCertName,DWORD dwCertNameLeng)
{
	OutputDebugString(_T("==>GetCertNameOfMsSign"));
	OutputDebugString(wszFileName);

	LONG  lStatus;
	WINTRUST_FILE_INFO FileData;

	ZeroMemory(&FileData,sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = wszFileName;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	ZeroMemory(&WinTrustData, sizeof(WinTrustData));
	WinTrustData.cbStruct = sizeof(WinTrustData);        
	WinTrustData.pPolicyCallbackData	= NULL;    
	WinTrustData.pSIPClientData			= NULL;    
	WinTrustData.dwUIChoice				= WTD_UI_NONE;    
	WinTrustData.fdwRevocationChecks	= WTD_REVOKE_NONE;     
	WinTrustData.dwUnionChoice			= WTD_CHOICE_FILE;    
	WinTrustData.dwStateAction			= WTD_STATEACTION_VERIFY;   
	WinTrustData.hWVTStateData			= NULL;    
	WinTrustData.pwszURLReference		= NULL;    
	WinTrustData.dwProvFlags			= 0;
	WinTrustData.dwUIContext			= 0;    
	WinTrustData.pFile					= &FileData;

	BOOL Result = FALSE;

	__try
	{

		lStatus = WinVerifyTrust(
			NULL,
			&WVTPolicyGUID,
			&WinTrustData);

		if (lStatus != ERROR_SUCCESS && lStatus != CERT_E_EXPIRED) 
		{
			OutputDebugString(_T("GetCertNameOfMsSign: lStatus != ERROR_SUCCESS && lStatus != CERT_E_EXPIRED"));
			return FALSE;			
		}

		// 获取证书签名信息
		CRYPT_PROVIDER_DATA *pProvData = WTHelperProvDataFromStateData(WinTrustData.hWVTStateData);
		if(pProvData)
		{			
			PCCERT_CONTEXT		pCertContext = NULL;
			PCERT_SIMPLE_CHAIN	pCertSimpleChain = NULL;	

			if (pProvData->csSigners > 0 && pProvData->pasSigners // 有签名者
				&& pProvData->pasSigners->pChainContext
				&& pProvData->pasSigners->pChainContext->rgpChain && pProvData->pasSigners->pChainContext->cChain > 0)
			{
				pCertSimpleChain = 	pProvData->pasSigners->pChainContext->rgpChain[0];
			}

			if (pCertSimpleChain &&
				pCertSimpleChain->cElement > 0 && pCertSimpleChain->rgpElement
				&& pCertSimpleChain->rgpElement[0] != NULL)
			{
				PCCERT_CONTEXT  pCertContext = pCertSimpleChain->rgpElement[0]->pCertContext;
				if (pCertContext)
				{
					WCHAR CertName[512] = {};
					DWORD NameLength = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,0,0,CertName, _countof(CertName));

					if (NameLength > 0 && NameLength < dwCertNameLeng/sizeof(TCHAR) )
					{
						//OutputDebugString(CertName);
						//if (_wcsicmp(CertName,L"一普明为（北京）信息技术有限公司") == 0)

						memcpy(strCertName,CertName,NameLength*sizeof(TCHAR));
						Result = TRUE;
					}
				}
			}
			else
			{
				OutputDebugString(_T("GetCertNameOfMsSign: WTHelperProvDataFromStateData pCertSimpleChain\n"));
			}
		}
		else
		{
			OutputDebugString(_T("GetCertNameOfMsSign: WTHelperProvDataFromStateData faild\n"));
		}

		// 释放资源
		HANDLE h = WinTrustData.hWVTStateData;
		ZeroMemory( &WinTrustData, sizeof(WINTRUST_DATA) );
		WinTrustData.cbStruct = sizeof(WINTRUST_DATA);
		WinTrustData.hWVTStateData = h;
		WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &WVTPolicyGUID , &WinTrustData);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		Result = FALSE;
	}

	return Result;
}

BOOL CheckMSSignature(LPCWSTR lpFileName)
{
	BOOL bRet = FALSE;
	HCATADMIN hCatAdmin = NULL;
	if ( !CryptCATAdminAcquireContext( &hCatAdmin, NULL, 0 ) )
		return FALSE;

	HANDLE hFile = CreateFileW(lpFileName,GENERIC_READ,FILE_SHARE_READ,NULL, OPEN_EXISTING, 0, NULL );
	if(INVALID_HANDLE_VALUE == hFile )
	{
		CryptCATAdminReleaseContext( hCatAdmin, 0 );
		return FALSE;
	}

	DWORD dwCnt = 100;
	BYTE byHash[100];
	CryptCATAdminCalcHashFromFileHandle( hFile, &dwCnt, byHash, 0 );
	CloseHandle( hFile );

	LPWSTR pszMemberTag = new WCHAR[dwCnt * 2 + 1];
	for ( DWORD dw = 0; dw < dwCnt; ++dw )
	{
		wsprintfW( &pszMemberTag[dw * 2], L"%02X", byHash[dw] );
	}

	WINTRUST_DATA wd = { 0 };
	WINTRUST_FILE_INFO wfi = { 0 };
	WINTRUST_CATALOG_INFO wci = { 0 };
	CATALOG_INFO ci = { 0 };
	HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash( hCatAdmin,byHash, dwCnt, 0, NULL );
	if ( NULL == hCatInfo )
	{
		wfi.cbStruct       = sizeof( WINTRUST_FILE_INFO );
		wfi.pcwszFilePath  = lpFileName;
		wfi.hFile          = NULL;
		wfi.pgKnownSubject = NULL;

		wd.cbStruct            = sizeof( WINTRUST_DATA );
		wd.dwUnionChoice       = WTD_CHOICE_FILE;
		wd.pFile               = &wfi;
		wd.dwUIChoice          = WTD_UI_NONE;
		wd.fdwRevocationChecks = WTD_REVOKE_NONE;
		wd.dwStateAction       = WTD_STATEACTION_IGNORE;
		wd.dwProvFlags         = WTD_SAFER_FLAG;
		wd.hWVTStateData       = NULL;
		wd.pwszURLReference    = NULL;
	}
	else
	{
		CryptCATCatalogInfoFromContext( hCatInfo, &ci, 0 );
		wci.cbStruct             = sizeof( WINTRUST_CATALOG_INFO );
		wci.pcwszCatalogFilePath = ci.wszCatalogFile;
		wci.pcwszMemberFilePath  = lpFileName;
		wci.pcwszMemberTag       = pszMemberTag;

		wd.cbStruct            = sizeof( WINTRUST_DATA );
		wd.dwUnionChoice       = WTD_CHOICE_CATALOG;
		wd.pCatalog            = &wci;
		wd.dwUIChoice          = WTD_UI_NONE;
		wd.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
		wd.dwProvFlags         = 0;
		wd.hWVTStateData       = NULL;
		wd.pwszURLReference    = NULL;
	}

	GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	HRESULT hr  = WinVerifyTrust(NULL,&action,&wd );
	bRet = SUCCEEDED(hr);

	if ( NULL != hCatInfo )
		CryptCATAdminReleaseCatalogContext( hCatAdmin, hCatInfo, 0 );

	CryptCATAdminReleaseContext(hCatAdmin,0);
	delete[] pszMemberTag;
	return bRet;
}

BOOL CloseEnginePort()
{
	BOOL bRet =TRUE;
	CloseHandle(g_EnginePort);
	g_EnginePort = INVALID_HANDLE_VALUE;

	return TRUE;
}

BOOL OpenEnginePort()
{
	BOOL bRet = FALSE;
	HRESULT hResul = FilterConnectCommunicationPort(MINISPY_PORT_NAME,
		0,NULL,0,NULL,&g_EnginePort);

	if (S_OK == hResul)
	{
		bRet = TRUE;
		OutputDebugString(_T("OpenEnginePort: FilterConnectCommunicationPort sucess\n"));
	}
	else
	{
		CString strdbg;
		strdbg.Format(_T("OpenEnginePort: FilterConnectCommunicationPort faild,hResult=%d\n"),hResul);
		OutputDebugString(strdbg);
	}

	_beginthreadex(NULL, 0, _ReadPacketThread, NULL,0, NULL);

	return bRet;
}

BOOL _PassHandle()
{
	return _SendReplyMess(REPLY_PASS);
}

BOOL _BlockHandle()
{
	return _SendReplyMess(REPLY_BLOCK);
}

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

BOOL _SendReplyMess(ULONG ReplyResult)
{
	HRESULT hResult;
	FILTER_REPLY_MESSAGE ReplyMess;
	ULONG replyLength = sizeof(FILTER_REPLY_MESSAGE);
	replyLength =sizeof(FILTER_REPLY_HEADER)+sizeof(ULONG);
	ZeroMemory(&ReplyMess,replyLength);
	ReplyMess.ReplyData.Result = ReplyResult;
	ReplyMess.ReplyHeader.MessageId = g_MessageId;

	hResult = FilterReplyMessage(g_EnginePort, (PFILTER_REPLY_HEADER)&ReplyMess, replyLength);
	if (hResult == S_OK)
	{
		OutputDebugString(_T("SendReplyMess:  FilterReplyMessage sucess!!\n"));
	}
	else
	{
		CString strdbg;
		strdbg.Format(_T("SendReplyMess:  FilterReplyMessage faild,hResult=%d\n"),hResult);
		OutputDebugString(strdbg);
	}

	return TRUE;
}

CString GetNameByPid(DWORD  ProcessID)
{
	TCHAR    path[_MAX_PATH+1]={0};  
	TCHAR    drive[_MAX_DRIVE]={0};  
	TCHAR    dir[_MAX_DIR]={0};  
	TCHAR    fname[_MAX_FNAME]={0};  
	TCHAR    ext[_MAX_EXT]={0};  
	CString strName;
	//HANDLE  hToken;  


	//提升程序权限  
	//OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken);  
	//EnablePrivilege(hToken,SE_DEBUG_NAME);   

	//处理系统函数  
	if (ProcessID==4)  
	{  
		OutputDebugString(_T("GetNameByPid: system!!!\n"));
		return _T("system");  
	}  
	HANDLE h_Process=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,ProcessID);  
	if (!h_Process)  
	{  
		OutputDebugString(_T("GetNameByPid: OpenProcess faild!!!\n"));
		return _T("");  
	}  

	GetModuleFileNameEx(h_Process,NULL,path,MAX_PATH+1);  
	OutputDebugString(path);
	_wsplitpath(path, drive, dir, fname, ext );

	strName = fname;
	strName +=ext;
	OutputDebugString(strName);

	return strName;
}
unsigned __stdcall _ReadPacketThread(void* lParam)
{
	WCHAR Temp1[] = L"?";
	WCHAR Temp2[] = L"S";
	HRESULT hResult;
	ULONG recLength;
	FILTER_RECEIVE_MESSAGE recMsg;
	recLength = sizeof(FILTER_RECEIVE_MESSAGE);
	recLength = sizeof(FILTER_MESSAGE_HEADER)+sizeof(Send_Message);
	while(g_EnginePort != INVALID_HANDLE_VALUE)
	{
		ZeroMemory(&recMsg, recLength);
		hResult = FilterGetMessage(g_EnginePort, (PFILTER_MESSAGE_HEADER)&recMsg, recLength, NULL);
		if (hResult == S_OK &&
			wcsnlen(recMsg.ReciveData.FilePath,MAX_PATH_LENGTH))
		{
			CString strDbg;
			strDbg.Format(_T("type=%d,Pid=%d,FilePath=%s"),recMsg.ReciveData.Type,recMsg.ReciveData.Pid,recMsg.ReciveData.FilePath);
			g_MessageId = recMsg.MsgHeader.MessageId;

			if(IDYES == AfxMessageBox(strDbg,MB_YESNO|MB_ICONEXCLAMATION))
			{
				OutputDebugString(_T("_ReadPacketThread: _PassHandle\n"));
				_PassHandle();
			}
			else
			{
				OutputDebugString(_T("_ReadPacketThread: _BlockHandle\n"));
				_BlockHandle();
			}
		}
	}
	return 0;
}