#pragma once
#include "minispy.h"

BOOL EnablePidProctect();
BOOL DisablePidProctect();
BOOL EnableFileProctect();
BOOL DisableFileProctect();
BOOL EnableRegProctect();
BOOL DisableRegProctect();
BOOL SetProctFilePath(PVOID Buffer,DWORD dwBufferLength);
BOOL SetProctRegPath(PVOID Buffer,DWORD dwBufferLength);
BOOL SetTrustPid(PVOID Buffer,DWORD dwBufferLength);
BOOL InstallMiniFilerDriver();
BOOL UnInstallMiniFilerDriver();
BOOL OpenEnginePort();
BOOL CloseEnginePort();
BOOL GetCertNameOfMsSign(LPCWSTR wszFileName,LPTSTR strCertName,DWORD dwCertNameLeng);
BOOL CheckMSSignature(LPCWSTR lpFileName);
