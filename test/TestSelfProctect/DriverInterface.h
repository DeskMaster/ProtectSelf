#pragma once
#include "minispy.h"

BOOL InstallMiniFilerDriver();
BOOL UnInstallMiniFilerDriver();
BOOL EnablePidProctect();
BOOL DisablePidProctect();
BOOL EnableFileProctect();
BOOL DisableFileProctect();
BOOL EnableRegProctect();
BOOL DisableRegProctect();
BOOL SetProctFilePath(PVOID Buffer,DWORD dwBufferLength);
BOOL SetProctRegPath(PVOID Buffer,DWORD dwBufferLength);
BOOL SetTrustPid(PVOID Buffer,DWORD dwBufferLength);
