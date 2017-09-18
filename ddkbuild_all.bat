start /wait /b %~dp0\filter_xp\ddkbuild.bat x86 WXP
start /wait /b %~dp0\filter\ddkbuild.bat x64 WLH
start /wait /b %~dp0\filter\ddkbuild.bat x86 WLH
pause
copy %~dp0\filter\objchk_wlh_amd64\amd64\SelfProtect.sys %~dp0bin\SelfProtect_x64.sys
copy %~dp0\filter\objchk_wlh_amd64\amd64\SelfProtect.pdb %~dp0bin\SelfProtect_x64.pdb
copy %~dp0\filter\objchk_wlh_x86\i386\SelfProtect.sys %~dp0bin\SelfProtect_x86.sys
copy %~dp0\filter\objchk_wlh_x86\i386\SelfProtect.pdb %~dp0bin\SelfProtect_x86.pdb
copy %~dp0\filter_xp\objchk_wxp_x86\i386\SelfProtect.sys %~dp0bin\SelfProtect_xp_x86.sys
copy %~dp0\filter_xp\objchk_wxp_x86\i386\SelfProtect.pdb %~dp0bin\SelfProtect_xp_x86.pdb
pause