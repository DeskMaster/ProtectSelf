call %WINDDK_ROOT_7600%\bin\setenv.bat %WINDDK_ROOT_7600%\ chk %1 %2
%~d0
cd %~dp0
build
exit