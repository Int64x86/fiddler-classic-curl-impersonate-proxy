@echo off
setlocal
set "ROOT=%~dp0"
set "CMAKE=C:\Program Files\CMake\bin\cmake.exe"

pushd "%ROOT%"

"%CMAKE%" -S . -B build -G "Visual Studio 17 2022" -A x64
if errorlevel 1 exit /b %errorlevel%

"%CMAKE%" --build build --config Release

copy /Y "build\Release\fiddler-impersonate-proxy.exe" "%USERPROFILE%\Documents\Fiddler2\Scripts\CurlImpersonateProxyExtension\"
copy /Y "build\Release\libcurl-impersonate.dll" "%USERPROFILE%\Documents\Fiddler2\Scripts\CurlImpersonateProxyExtension\"