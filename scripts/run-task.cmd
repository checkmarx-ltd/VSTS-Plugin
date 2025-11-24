@echo off
pushd %~dp0..\CxScan\CxScanV20

:: --- Build TypeScript ---
call npx tsc

:: --- SAST Connection / Auth ---
set INPUT_ENABLEPROXY=false
set INPUT_CheckmarxService=endpointId
set ENDPOINT_URL_endpointId=http://10.33.0.15
set ENDPOINT_AUTH_SCHEME_endpointId=UsernamePassword
set ENDPOINT_AUTH_PARAMETER_endpointId_USERNAME=admin@cx
set ENDPOINT_AUTH_PARAMETER_endpointId_PASSWORD=Cx12345678!

:: --- Project Context ---
set INPUT_PROJECTNAME=MyFakeProject_ForTesting_Unknown_999999
set INPUT_FULLTEAMNAME=/CxServer
set INPUT_OVERRIDEPROJECTSETTINGS=true

:: --- Preset + Engine Config ---
set INPUT_PRESET=Checkmarx Default
set INPUT_CONFIGURATION=Default Configuration
set INPUT_CONFIGURATIONID=1
set INPUT_ENGINECONFIGURATIONID=1
set INPUT_ENGINECONFIGID=1
set INPUT_ENGINECONFIGURATION=Default Configuration

:: --- Source Under Test ---
set BUILD_SOURCESDIRECTORY=C:\Users\RiyajS\Downloads\patternTest

:: --- Scan Toggles ---
set INPUT_enableSastScan=true
set INPUT_ENABLEDEPENDENCYSCAN=false
set SYSTEM_DEBUG=true

:: --- DEBUG:  ---
echo FILEEXT: %INPUT_FILEEXTENSION%
set INPUT_ | findstr /I "FILEEXTENSION EXCLUDE"

:: --- Execute Scan ---
"C:\Program Files\nodejs\node.exe" --inspect=9229 target\index.js


popd