@echo off
pushd %~dp0..\CxScan\CxScanV20

:: --- Build TypeScript ---
call npx tsc

:: --- SAST Connection / Auth ---
set INPUT_ENABLEPROXY=false
set INPUT_CheckmarxService=endpointId
set ENDPOINT_URL_endpointId=http://10.33.0.40
set ENDPOINT_AUTH_SCHEME_endpointId=UsernamePassword
set ENDPOINT_AUTH_PARAMETER_endpointId_USERNAME=admin@cx
set ENDPOINT_AUTH_PARAMETER_endpointId_PASSWORD=Cx12345678!

:: SCA CONNECTION
set INPUT_dependencyServerURL=endpointIdSCA
set ENDPOINT_URL_endpointIdSCA=https://api-sca.checkmarx.net
set ENDPOINT_AUTH_SCHEME_endpointIdSCA=UsernamePassword
set ENDPOINT_AUTH_PARAMETER_endpointIdSCA_USERNAME=UmeshW
set ENDPOINT_AUTH_PARAMETER_endpointIdSCA_PASSWORD=DEVcx78$
set INPUT_DEPENDENCYACCESSCONTROLURL=https://platform.checkmarx.net
set INPUT_DEPENDENCYWEBAPPURL=https://sca.checkmarx.net
set INPUT_DEPENDENCYTENANT=plugins
set INPUT_SCATEAM=/CxServer
set INPUT_SYNCMODE=true

:: --- Project Context ---
set INPUT_PROJECTNAME=RegressionTest
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
set BUILD_SOURCESDIRECTORY=C:\Project\NodeGoat-master\NodeGoat-master

:: --- Scan Toggles ---
set INPUT_enableSastScan=false
set INPUT_ENABLEDEPENDENCYSCAN=true
set INPUT_ISENABLESCARESOLVER=true
set SYSTEM_DEBUG=true

@REM set INPUT_INCLUDESOURCE=true
@REM set INPUT_DEPENDENCYFILEEXTENSION=
@REM set INPUT_DEPENDENCYFOLDEREXCLUSION=src,node_modules,bin,obj

set INPUT_PATHTOSCARESOLVER=C:\tools\CxSCAResolver
set INPUT_SCARESOLVERADDPARAMETERS=-s C:\2738\VulnerableDockerfile-main -n TestLocal -r C:\2738\zendphp\results-sca.json


:: --- Execute Scan ---
"C:\Program Files\nodejs\node.exe" target\index.js

popd    