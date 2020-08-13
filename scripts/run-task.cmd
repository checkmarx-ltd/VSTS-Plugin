pushd %~dp0..\CxScan\CxScanV20

call tsc

set INPUT_CheckmarxService=endpointId
set ENDPOINT_URL_endpointId=http://10.32.4.137
set ENDPOINT_AUTH_PARAMETER_endpointId_USERNAME=***REMOVED***
set ENDPOINT_AUTH_PARAMETER_endpointId_PASSWORD=***REMOVED***
set BUILD_SOURCESDIRECTORY=C:\Checkmarx\powershellPlugin
set INPUT_ENABLESASTSCAN=false
set INPUT_PROJECTNAME=newOne12
set INPUT_FULLTEAMNAME=\CxServer
set INPUT_DENYPROJECT=false
set INPUT_INCSCAN=true
set INPUT_COMMENT=Greetings from TypeScript
set ENDPOINT_AUTH_SCHEME_endpointId=UsernamePassword
set BUILD_DEFINITIONNAME=builddef
set BUILD_BUILDNUMBER=23
set INPUT_SYNCMODE=true
set INPUT_ENABLEPOLICYVIOLATIONS=true
set INPUT_PRESET=Checkmarx Default

set INPUT_VULNERABILITYTHRESHOLD=false
set INPUT_HIGH=1
set INPUT_MEDIUM=1
set INPUT_LOW=1
set ENDPOINT

set INPUT_ENABLEDEPENDENCYSCAN=true
set INPUT_dependencyServerURL=endpointIdSCA
set ENDPOINT_URL_endpointIdSCA=https://api.scacheckmarx.com
set ENDPOINT_AUTH_PARAMETER_endpointIdSCA_USERNAME=***REMOVED***
set ENDPOINT_AUTH_PARAMETER_endpointIdSCA_PASSWORD=***REMOVED***
set ENDPOINT_AUTH_SCHEME_endpointIdSCA=UsernamePassword
set INPUT_DEPENDENCYACCESSCONTROLURL=https://platform.checkmarx.net
set INPUT_DEPENDENCYWEBAPPURL=https://sca.scacheckmarx.com/
set INPUT_DEPENDENCYTENANT=plugins
set Endpoint
node target\index.js

popd