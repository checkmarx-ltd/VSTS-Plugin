pushd %~dp0..\CxScan

call tsc

set INPUT_CheckmarxService=endpointId
set ENDPOINT_URL_endpointId=http://example.com
set ENDPOINT_AUTH_PARAMETER_endpointId_USERNAME=myusername
set ENDPOINT_AUTH_PARAMETER_endpointId_PASSWORD=mypassword
set BUILD_SOURCESDIRECTORY=c:\projectsToScan\MyProject
set INPUT_PROJECTNAME=VstsTest1
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

set INPUT_VULNERABILITYTHRESHOLD=true
set INPUT_HIGH=1
set INPUT_MEDIUM=1
set INPUT_LOW=1

node target\index.js

popd