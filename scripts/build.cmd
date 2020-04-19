pushd %~dp0..\CxScan\CxScanV20
call tsc
popd

pushd %~dp0..\CxScan\CxScanV19
call tsc
popd

pushd %~dp0..
del %~dp0..\*.vsix
call tfx extension create --manifest-globs vss-extension.json
popd