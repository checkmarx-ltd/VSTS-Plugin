pushd %~dp0..
del *.vsix
REM tsc
call tfx extension create --manifest-globs vss-extension.json
REM tfx extension publish --share-with Checkmarx --token x6msals6q6s7joqejd3od63xadccjfa374p5br7moorlmlhgwyra
popd