del *.vsix
#tsc
tfx extension create --manifest-globs vss-extension.json
#tfx extension publish --share-with Checkmarx --token ***REMOVED***
echo | pause
