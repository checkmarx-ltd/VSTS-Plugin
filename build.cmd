del *.vsix
#tsc
tfx extension create --bypass-validation --manifest-globs vss-extension.json
#tfx extension publish --share-with Checkmarx --token <TOKEN>
echo | pause
