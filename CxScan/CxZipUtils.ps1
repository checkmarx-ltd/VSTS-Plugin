function CheckFile($dir, $exFolders){
  $bool = $true
  foreach ($folder in $exFolders){

    if ($dir -like [IO.Path]::Combine('*', $folder,'*')){
        $bool = $false
     }
   }

   return $bool;
}


function ZipSource($folderExclusion, $fileExtension, $sourceLocation){

   $filesStr = ""
   $foldersStr = ""

    if(!([string]::IsNullOrEmpty($fileExtension))){
        $filesStr = $fileExtension
    }
    if(!([string]::IsNullOrEmpty($folderExclusion))){
        $foldersStr = $folderExclusion
    }
    try{
        [array]$exFiles = $filesStr.Split(",") | Foreach-Object { if( !([string]::IsNullOrEmpty($_))){ $_.Trim() }}
        $exFiles = $exFiles | Foreach-Object { if (!([string]::IsNullOrEmpty($_)) -and  $_.ToString().StartsWith('.')){ "*$_" } Else {"$_"} }
     }  catch {
       write-host ("Failed to parse files exclusions: {0}" -f $_.Exception.Message)
      [array]$exFiles = @();
     }
    try{
         [array]$exFolders = $foldersStr.Split(",") | Foreach-Object{ if( !([string]::IsNullOrEmpty($_))){ $_.Trim()}}
    } catch {
       write-host ("Failed to parse folder exclusions: {0}" -f $_.Exception.Message)
      [array]$exFolders = @();
    }

    $zipfilename = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
    Add-Type -Assembly System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    [System.IO.Compression.ZipArchive] $arch = [System.IO.Compression.ZipFile]::Open($zipfilename,[System.IO.Compression.ZipArchiveMode]::Update)

     
    write-host "Zipping sources to $zipfilename" -foregroundcolor "green"
    Get-ChildItem $sourceLocation -Recurse -Exclude $exFiles |      
    Foreach-Object {      
        if(!(([IO.FileInfo]$_.FullName).Attributes -eq "Directory") -and (CheckFile $_.FullName $exFolders) ){         
            $loc = $_.FullName.Substring($sourceLocation.length + 1)
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($arch, $_.FullName, $loc, $compressionLevel) | Out-Null
         }
        
    }
    $arch.Dispose()

    return $zipfilename
}
