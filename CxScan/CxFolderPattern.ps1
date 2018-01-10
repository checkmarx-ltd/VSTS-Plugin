function  ProcessExcludedFolders($folderExclusions) {
        if ( [string]::IsNullOrEmpty($folderExclusions)) {
            return "";
        }
        $result = "";
        [array]$patterns =  $folderExclusions.split(",")| Foreach-Object {
                                                            if( !([string]::IsNullOrEmpty($_))){
                                                                $result += "!**/" + $_.Trim() + "/**,"

                                                            }

        $result = $result.Substring(0 ,$result.LastIndexOf(","));                                                 }
        Write-Host ("Exclude folders converted to: {0}" -f $result);
        return $result;
  }


  function ProcessExcludedFiles($fileExclusions) {
    $pattern = "";
    $result = "";

    $fileExclusions.split(",")| Foreach-Object {
                                if( -not ([string]::IsNullOrEmpty($_.Trim()))){
                                    $pattern+= $_.Trim()
                                    $pattern +=","
                                }
                            }


    $pattern = $pattern.Substring(0 ,$pattern.LastIndexOf(","));
    $pattern.Split(",") | Foreach-Object {$result += $_.Replace("*", "**/*");
                                          $result +=","}
    $result = $result.Substring(0 ,$result.LastIndexOf(","));
    Write-Host ("Excluded files converted to: {0}" -f $result);

    return $result
  }


function GeneratePattern($folderExclusions, $filterPattern)
{
    $excludeFoldersPattern = ProcessExcludedFolders $folderExclusions;

    if ([string]::IsNullOrEmpty($filterPattern) -and [string]::IsNullOrEmpty($excludeFoldersPattern)) {
        return "";
    } Elseif ((-not [string]::IsNullOrEmpty($filterPattern)) -and [string]::IsNullOrEmpty($excludeFoldersPattern))
    {
        return $filterPattern;
    }
    elseif  ([string]::IsNullOrEmpty($filterPattern) -and  -not  [string]::IsNullOrEmpty($excludeFoldersPattern))
     {
        return $excludeFoldersPattern;
    } else {
        return $filterPattern + "," + $excludeFoldersPattern;
    }
}