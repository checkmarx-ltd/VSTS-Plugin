function ResolveVal($val){
   if (-Not $val){
         return  "none"  ;
       }else{
         return $val;
       }
 }

 function ResolveString($val){

     if (-not ([string]::IsNullOrEmpty($val))){
         return $val;
     }else{
          return "none"
      }
 }


function ResolveServiceURL($serviceUrl){
    $serviceUrl = $serviceUrl.TrimStart().TrimEnd()
    $serviceUrl = $serviceUrl.Replace('CxWebClient', '').trim()
    if ($serviceUrl.EndsWith('//')){
        $serviceUrl = $serviceUrl.Substring(0,$serviceUrl.Length -1)
    }
    if (-Not $serviceUrl.EndsWith('/')){
        $serviceUrl = $serviceUrl + '/'
    }
    return $serviceUrl
}

function DeleteFile($fileName){
    try{
        [System.IO.File]::Delete($fileName)
    } catch {
        Write-Host ("An error occurred while deleting temp zip file: {0}. Error: {1}" -f $fileName, $_.Exception.Message)
    }
}

 function PrintScanResults($scanResults){

     $resHigh = $scanResults.highResults
     $resMedium = $scanResults.mediumResults
     $resLow = $scanResults.lowResults
     $resInfo = $scanResults.infoResults
     $cxLink = $scanResults.sastSummaryResultsLink

     Write-Host " "
     Write-Host "-----------------------Checkmarx Scan Results(CxSAST):------------------------"
     Write-Host ("High severity results: {0}" -f $resHigh)
     Write-Host ("Medium severity results: {0}" -f $resMedium)
     Write-Host ("Low severity results: {0}" -f $resLow)
     Write-Host ("Info severity results: {0}" -f $resInfo)
     Write-Host ""
     Write-Host ("Scan results location: {0}" -f $cxLink)
     Write-Host "------------------------------------------------------------------------------";
 }


    function PrintOSAResults($osaSummaryResults, $osaProjectSummaryLink) {
        Write-Host("-----------------------Checkmarx Scan Results(CxOSA):-------------------------");
        Write-Host("");
        Write-Host("------------------------");
        Write-Host("Vulnerabilities Summary ");
        Write-Host("------------------------");
        Write-Host("OSA high severity results: {0}" -f $osaSummaryResults.totalHighVulnerabilities);
        Write-Host("OSA medium severity results: {0}" -f $osaSummaryResults.totalMediumVulnerabilities);
        Write-Host("OSA low severity results: {0}" -f $osaSummaryResults.totalLowVulnerabilities);
        Write-Host("Vulnerability score: {0}" -f $osaSummaryResults.vulnerabilityScore);
        Write-Host("");
        Write-Host("-----------------------");
        Write-Host("Libraries Scan Results ");
        Write-Host("-----------------------");
        Write-Host("Open-source libraries: {0}" -f $osaSummaryResults.totalLibraries);
        Write-Host("Vulnerable and outdated: {0}" -f $osaSummaryResults.vulnerableAndOutdated);
        Write-Host("Vulnerable and updated: {0}" -f $osaSummaryResults.vulnerableAndUpdated);
        Write-Host("Non-vulnerable libraries: {0}" -f $osaSummaryResults.nonVulnerableLibraries);
        Write-Host("");
        Write-Host("OSA scan results location: {0}" -f $osaProjectSummaryLink);
        Write-Host("------------------------------------------------------------------------------");
    }

    function IsSASTThresholdExceeded($scanResults){
        $scanType = "CxSAST"
        $highExceeded = isLevelThresholdExceeded $scanResults.highResults $scanResults.highThreshold "high" $scanType ;
        $mediumExceeded = isLevelThresholdExceeded $scanResults.mediumResults $scanResults.mediumThreshold "medium" $scanType ;
        $lowExceeded = isLevelThresholdExceeded $scanResults.lowResults $scanResults.lowThreshold "low" $scanType ;
        return ($highExceeded -or $mediumExceeded -or $lowExceeded)
    }

     function IsOSAThresholdExceeded($scanResults){
        $scanType = "CxOSA"
        $highExceeded = IsLevelThresholdExceeded $scanResults.osaHighResults $scanResults.osaHighThreshold "high" $scanType ;
        $mediumExceeded = IsLevelThresholdExceeded $scanResults.osaMediumResults $scanResults.osaMediumThreshold "medium" $scanType ;
        $lowExceeded = IsLevelThresholdExceeded $scanResults.osaLowResults $scanResults.osaLowThreshold "low" $scanType ;
        return ($highExceeded -or $mediumExceeded -or $lowExceeded)
     }

    function IsLevelThresholdExceeded($result, $threshold, $severity, $scanType){
       if(-Not [string]::IsNullOrEmpty($threshold)){
            [Int]$thresholdNum = [convert]::ToInt32($threshold, 10)
            [Int]$resultNum = [convert]::ToInt32($result, 10)
            if($resultNum -gt $thresholdNum){
                Write-Host  ("##vso[task.logissue type=error;]{0} {1} severity results are above threshold. Results: {2}. Threshold: {3}" -f $scanType, $severity, $resultNum, $thresholdNum)
			   return $true
            }
        }
        return $false;
    }







