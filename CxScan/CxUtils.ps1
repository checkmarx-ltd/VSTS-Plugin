function resolveVal($val){
   if (-Not $val){
         return  "none"  ;
       }else{
         return $val;
       }
 }

 function resolveString($val){

     if (-not ([string]::IsNullOrEmpty($val))){
         return $val;
     }else{
          return "none"
      }
 }


 function printScanResults($scanResults){

     $resHigh = $scanResults.highResults
     $resMedium = $scanResults.mediumResults
     $resLow = $scanResults.lowResults
     $resInfo = $scanResults.infoResults
     $cxLink = $scanResults.sastSummaryResultsLink

     Write-Host " "
     Write-Host "----------------------Checkmarx Scan Results(CxSAST):-------------------------";
     Write-Host ("High severity results: {0}" -f $resHigh)
     Write-Host ("Medium severity results: {0}" -f $resMedium)
     Write-Host ("Low severity results: {0}" -f $resLow)
     Write-Host ("Info severity results: {0}" -f $resInfo)
     Write-Host ""
     Write-Host ("Scan results location: {0}" -f $cxLink)
     Write-Host "------------------------------------------------------------------------------";
     Write-Host " "

 }
