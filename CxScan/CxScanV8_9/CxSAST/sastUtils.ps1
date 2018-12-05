$newHighCount = 0;
$newMediumCount = 0;
$newLowCount = 0;
$newInfoCount = 0;

function addSASTResults($results, $scanResults){
    $scanResults | Add-Member -MemberType NoteProperty -Name highResults -Value $results.highSeverity;
    $scanResults | Add-Member -MemberType NoteProperty -Name mediumResults -Value $results.mediumSeverity;
    $scanResults | Add-Member -MemberType NoteProperty -Name lowResults -Value $results.lowSeverity;
    $scanResults | Add-Member -MemberType NoteProperty -Name infoResults -Value $results.infoSeverity;

    $sastScanLink = ("{0}/CxWebClient/ViewerMain.aspx?scanId={1}&ProjectID={2}" -f $config.url, $scanResults.scanId, $config.projectId);
    $scanResults | Add-Member -MemberType NoteProperty -Name sastScanResultsLink -Value $sastScanLink

    $sastProjectLink = ("{0}/CxWebClient/portal#/projectState/{1}/Summary" -f $config.url, $config.projectId);
    $scanResults | Add-Member -MemberType NoteProperty -Name sastSummaryResultsLink -Value $sastProjectLink;
   
    $scanResults.sastResultsReady = $true;

    return $scanResults;
}

function setScanDetailedReport($reportObj,  $scanResults){   
    $XMLResults = $reportObj.CxXMLResults

    $jsonQuery=""
    ForEach($query In $xdoc.CxXMLResults.Query) {
        $jsonQuery +=  @{name=$query.name;severity= $query.Severity;resultLength=$query.Result.Length} | ConvertTo-Json -Compress
        $jsonQuery+=";";
    }

    $scanResults | Add-Member -MemberType NoteProperty -Name scanStart -Value $XMLResults.scanStart;
    $scanResults | Add-Member -MemberType NoteProperty -Name scanTime -Value $XMLResults.scanTime;
    $scanResults | Add-Member -MemberType NoteProperty -Name locScanned -Value $XMLResults.linesOfCodeScanned;
    $scanResults | Add-Member -MemberType NoteProperty -Name filesScanned -Value $XMLResults.filesScanned;
    $scanResults | Add-Member -MemberType NoteProperty -Name riskLevel -Value $XMLResults.RiskLevelScore
    $scanResults | Add-Member -MemberType NoteProperty -Name projectId -Value $XMLResults.ProjectId

        foreach ($query in $XMLResults.Query) {
            $qResult = $query.result;
            For ($i=0; $i -le $qResult.count; $i++) {
                $result = $qResult[$i];
                if ("True".equals($result.falsePositive)) {
                    $qResult.remove($i);
                } elseif ("New".equals($result.status)){
                     switch ($result.severity )
                    {
                        High {$newHighCount++}
                        Medium {$newMediumCount++}
                        Low {$newLowCount++}
                        Info{$newInfoCount++}
                    }
                }
            }
        }
        $scanResults | Add-Member -MemberType NoteProperty -Name newHighCount -Value $newHighCount;
        $scanResults | Add-Member -MemberType NoteProperty -Name newMediumCount -Value $newMediumCount;
        $scanResults | Add-Member -MemberType NoteProperty -Name newLowCount -Value $newLowCount;
        $scanResults | Add-Member -MemberType NoteProperty -Name newInfoCount -Value $newInfoCount;
        $scanResults | Add-Member -MemberType NoteProperty -Name queryList -Value $jsonQuery;

        return $scanResults;
}


function printResultsToConsole($scanResults) {
    Write-Host "----------------------------Checkmarx Scan Results(CxSAST):-------------------------------";
    Write-Host "High severity results: " $scanResults.highResults;
    Write-Host "Medium severity results: " $scanResults.mediumResults;
    Write-Host "Low severity results: " $scanResults.lowResults;
    Write-Host "Info severity results: " $scanResults.infoResults;
    Write-Host "";
    Write-Host "Scan results location: " $scanResults.sastScanResultsLink;
    Write-Host "------------------------------------------------------------------------------------------\n";
}