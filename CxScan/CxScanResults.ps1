function InitScanResults($scanResults, $scan){
    $scanResults | Add-Member -MemberType NoteProperty -Name sastResultsReady -Value $true;
    $scanResults | Add-Member -MemberType NoteProperty -Name projectId -Value $scan.ProjectID
    $scanResults | Add-Member -MemberType NoteProperty -Name scanID -Value $scan.LastScanID
    $scanResults | Add-Member -MemberType NoteProperty -Name highResults -Value $scan.HighVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name mediumResults -Value $scan.MediumVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name lowResults -Value $scan.LowVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name infoResults -Value $scan.InfoVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name riskLevel -Value $scan.RiskLevelScore

    return $scanResults
}




function AddSASTResults($syncMode, $vulnerabilityThreshold, $high, $medium, $low, $summaryLink, $resultLink, $osaEnabled, $projectScannedList, $projectID){
    $scanResults = New-Object System.Object

    $scanResults | Add-Member -MemberType NoteProperty -Name syncMode -Value $syncMode
    $scanResults | Add-Member -MemberType NoteProperty -Name thresholdEnabled -Value $vulnerabilityThreshold
    if([System.Convert]::ToBoolean($vulnerabilityThreshold)){
        $scanResults | Add-Member -MemberType NoteProperty -Name highThreshold -Value $high
        $scanResults | Add-Member -MemberType NoteProperty -Name mediumThreshold -Value $medium
        $scanResults | Add-Member -MemberType NoteProperty -Name lowThreshold -Value $low
    }
    $scanResults | Add-Member -MemberType NoteProperty -Name sastSummaryResultsLink -Value $summaryLink
    $scanResults | Add-Member -MemberType NoteProperty -Name sastScanResultsLink -Value $resultLink
    $scanResults | Add-Member -MemberType NoteProperty -Name osaEnabled -Value $osaEnabled
    $scanList = @($projectScannedList)
    foreach ($scan in $scanList) {
        if ($projectID -eq $scan.ProjectID) {
            $scanResults = InitScanResults $scanResults $scan
        }
    }

    return $scanResults
}

function AddOSAResults($scanResults, $osaSummaryResults, $osaProjectSummaryLink, $osaVulnerabilityThreshold, $osaHigh, $osaMedium, $osaLow){
    $scanResults | Add-Member -MemberType NoteProperty -Name osaStartTime -Value $osaSummaryResults.osaStartTime
    $scanResults | Add-Member -MemberType NoteProperty -Name osaEndTime -Value $osaSummaryResults.osaEndTime

    $scanResults | Add-Member -MemberType NoteProperty -Name osaHighResults -Value $osaSummaryResults.totalHighVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name osaMediumResults -Value $osaSummaryResults.totalMediumVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name osaLowResults -Value $osaSummaryResults.totalLowVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name osaSummaryResultsLink -Value $osaProjectSummaryLink

    $osaTotalVulnerableLibs = $osaSummaryResults.highVulnerabilityLibraries + $osaSummaryResults.mediumVulnerabilityLibraries + $osaSummaryResults.lowVulnerabilityLibraries

    $scanResults | Add-Member -MemberType NoteProperty -Name osaVulnerableLibraries -Value $osaTotalVulnerableLibs
    $scanResults | Add-Member -MemberType NoteProperty -Name osaOkLibraries -Value $osaSummaryResults.nonVulnerableLibraries
    $scanResults | Add-Member -MemberType NoteProperty -Name osaThresholdEnabled -Value $osaVulnerabilityThreshold
    $scanResults | Add-Member -MemberType NoteProperty -Name osaHighThreshold -Value $osaHigh
    $scanResults | Add-Member -MemberType NoteProperty -Name osaMediumThreshold -Value $osaMedium
    $scanResults | Add-Member -MemberType NoteProperty -Name osaLowThreshold -Value $osaLow
    $scanResults | Add-Member -MemberType NoteProperty -Name osaCveList -Value $osaSummaryResults.osaCveList
    $scanResults | Add-Member -MemberType NoteProperty -Name osaLibraries -Value $osaSummaryResults.osaLibraries

    return $scanResults
}