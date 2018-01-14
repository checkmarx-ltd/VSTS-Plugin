$generateReportTimeOutInSec = 500;
$REPORT_NAME = "CxSASTReport";

$CX_REPORT_LOCATION = Join-Path -Path "Checkmarx" -ChildPath "Report";

function CreatePDFReport($scanId){
    Write-Host  "Generating PDF report";
    Try{
        $ReportFolder = "CxReport"
        $HubScannerLogsLocation = Join-path $env:AGENT_HOMEDIRECTORY $ReportFolder
        if (!(Test-Path($HubScannerLogsLocation))) {
            Write-Host ("INFO: Create CxReport folder at: {0}" -f $HubScannerLogsLocation)
            New-Item -ItemType directory -Path $HubScannerLogsLocation | Out-Null
        }
        $BuildLogFolder =[System.IO.Path]::Combine($HubScannerLogsLocation, $env:BUILD_DEFINITIONNAME, $env:BUILD_BUILDNUMBER)
        if (!(Test-Path($BuildLogFolder))) {
            Write-Host ("INFO: Create build specific Hub logs folder at: {0}" -f $BuildLogFolder)
            New-Item -ItemType directory -Path $BuildLogFolder | Out-Null
        }
        $workspace = [System.IO.Path]::GetTempPath()
        #$reportPath = [String]$env:COMMON_TESTRESULTSDIRECTORY'
        #$workspace = [String]$env:BUILD_ARTIFACTSTAGINGDIRECTORY



        $scanReport = createReport $scanId "PDF";
        $now = [DateTime]::Now.ToString("yyyyMMddHHmmss")
        $pdfFileName = $REPORT_NAME + "_" + $now + ".pdf";
        #$pdfPath=  [io.path]::combine($workspace, $CX_REPORT_LOCATION, $pdfFileName)
        # $pdfPath=  Join-Path  $workspace1 $pdfFileName
        $pdfPath=  [io.path]::combine($workspace, $pdfFileName)
        [io.file]::WriteAllBytes($pdfPath,$scanReport)


        Write-Host "PDF report location: " $pdfPath;
        #   $RiskReportFile = Join-Path $BuildLogFolder $RiskReportFilename
        #    $RiskReport | ConvertTo-Json -Compress | Out-File $RiskReportFile

        #    Write-Host "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Checkmarx Scan Results;]$pdfPath"
        Write-Host "##vso[task.addattachment type=cxReport;name=cxReport;]$pdfPath"
        Write-Host ("INFO: File at {0}" -f $pdfPath)
    }
    Catch {
        write-Error "Fail to generate PDF report: " $_.Exception.Message
    }
}

function SetScanDetailedReport($xdoc, $scanResults) {
    $jsonQuery=""

    ForEach($query In $xdoc.CxXMLResults.Query) {
        $jsonQuery +=  @{name=$query.name;severity= $query.Severity;resultLength=$query.Result.Length} | ConvertTo-Json -Compress
        $jsonQuery+=";";
    }

    $scanResults | Add-Member -MemberType NoteProperty -Name scanStart -Value $xdoc.CxXMLResults.ScanStart
    $scanResults | Add-Member -MemberType NoteProperty -Name scanTime -Value $xdoc.CxXMLResults.ScanTime;
    $scanResults | Add-Member -MemberType NoteProperty -Name locScanned -Value $xdoc.CxXMLResults.LinesOfCodeScanned;
    $scanResults | Add-Member -MemberType NoteProperty -Name queryList -Value $jsonQuery;
    $scanResults | Add-Member -MemberType NoteProperty -Name filesScanned -Value $xdoc.CxXMLResults.FilesScanned;

    return $scanResults
}

function ResolveXMLReport($scanResults, $cxReport){

    $cxReporetStr = [System.Text.Encoding]::UTF8.GetString($cxReport);
    $cxReporetStr =  $cxReporetStr.Substring($cxReporetStr.IndexOf("<CxXMLResults") );

    # Create file:
    $now = [DateTime]::Now.ToString("yyyyMMddHHmmss")
    $tmpXMLPath =  [System.IO.Path]::GetTempPath() +  $REPORT_NAME + "_" + $now + ".xml";
    $cxReporetStr >>  $tmpXMLPath
    $xdoc = new-object System.Xml.XmlDocument
    $xmlFile = resolve-path($tmpXMLPath)
    $xdoc.load($xmlFile)
    [xml] $xdoc = get-content $tmpXMLPath
    $scanResults = SetScanDetailedReport $xdoc $scanResults;

    #Delete Temp File
    try{
       [System.IO.File]::Delete($tmpXMLPath);
    } catch {
        Write-Host ("An error occurred while deleting temp report file: {0}" -f  $_.Exception.Message)
    }

    return $scanResults
}

function waitForReport($reportId, $reportType){
    $timeToStop =  [DateTime]::Now.AddSeconds($generateReportTimeOutInSec);
    $scanReportStatus = $null;
    while ([DateTime]::Now -le  $timeToStop) {
        $timeLeft = $timeToStop.Subtract([DateTime]::Now).ToString().Split('.')[0]
        Write-Host ("Waiting for server to generate {0} report. {1} sec left to timeout" -f $reportType, $timeLeft);
        Start-Sleep -s 10; #Get status every 10 sec

        $scanReportStatus = $proxy.GetScanReportStatus($sessionId, $reportId);

        if (-Not $scanReportStatus.IsSuccesfull) {
           Write-Warning ("Fail to get status from scan report: {0}" -f $scanReportStatus.ErrorMessage);
        }

        if ($scanReportStatus.IsFailed) {
           # throw new CxClientException("Generation of scan report [id=" + reportId + "] failed");
            Write-Error "Generation of scan report [id="  $reportId  "] failed";
        }

        if ($scanReportStatus.IsReady) {
            Write-Host $reportType "Scan Report Is Ready"  #todo
            return;
        }
    }

    if ($scanReportStatus -eq $null -Or -Not $scanReportStatus.IsReady) {
       Write-Error "Generation of scan report [id=" reportId  "] failed. Timed out";
    }
}

function createReport($scanId, $type){
    $cxWSReportRequestType = ($namespace + '.cxWSReportRequest')
    $cxWSReportRequest = New-Object ($cxWSReportRequestType)
    $cxWSReportRequest.Type= $type;
    $cxWSReportRequest.ScanID= $scanId;

    $createScanReportResponse = $proxy.CreateScanReport($sessionId, $cxWSReportRequest);

    if (-Not $createScanReportResponse.IsSuccesfull) {
        Write-Error ("Fail to create scan report: {0}" -f  $createScanReportResponse.ErrorMessage)
        Exit
    }

    $reportId = $createScanReportResponse.ID;
    waitForReport $reportId $type;
    $scanReport = $proxy.GetScanReport($sessionId, $reportId);

    if (-Not $scanReport.IsSuccesfull) {
        Write-Error "Failed to retrieve scan report: "  $createScanReportResponse.ErrorMessage;
        #throw new CxClientException"Fail to retrieve scan report: "  $createScanReportResponse.ErrorMessage;
    }

    return $scanReport.ScanResults;
}



