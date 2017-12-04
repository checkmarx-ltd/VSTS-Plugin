$generateReportTimeOutInSec = 500;
$PDF_REPORT_NAME = "CxSASTReport";
$CX_REPORT_LOCATION = Join-Path -Path "Checkmarx" -ChildPath "Reports";

function createPDFReport($scanId){
    Write-Host  "Generating PDF report";

    Try{
    $ReportFolder = "CxReports"
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


         #  $RiskReport = [PSCUSTOMOBJECT]@{
          #      projectName = $HubProjectName
           #     projectLink = ("{0}/#projects/id:{1}" -f $HubUrl, $ProjectVersion[5])
            #    projectVersion = $HubRelease
             #   projectVersionLink = ("{0}/#versions/id:{1}" -f $HubUrl, $ProjectVersion[7])
              #  totalCount = $TotalCount
               # components = $Components
           # }

        $scanReport = createReport $scanId "PDF";
        $now = [DateTime]::Now.ToString("yyyyMMddHHmmss")
        $pdfFileName = $PDF_REPORT_NAME + "_" + $now + ".pdf";

        #$pdfPath=  [io.path]::combine($workspace, $CX_REPORT_LOCATION, $pdfFileName)
       # $pdfPath=  Join-Path  $workspace1 $pdfFileName
        $pdfPath=  [io.path]::combine($workspace, $pdfFileName)
        [io.file]::WriteAllBytes($pdfPath,$scanReport)


        Write-Host "PDF report location: " $pdfPath;
      #   $RiskReportFile = Join-Path $BuildLogFolder $RiskReportFilename
    #    $RiskReport | ConvertTo-Json -Compress | Out-File $RiskReportFile

    #    Write-Host "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Checkmarx Scan Results;]$pdfPath"
        Write-Host "##vso[task.addattachment type=cxRiskReport;name=riskReport;]$pdfPath"
        ##vso[task.uploadfile]c:\additionalfile.log
        Write-Host ("INFO: File at {0}" -f $pdfPath)
    }
    Catch {
        write-Error "Fail to generate PDF report: " $_.Exception.Message
    }
}

function setScanDetailedReport($xdoc, $scanResults) {
    $scanResults | Add-Member -MemberType NoteProperty -Name scanStartDate -Value $xdoc.CxXMLResults.ScanStart
    $scanResults | Add-Member -MemberType NoteProperty -Name scanTime -Value $xdoc.CxXMLResults.ScanTime;
    $scanResults | Add-Member -MemberType NoteProperty -Name linesOfCodeScanned -Value $xdoc.CxXMLResults.LinesOfCodeScanned;
    $scanResults | Add-Member -MemberType NoteProperty -Name filesScanned -Value $xdoc.CxXMLResults.FilesScanned;
    $scanResults | Add-Member -MemberType NoteProperty -Name queryList -Value @()

    #  foreach ($query in $xdoc.CxXMLResults.Query){
     #     $scanResults.queryList.Add($query)
     #}

    return $scanResults
}

function resolveXMLReport($scanResults, $cxReport){

    $cxReporetStr = [System.Text.Encoding]::UTF8.GetString($cxReport);
    $cxReporetStr =  $cxReporetStr.Substring($cxReporetStr.IndexOf("<CxXMLResults") );
    #$cxReporetString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cxReport))
    # Create file:
    $tmpXMLPath =  [System.IO.Path]::GetTempPath() + "tmpFile.xml"
    $cxReporetStr >>  $tmpXMLPath
    $xdoc = new-object System.Xml.XmlDocument
    $xmlFile = resolve-path($tmpXMLPath)
    $xdoc.load($xmlFile)
    [xml] $xdoc = get-content $tmpXMLPath
    $scanResults = setScanDetailedReport $xdoc $scanResults;
    [System.IO.File]::Delete($tmpXMLPath)

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
           Write-Warning "Fail to get status from scan report: " + $scanReportStatus.ErrorMessage;
        }

        if ($scanReportStatus.IsFailed) {
           # throw new CxClientException("Generation of scan report [id=" + reportId + "] failed");
            Write-Error "Generation of scan report [id=" + $reportId + "] failed";
        }

        if ($scanReportStatus.IsReady) {
        Write-Host "Scan Report Is Ready :)"
            return;
        }
    }

    if ($scanReportStatus -eq $null -Or -Not $scanReportStatus.IsReady) {
       # throw new CxClientException("Generation of scan report [id=" + reportId + "] failed. Timed out");
       Write-Error "Generation of scan report [id=" + reportId + "] failed. Timed out";
    }
}

function createReport($scanId, $type){
    $cxWSReportRequestType = ($namespace + '.cxWSReportRequest')
    $cxWSReportRequest = New-Object ($cxWSReportRequestType)
    $cxWSReportRequest.Type= $type;
    $cxWSReportRequest.ScanID= $scanId;

    $createScanReportResponse = $proxy.CreateScanReport($sessionId, $cxWSReportRequest);

    if (-Not $createScanReportResponse.IsSuccesfull) {

        Write-Error ("Failed to parse files exclusions: {0}" -f  $createScanReportResponse.ErrorMessage)
        Exit
        #throw new CxClientException("Fail to create scan report: " + createScanReportResponse.getErrorMessage());
    }

    $reportId = $createScanReportResponse.ID;
    waitForReport $reportId $type;
    $scanReport = $proxy.GetScanReport($sessionId, $reportId);

    if (-Not $scanReport.IsSuccesfull) {
        Write-Error "Fail to create scan report: "  $createScanReportResponse.ErrorMessage;
        #throw new CxClientException"Fail to retrieve scan report: "  $createScanReportResponse.ErrorMessage;
    }

    return $scanReport.ScanResults;
}


function FormatScanResultContent{
    [CmdletBinding()]
    param ($high, $medium, $low, $cxLink)

    Write-Verbose "Formatting the scan result report"

    $template  = '<div style="padding:5px 0px">
                      <span>Vulnerabilities Summary:</span>
                  </div>
                  <table border="0" style="border-top: 1px solid #eee;border-collapse: separate;border-spacing: 0 2px;">
                      <tr>
                          <td>
                              <span style="text-align: center; padding-right:20px;"><span style="background-color:red; padding-right:19px;">High</span></span>
                          </td>
                          <td style="text-align: center;"><span style="padding:0px 2px">{0}</span></td>
                      </tr>
                      <tr>
                          <td>
                              <span style="text-align: center; padding-right:40px;"><span style="background-color:orange;">Medium</span></span>
                          </td>
                          <td style="text-align: center;"><span style="padding:0px 2px">{1}</span></td>
                      </tr>
                      <tr>
                          <td>
                              <span style="text-align: center; padding-right:40px;"><span style="background-color:yellow; padding-right:23px;">Low</span></span>
                          </td>
                          <td style="text-align: center;"><span style="padding:0px 2px">{2}</span></td>
                      </tr>
                  </table>
                  <div style="padding: 10px 0px">
                      <a target="_blank" href="{3}">Detailed Checkmarx Report &gt;</a>
                  </div>'

    $content = [String]::Format($template, $high, $medium, $low, $cxLink)
    return $content
}
