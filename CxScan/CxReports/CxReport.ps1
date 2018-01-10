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
        ##vso[task.uploadfile]c:\additionalfile.log
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
           Write-Warning "Fail to get status from scan report: " + $scanReportStatus.ErrorMessage;
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
        Write-Error "Fail to create scan report: "  $createScanReportResponse.ErrorMessage;
        #throw new CxClientException"Fail to retrieve scan report: "  $createScanReportResponse.ErrorMessage;
    }

    return $scanReport.ScanResults;
}

function CreateSummaryReport{
    [CmdletBinding()]
    param ($reportPath, $scanResults, $thresholdExceeded, $osaThresholdExceeded)

    $content = FormatScanResultContent $scanResults.highResults  $scanResults.mediumResults $scanResults.lowResults  $scanResults.sastSummaryResultsLink $thresholdExceeded $scanResults.osaEnabled $scanResults.osaFailed.ToString() $scanResults.osaHighResults $scanResults.osaMediumResults $scanResults.osaLowResults $scanResults.osaSummaryResultsLink $osaThresholdExceeded

    $reportPath = [IO.Path]::Combine($reportPath, "scanReport.html");
    Write-Host $reportPath
    [IO.File]::WriteAllText($reportPath, $content)
    Write-Host "Produced a Checkmarx scan summary report at $reportPath"
    Write-Host "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Checkmarx Scan Results;]$reportPath"
}

function FormatScanResultContent{
    [CmdletBinding()]
    param (
     $high,
     $medium,
     $low,
     $cxLink,
     $thresholdExceeded,
     $osaEnabled,
     $osaFailed,
     $osaHigh,
     $osaMedium,
     $osaLow,
     $cxOsaLink,
     $osaThresholdExceeded
    )

    Write-Host "Formatting scan summary report" #todo

    $templateSAST  ='<div style="padding:5px 0px">
                      <span>CxSAST Vulnerabilities Summary:</span>
                  </div>
                  <table border="0" style="border-top: 1px solid #eee;border-collapse: separate;border-spacing: 0 2px;">
                      <tr>
                          <td>
                              <span style="text-align: center; padding-right:20px;"><span style="background-color:red; padding-right:19px;">CxSAST High</span></span>
                          </td>
                          <td style="text-align: center;"><span style="padding:0px 2px">{0}</span></td>
                      </tr>
                      <tr>
                          <td>
                              <span style="text-align: center; padding-right:40px;"><span style="background-color:orange;">CxSAST Medium</span></span>
                          </td>
                          <td style="text-align: center;"><span style="padding:0px 2px">{1}</span></td>
                      </tr>
                      <tr>
                          <td>
                              <span style="text-align: center; padding-right:40px;"><span style="background-color:yellow; padding-right:23px;">CxSAST Low</span></span>
                          </td>
                          <td style="text-align: center;"><span style="padding:0px 2px">{2}</span></td>
                      </tr>
                  </table>
                  <div style="padding: 10px 0px">
                      <a target="_blank" href="{3}">Detailed Checkmarx Report &gt;</a>
                  </div>'

     $SASTemplate  ='<div class="cx-report" id="vss_1" style="margin-right: 35px; margin-left: 35px;">
                           <div id="results-report" class="results-report" style="">
                               <div class="summary-section" style="padding-top: 34px;padding-bottom: 25px;">
                                   <div class="sast-summary" id="sast-summary" style="margin-right: 6%;width: 380px;">
                                       <div class="summary-report-title sast" style="font-size: 24px;font-weight: 400;padding-bottom: 21px;color: #373050;">
                                           <div class="summary-title-text sast" style="white-space: nowrap;font-weight: bold;">CxSAST Vulnerabilities Status</div>
                                           <div class="summary-title-links" style="color: #4A90E2;font-size: 14px;padding: 15px 2px;border-bottom: solid 1px #d5d5d5;">
                                               <a class="html-report" id="sast-summary-html-link" href="{0}">
                                                   <div class="results-link summary-link" style="align-items: center;">
                                                       <div class="summary-link-text" style=" padding: 0 8px;">Results</div>
                                                   </div>
                                               </a>
                                           </div>
                                       </div>
                                       <div class="summary-chart">
                                           <div class="threshold-exceeded-compliance" id="threshold-exceeded-compliance"><div class="threshold-exceeded" style="font-size: 14px; padding: 4px 9px;background-color: {1};width: 160px;color: white;border-radius: 2px;font-weight: bold;"><div class="threshold-exceeded-icon" style="padding-right: 6px;margin: auto 0;"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="12px" height="12px" viewBox="0 0 12 12" version="1.1"><defs></defs><g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd"><g id="Icons" transform="translate(-52.000000, -241.000000)"><g id="threshhold-icon" transform="translate(52.000000, 241.000000)"><g><path d="M8.0904685,3 L7.0904685,3 L7.0904685,5 L8.0904685,5 L8.0904685,11 L3.0904685,11 L3.0904685,0 L8.0904685,0 L8.0904685,3 Z M3.0904685,3 L3.0904685,5 L5.0904685,5 L5.0904685,3 L3.0904685,3 Z M5.0904685,3 L5.0904685,5 L7.0904685,5 L7.0904685,3 L5.0904685,3 Z" id="Combined-Shape" fill="#FFFFFF"></path><path d="M10.5904685,11.5 L0.590468498,11.5" id="Line" stroke="#FFFFFF" stroke-linecap="square"></path></g></g></g></g></svg></div><div class="threshold-exceeded-text">{2}</div></div></div>
                                           <div class="chart" style=" table-layout: fixed;width: 100%;height: 240px;margin-top: 0;padding: 0;background-image: linear-gradient(to top, #d5d5d5, #ffffff 2%);background-size: 100% 70px;background-position: left bottom;border-bottom: solid #979797 2px;">
                                               <div style="height: 200px;">
                                                    <div class="bar-wrapper" style="padding-top: 56%">
                                                    </div>
                                                   <div class="bar-1" id="bar-high" style="position: absolute;width: 6%;height:{3};background-color: #373050;margin-left: 5%;"></div>
                                                   <div class="bar-title-container" style="width: 6%;margin-left: 5%;padding-top: 4%;text-align: center;word-wrap: break-word;color: #444444;">
                                                       <div class="bar-title-icon" style=" margin-right: 6px;"></div>
                                                       <div class="bar-title" style="background-color: #DA2945;width: 48px;font-size: 14px;white-space: nowrap;">High -</div>
                                                       <div class="bar-count" style="background-color: #DA2945;width: 48px;" id="bar-count-high">{4}</div>
                                                   </div>
                                                   <div class="bar-2" id="bar-med" style="width:  6%;height:{5};background-color: #373050;margin-left: 45%;margin-top: -38%;"></div>
                                                   <div class="bar-title-container" style="width: 6%;margin-left: 45%;padding-top: 4%;text-align: center;word-wrap: break-word;color: #444444;">
                                                       <div class="bar-title-icon" style=" margin-right: 6px;">                                                                           </div>
                                                       <div class="bar-title" style="background-color: #ee9142;width: 65px;font-size: 14px;white-space: nowrap;">Medium -</div>
                                                       <div class="bar-count" style="background-color: #ee9142;width: 65px;" id="bar-count-med">{6}</div>
                                                   </div>
                                                   <div class="bar-3" id="bar-low" style="width: 6%;height:{7};background-color: #373050;margin-left: 80%;margin-top: -60%;"></div>
                                                   <div class="bar-title-container" style="width: 6%;margin-left: 78%;padding-top: 4%;text-align: center;word-wrap: break-word;color: #444444;">
                                                   <div class="bar-title-icon" style=" margin-right: 6px;"></div>
                                                       <div class="bar-title" style="background-color: #eeda4ad9;width: 66px;font-size: 14px;white-space: nowrap;">Low -</div>
                                                       <div class="bar-count" style="background-color: #eeda4ad9;width: 66px;" id="bar-count-low">{8}</div>
                                                   </div>
                                               </div>
                                           </div>
                                       </div>
                                   </div>
                            </div>
                            <div id="end-div"></div>
                         </div>
                       </div>'




    $OSASASTemplate  ='<div class="cx-report" id="vss_1" style="margin-right: 35px; margin-left: 35px;">
                          <div id="results-report" class="results-report" style="">
                              <div class="summary-section" style="padding-top: 34px;padding-bottom: 25px;">
                                  <div class="sast-summary" id="sast-summary" style="margin-right: 6%;width: 380px;">
                                      <div class="summary-report-title sast" style="font-size: 24px;font-weight: 400;padding-bottom: 21px;color: #373050;">
                                          <div class="summary-title-text sast" style="white-space: nowrap;font-weight: bold;">CxSAST Vulnerabilities Status</div>
                                          <div class="summary-title-links" style="color: #4A90E2;font-size: 14px;padding: 15px 2px;border-bottom: solid 1px #d5d5d5;">
                                              <a class="html-report" id="sast-summary-html-link" href="{0}">
                                                  <div class="results-link summary-link" style="align-items: center;">
                                                      <div class="summary-link-text" style=" padding: 0 8px;">Results</div>
                                                  </div>
                                              </a>
                                          </div>
                                      </div>
                                      <div class="summary-chart">
                                          <div class="threshold-exceeded-compliance" id="threshold-exceeded-compliance"><div class="threshold-exceeded" style="font-size: 14px; padding: 4px 9px;background-color: {1};width: 160px;color: white;border-radius: 2px;font-weight: bold;"><div class="threshold-exceeded-icon" style="padding-right: 6px;margin: auto 0;"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="12px" height="12px" viewBox="0 0 12 12" version="1.1"><defs></defs><g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd"><g id="Icons" transform="translate(-52.000000, -241.000000)"><g id="threshhold-icon" transform="translate(52.000000, 241.000000)"><g><path d="M8.0904685,3 L7.0904685,3 L7.0904685,5 L8.0904685,5 L8.0904685,11 L3.0904685,11 L3.0904685,0 L8.0904685,0 L8.0904685,3 Z M3.0904685,3 L3.0904685,5 L5.0904685,5 L5.0904685,3 L3.0904685,3 Z M5.0904685,3 L5.0904685,5 L7.0904685,5 L7.0904685,3 L5.0904685,3 Z" id="Combined-Shape" fill="#FFFFFF"></path><path d="M10.5904685,11.5 L0.590468498,11.5" id="Line" stroke="#FFFFFF" stroke-linecap="square"></path></g></g></g></g></svg></div><div class="threshold-exceeded-text">{2}</div></div></div>
                                          <div class="chart" style=" table-layout: fixed;width: 100%;height: 240px;margin-top: 0;padding: 0;background-image: linear-gradient(to top, #d5d5d5, #ffffff 2%);background-size: 100% 70px;background-position: left bottom;border-bottom: solid #979797 2px;">
                                              <div style="height: 200px;">
                                                   <div class="bar-wrapper" style="padding-top: 56%">
                                                   </div>
                                                  <div class="bar-1" id="bar-high" style="position: absolute;width: 6%;height:{3};background-color: #373050;margin-left: 12%;"></div>
                                                  <div class="bar-title-container" style="width: 6%;margin-left: 10%;padding-top: 15px;text-align: center;word-wrap: break-word;color: #444444;">
                                                      <div class="bar-title-icon" style=" margin-right: 6px;">                                                                           </div>
                                                      <div class="bar-title" style="background-color: #DA2945;width: 48px;font-size: 14px;white-space: nowrap;">High -</div>
                                                      <div class="bar-count" style="background-color: #DA2945;width: 48px;" id="bar-count-high">{4}</div>
                                                  </div>
                                                  <div class="bar-2" id="bar-med" style="width:  6%;height:{5};background-color: #373050;margin-left: 40%;margin-top: -38%;"></div>
                                                  <div class="bar-title-container" style="width: 6%;margin-left: 37%;padding-top: 15px;text-align: center;word-wrap: break-word;color: #444444;">
                                                      <div class="bar-title-icon" style=" margin-right: 6px;">                                                                           </div>
                                                      <div class="bar-title" style="background-color: #ee9142;width: 65px;font-size: 14px;white-space: nowrap;">Medium -</div>
                                                      <div class="bar-count" style="background-color: #ee9142;width: 65px;" id="bar-count-med">{6}</div>
                                                  </div>
                                                  <div class="bar-3" id="bar-low" style="width: 6%;height:{7};background-color: #373050;margin-left: 75%;margin-top: -60%;"></div>
                                                  <div class="bar-title-container" style="width: 6%;margin-left: 70%;padding-top: 15px;text-align: center;word-wrap: break-word;color: #444444;">
                                                  <div class="bar-title-icon" style=" margin-right: 6px;"></div>
                                                      <div class="bar-title" style="background-color: #eeda4a;width: 66px;font-size: 14px;white-space: nowrap;">Low -</div>
                                                      <div class="bar-count" style="background-color: #eeda4a;width: 66px;" id="bar-count-low">{8}</div>
                                                  </div>
                                              </div>
                                          </div>
                                      </div>
                                  </div>
                                   <div class="osa-summary" id="osa-summary" style="margin-right: 6%;width: 380px;margin-left: 74%;margin-top: -372px;">
                                        <div class="summary-report-title osa" style="font-size: 24px;font-weight: 400;padding-bottom: 21px;color: #373050;">
                                            <div class="summary-title-text osa" style="white-space: nowrap;font-weight: bold;">CxOSA Vulnerabilities & Libraries</div>
                                            <div class="summary-title-links" style="color: #4A90E2;font-size: 14px;padding: 15px 2px;border-bottom: solid 1px #d5d5d5;">
                                                <a class="html-report" id="osa-summary-html-link" href="{9}">
                                                    <div class="results-link summary-link" style="align-items: center;">
                                                        <div class="results-link-icon link-icon"></div>
                                                        <div class="summary-link-text" style=" padding: 0 8px;">Results</div>
                                                    </div>
                                                </a>
                                            </div>
                                        </div>
                                        <div class="osa-results">
                                            <div class="osa-libraries"></div>
                                            <div class="osa-chart">
                                                <div class="threshold-exceeded-compliance" id="threshold-exceeded-compliance"><div class="threshold-exceeded" style="font-size: 14px; padding: 4px 9px;background-color: {10};width: 160px;color: white;border-radius: 2px;font-weight: bold;"><div class="threshold-exceeded-icon" style="padding-right: 6px;margin: auto 0;"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="12px" height="12px" viewBox="0 0 12 12" version="1.1"><defs></defs><g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd"><g id="Icons" transform="translate(-52.000000, -241.000000)"><g id="threshhold-icon" transform="translate(52.000000, 241.000000)"><g><path d="M8.0904685,3 L7.0904685,3 L7.0904685,5 L8.0904685,5 L8.0904685,11 L3.0904685,11 L3.0904685,0 L8.0904685,0 L8.0904685,3 Z M3.0904685,3 L3.0904685,5 L5.0904685,5 L5.0904685,3 L3.0904685,3 Z M5.0904685,3 L5.0904685,5 L7.0904685,5 L7.0904685,3 L5.0904685,3 Z" id="Combined-Shape" fill="#FFFFFF"></path><path d="M10.5904685,11.5 L0.590468498,11.5" id="Line" stroke="#FFFFFF" stroke-linecap="square"></path></g></g></g></g></svg></div><div class="threshold-exceeded-text">{11}</div></div></div>
                                                <div class="osa-chart chart" style=" table-layout: fixed;width: 100%;height: 240px;margin-top: 0;padding: 0;background-image: linear-gradient(to top, #d5d5d5, #ffffff 2%);background-size: 100% 70px;background-position: left bottom;border-bottom: solid #979797 2px;">
                                                    <div style="height: 200px;">
                                                         <div class="bar-wrapper" style="padding-top: 56%">
                                                         </div>
                                                        <div class="bar-1" id="osa-bar-high" style="position: absolute;width: 6%;height:{12};background-color: #373050;margin-left: 14%;"></div>
                                                        <div class="bar-title-container" style="width: 6%;margin-left: 12%;padding-top: 15px;text-align: center;word-wrap: break-word;color: #444444;">
                                                            <div class="bar-title-icon" style=" margin-right: 6px;"></div>
                                                            <div class="bar-title" style="background-color: #DA2945;width: 48px;font-size: 14px;white-space: nowrap;">High -</div>
                                                            <div class="bar-count" style="background-color: #DA2945;width: 48px;" id="osa-bar-count-high">{13}</div>
                                                        </div>
                                                        <div class="bar-2" id="osa-bar-med" style="position: absolute;width:  6%;height:{14};background-color: #373050;margin-left: 45%;margin-top: -33%;"></div>
                                                        <div class="bar-title-container" style="width: 6%;margin-left: 40%;padding-top: 15px;text-align: center;word-wrap: break-word;color: #444444;">
                                                            <div class="bar-title-icon" style=" margin-right: 6px;"></div>
                                                            <div class="bar-title" style="background-color: #ee9142;width: 65px;font-size: 14px;white-space: nowrap;">Medium -</div>
                                                            <div class="bar-count" style="background-color: #ee9142;width: 65px;" id="osa-bar-count-med">{15}</div>
                                                        </div>
                                                        <div class="bar-3" id="osa-bar-low" style="width: 6%;height:{16};background-color: #373050;margin-left: 75%;margin-top: -60%;"></div>
                                                        <div class="bar-title-container" style="width: 6%;margin-left: 70%;padding-top: 15px;text-align: center;word-wrap: break-word;color: #444444;">
                                                        <div class="bar-title-icon" style=" margin-right: 6px;"></div>
                                                            <div class="bar-title" style="background-color: #eeda4a;width: 66px;font-size: 14px;white-space: nowrap;">Low -</div>
                                                            <div class="bar-count" style="background-color: #eeda4a;width: 66px;" id="osa-bar-count-low">{17}</div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                            </div>
                            <div id="end-div"></div>
                        </div>
                      </div>'


    $content ="";

    $maxCount =[math]::max($high, [math]::max( $medium, $low ));
    $maxHeight = $maxCount * 100 / 90;
    $highHeight = ($high * 100 / $maxHeight).ToString() + "%";
    $medHeight = ($medium * 100 / $maxHeight).ToString() + "%";
    $lowHeight = ($low * 100 / $maxHeight).ToString() + "%";

    $thresholdColor = "#21bf3f" #green
    if ($thresholdExceeded -eq "true"){
       $threshold = "Threshold Exceeded";
       $thresholdColor = "#DA2945" #red
    } else{
        $threshold = "Threshold Compliant";
    }

    if($osaEnabled -eq "true" -and  $osaFailed -ne "true"){
        $osaThresholdColor = "#21bf3f" #green
        $osaMaxCount =[math]::max($osaHigh, [math]::max($osaMedium, $osaLow));
        $osaMaxHeight = $osaMaxCount * 100 / 90
        $osaHighHeight = ($osaHigh * 100 / $osaMaxHeight).ToString() + "%";
        $osaMedHeight = ($osaHigh * 100 / $osaMaxHeight).ToString() + "%";
        $osaLowHeight = ($osaHigh * 100 / $osaMaxHeight).ToString() + "%";

        if ($osaThresholdExceeded -eq "true"){
              $osaThreshold = "Threshold Exceeded";
              $osaThresholdColor = "#DA2945" #red
        } else{
          $osaThreshold = "Threshold Compliant";
        }
        $content = [String]::Format($OSASASTemplate, $cxLink, $thresholdColor, $threshold, $highHeight, $high, $medHeight, $medium, $lowHeight, $low, $cxOsaLink, $osaThresholdColor, $osaThreshold, $osaHighHeight, $osaHigh, $osaMedHeight, $osaMedium, $osaLowHeight, $osaLow)

   }else{
     $content = [String]::Format($SASTemplate, $cxLink, $thresholdColor, $threshold, $highHeight, $high, $medHeight, $medium, $lowHeight, $low)
   }
    return $content;
}






