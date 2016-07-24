function CreateScanReport{
    [CmdletBinding()]
    param ($reportPath, $high, $medium, $low, $cxLink)

    $content = FormatScanResultContent $high $medium $low $cxLink

    $reportPath = [IO.Path]::Combine($reportPath, "scanReport.md");

    [IO.File]::WriteAllText($reportPath, $content)
    Write-Verbose "Produced a Checkmarx scan summary report at $reportPath"

    Write-Host "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Checkmarx Scan Results;]$reportPath"
}

function FormatScanResultContent{
    [CmdletBinding()]
    param ($high, $medium, $low, $cxLink)

    Write-Verbose "Formatting the scan result report"

    $template  = '<div style="padding:5px 0px">
                      <span>Vulnerabilities founded summary:</span>
                  </div>
                  <table border="0" style="border-top: 1px solid #eee;border-collapse: separate;border-spacing: 0 2px;">
                      <tr>
                          <td>
                              <span style="text-align: center; padding-right:20px;"><span style="background-color:red; padding-right:19px;">High:</span></span>
                          </td>
                          <td style="text-align: center;"><span style="padding:0px 2px">{0}</span></td>
                      </tr>
                      <tr>
                          <td>
                              <span style="text-align: center; padding-right:40px;"><span style="background-color:orange;">Medium:</span></span>
                          </td>
                          <td style="text-align: center;"><span style="padding:0px 2px">{1}</span></td>
                      </tr>
                      <tr>
                          <td>
                              <span style="text-align: center; padding-right:40px;"><span style="background-color:yellow; padding-right:23px;">Low:</span></span>
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
