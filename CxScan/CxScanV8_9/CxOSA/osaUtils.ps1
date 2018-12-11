function writeToOsaListToTemp($osaDependenciesJson, $tempDir) {
        try {
        $filePath = Join-Path $tempDir $"CxOSAFileList.json"
        New-Item -ItemType File $filePath
        $osaDependenciesJson | Out-File -filepath $filePath 
        Write-Host "OSA file list saved to file: [$filePath ]";

        } catch {
            Write-Host "Failed to write OSA file list to temp directory:  $_.Exception.Message";
        }

    }


function printOSAResultsToConsole($scanResults, $osaLink, $osaPolicies) {

    Write-Host "----------------------------Checkmarx Scan Results(CxOSA):-------------------------------";
    Write-Host ""
    Write-Host "------------------------"
    Write-Host "Vulnerabilities Summary:"
    Write-Host "------------------------"
    Write-Host "OSA high severity results: " $scanResults.totalHighVulnerabilities;
    Write-Host "OSA medium severity results: " $scanResults.totalMediumVulnerabilities;
    Write-Host "OSA low severity results: " $scanResults.totalLowVulnerabilities;
    Write-Host "Vulnerability score: " $scanResults.vulnerabilityScore;
    Write-Host "";
    Write-Host "-----------------------";
    Write-Host "Libraries Scan Results:";
    Write-Host "-----------------------";
    Write-Host "Open-source libraries: " $scanResults.totalLibraries;
    Write-Host "Vulnerable and outdated: " $scanResults.vulnerableAndOutdated;
    Write-Host "Vulnerable and updated:  " $scanResults.vulnerableAndUpdated;
    Write-Host "Non-vulnerable libraries: " $scanResults.nonVulnerableLibraries;
    Write-Host "";
    if ($config.enablePolicyViolations) {
        if ($osaPolicies.Count -eq 0){
            Write-Host "Project policy status: compliant";
        }else{
            Write-Host("Project policy status: violated");

            $policies =   $osaPolicies -join ", "
            Write-Host("OSA violated policies names: {0} " -f  $policies);
        }
    }
    Write-Host ""
    Write-Host "OSA scan results location: " $osaLink;
    Write-Host "-----------------------------------------------------------------------------------------";
}

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


function generatePattern($folderExclusions, $filterPattern)
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

function AddOSAResults($scanResults, $osaLink, $osaSummaryResultsm,  $osaLibraries, $osaCVE, $osaScanStatus){
    $scanResults.osaFailed = $false;
    $scanResults | Add-Member -MemberType NoteProperty -Name osaStartTime -Value $osaScanStatus.startAnalyzeTime
    $scanResults | Add-Member -MemberType NoteProperty -Name osaEndTime -Value $osaScanStatus.endAnalyzeTime

    $scanResults | Add-Member -MemberType NoteProperty -Name osaHighResults -Value $osaSummaryResults.totalHighVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name osaMediumResults -Value $osaSummaryResults.totalMediumVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name osaLowResults -Value $osaSummaryResults.totalLowVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name osaSummaryResultsLink -Value $osaLink

    $osaTotalVulnerableLibs = $osaSummaryResults.highVulnerabilityLibraries + $osaSummaryResults.mediumVulnerabilityLibraries + $osaSummaryResults.lowVulnerabilityLibraries

    $scanResults | Add-Member -MemberType NoteProperty -Name osaVulnerableLibraries -Value $osaTotalVulnerableLibs
    $scanResults | Add-Member -MemberType NoteProperty -Name osaOkLibraries -Value $osaSummaryResults.nonVulnerableLibraries
    $scanResults | Add-Member -MemberType NoteProperty -Name osaCveList -Value $osaCVE 
    $scanResults | Add-Member -MemberType NoteProperty -Name osaLibraries -Value $osaLibraries

    return $scanResults
}

function  AddOsaViolation($violation, $policyName, $scanResults)
{   $osaViolation = New-Object System.Object;
    $osaViolation | Add-Member -MemberType NoteProperty -Name libraryName -Value $violation.source
    $osaViolation | Add-Member -MemberType NoteProperty -Name policyName -Value $policyName
    $osaViolation | Add-Member -MemberType NoteProperty -Name ruleName -Value $violation.ruleName

    $date = ([datetime]$violation.firstDetectionDateByArm).ToShortDateString()
    $osaViolation | Add-Member -MemberType NoteProperty -Name detectionDate -Value $date
    ($scanResults.osaViolations.Add($osaViolation)) | Out-Null

    return $scanResults;
}

