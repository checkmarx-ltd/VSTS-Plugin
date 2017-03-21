[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $CheckmarxService,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $projectName,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $fullTeamName,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $preset,
    [String] $incScan,
    [String] $fsois,
    [String] $sourceFolder,
    [String] $folderExclusion,
    [String] $fileExtension,
    [String] $syncMode,
    [String] $vulnerabilityThreshold,
    [String] $high,
    [String] $medium,
    [String] $low,
    [String] $scanTimeout
)

import-module "Microsoft.TeamFoundation.DistributedTask.Task.Common"
import-module "Microsoft.TeamFoundation.DistributedTask.Task.Internal"
import-module "Microsoft.TeamFoundation.DistributedTask.Task.TestResults"

$ErrorActionPreference = "Stop"

[String]$srcRepoType = [String]$env:BUILD_REPOSITORY_PROVIDER
if($srcRepoType -Match 'git'){
    [String]$branchName = [String]$env:BUILD_SOURCEBRANCHNAME
    if(!([string]::IsNullOrEmpty($env:SYSTEM_ACCESSTOKEN))){
        $resource = "$($env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)$env:SYSTEM_TEAMPROJECTID/_apis/build/definitions/$($env:SYSTEM_DEFINITIONID)?api-version=2.0"
        Write-Host "Url for build definition: $resource"
        [String]$defaultBranch = "N/A"
        try {
            $response = Invoke-RestMethod -Uri $resource -Headers @{Authorization = "Bearer $env:SYSTEM_ACCESSTOKEN"}
            $defaultBranch = $response.repository.defaultBranch
            $defaultBranch = $defaultBranch.Substring($defaultBranch.LastIndexOf("/") + 1)

            Write-Host ("Default branch: '{0}', Current Branch: '{1}'" -f $defaultBranch, $branchName)

            if(!($branchName -Like $defaultBranch)){
                Write-Host "Default branch not equal to branch that source was push to."
                Write-Host "##vso[task.complete result=Skipped;]"
                Exit
            }
        } catch {
            $result = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($result)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();

            Write-Host "##vso[task.logissue type=error;]Fail to get default branch from server: " ,  $responseBody
            Write-Host "##vso[task.complete result=Failed;]DONE"
        }
    } Else {
        if(!($branchName -Like 'master')){
            Write-Host "Access to OAuth token is not given and not running on 'master' branch."
            Write-Host "##vso[task.complete result=Skipped;]"
            Exit
        }
    }
}

$reportPath = [String]$env:COMMON_TESTRESULTSDIRECTORY
$sourceLocation = [String]$env:BUILD_SOURCESDIRECTORY
$sourceLocation = $sourceLocation.trim()
Write-Host ("Source location: {0}" -f $sourceLocation)

$serviceEndpoint = Get-ServiceEndpoint -Context $distributedTaskContext -Name $CheckmarxService

if (!$serviceEndpoint){
    throw "Connected Service with name '$CheckmarxService' could not be found.  Ensure that this Connected Service was successfully provisioned using the services tab in the Admin UI."
}

$authScheme = $serviceEndpoint.Authorization.Scheme

if ($authScheme -ne 'UserNamePassword'){
	throw "The authorization scheme $authScheme is not supported for a CX server."
}

$serviceUrl = [string]$serviceEndpoint.Url  #Url to cx server
$user = [string]$serviceEndpoint.Authorization.Parameters.UserName  # cx user
$password = [string]$serviceEndpoint.Authorization.Parameters.Password # cx user pwd

write-host 'Entering CxScanner ......' -foregroundcolor "green"

$serviceUrl = $serviceUrl.TrimStart().TrimEnd()
$serviceUrl = $serviceUrl.Replace('CxWebClient', '').trim()
if ($serviceUrl.EndsWith('//')){
    $serviceUrl = $serviceUrl.Substring(0,$serviceUrl.Length -1)
}
if (-Not $serviceUrl.EndsWith('/')){
    $serviceUrl = $serviceUrl + '/'
}

$resolverUrlExtention = 'Cxwebinterface/CxWSResolver.asmx?wsdl'
$resolverUrl = $serviceUrl + $resolverUrlExtention

write-host "Connecting to Checkmarx at: $resolverUrl ....." -foregroundcolor "green"

$resolver = $null
try {
    $resolver = New-WebServiceProxy -Uri $resolverUrl -UseDefaultCredential
} catch {
    write-host "Could not resolve Checkmarx service URL. Service might be down or a wrong URL was supplied." -foregroundcolor "red"
    Write-Error $_.Exception
    Exit
}

if (!$resolver){
    write-host "Could not resolve service URL. Service might be down or a wrong URL was supplied." -foregroundcolor "red"
    Exit
}

$webServiceAddressObject = $resolver.GetWebServiceUrl('SDK' ,1)
$proxy = New-WebServiceProxy -Uri $webServiceAddressObject.ServiceURL -UseDefaultCredential #-Namespace CxSDK

if (!$proxy){
    write-host  "Could not find Checkmarx SDK service URL" -foregroundcolor "red"
    Exit
}

$namespace = $proxy.GetType().Namespace

$credentialsType = ($namespace + '.Credentials')
$credentials = New-Object ($credentialsType)
$credentials.User = $user
$credentials.Pass = $password

write-host  "Logging into Checkmarx...." -foregroundcolor "green"
$loginResponse = $proxy.Login($credentials, 1033)

. $PSScriptRoot/CxReport/CxReport.ps1

If(-Not $loginResponse.IsSuccesfull){
    write-host "An Error occurred while logging in: ", $loginResponse.ErrorMessage  -foregroundcolor "red"
    Write-Host "##vso[task.complete result=Failed;]DONE"
    Exit
}
Else{
	$sessionId = $loginResponse.SessionId

	#Init the parameters for Scan web nethod
    $CliScanArgsType = ($namespace + '.CliScanArgs')
    $CliScanArgs = New-Object ($CliScanArgsType)

    $ProjectSettingsType = ($namespace  + '.ProjectSettings')
    $CliScanArgs.PrjSettings =  New-Object ($ProjectSettingsType)

    $SourceCodeSettingsType = ($namespace  + '.SourceCodeSettings')
    $CliScanArgs.SrcCodeSettings = New-Object ($SourceCodeSettingsType)

    $LocalCodeContainerType = ($namespace  + '.LocalCodeContainer')
    $CliScanArgs.SrcCodeSettings.PackagedCode =  New-Object ($LocalCodeContainerType)

    $SourceFilterPatternsType = ($namespace  + '.SourceFilterPatterns')
    $CliScanArgs.SrcCodeSettings.SourceFilterLists =  New-Object ($SourceFilterPatternsType)
    $CliScanArgs.SrcCodeSettings.SourceFilterLists.ExcludeFilesPatterns = $null
    $CliScanArgs.SrcCodeSettings.SourceFilterLists.ExcludeFoldersPatterns = $null

	$CliScanArgs.IsPrivateScan = 0

    if([System.Convert]::ToBoolean($incScan)){
        $CliScanArgs.IsIncremental = 1
        if(!([string]::IsNullOrEmpty($fsois))){
            [Int]$fsois = [convert]::ToInt32($fsois, 10)
            write-host "todo: add scans count environment variable"
        }
    }

    $CliScanArgs.Comment = "Scan triggered by CxVSTS"
    $CliScanArgs.IgnoreScanWithUnchangedCode = 0
    $CliScanArgs.ClientOrigin = "SDK"

    $fullTeamName = $fullTeamName -replace ' ','#@!'
    $fullTeamName = $fullTeamName -replace '\\',' '
    $fullTeamName = $fullTeamName -replace '/',' '
    $fullTeamName = $fullTeamName -replace '(^\s+|\s+$)','' -replace '\s+','\\'
    $fullTeamName = $fullTeamName -replace '#@!',' '
    $fullTeamName = $fullTeamName -replace '\\\s+','\\'
    $fullTeamName = $fullTeamName -replace '\s+\\','\\'
    $fullTeamName = $fullTeamName -replace '\\+','\\'
    Write-Host ("Full team path: {0}" -f $fullTeamName)
	$CliScanArgs.PrjSettings.ProjectName = $fullTeamName + "\\" + $projectName

    Write-Host ("Preset name: {0}" -f $preset)
	$presetId
	switch ($preset){
        'Default 2014' {$presetId = 17}
        'Default' {$presetId = 7}
        'XS' {$presetId = 35}
        'Checkmarx Default' {$presetId = 36}
        'OWASP Mobile TOP 10 - 2016' {$presetId = 37}
        'JSSEC' {$presetId = 20}
        'Apple Secure Coding Guide' {$presetId = 19}
        'WordPress' {$presetId = 16}
        'OWASP TOP 10 - 2013' {$presetId = 15}
        'Mobile' {$presetId = 14}
        'High and Medium and Low' {$presetId = 13}
        'HIPAA' {$presetId = 12}
        'MISRA_CPP' {$presetId = 11}
        'MISRA_C' {$presetId = 10}
        'Android' {$presetId = 9}
        'SANS top 25' {$presetId = 8}
        'Empty preset' {$presetId = 6}
        'PCI' {$presetId = 5}
        'OWASP TOP 10 - 2010' {$presetId = 4}
        'High and Medium' {$presetId = 3}
        'Error handling' {$presetId = 2}
        'All' {$presetId = 1}
        }
    Write-Host ("PresetId: {0}" -f $presetId)

    $CliScanArgs.PrjSettings.PresetID = $presetId
    $CliScanArgs.PrjSettings.IsPublic = 1 # true
    $CliScanArgs.PrjSettings.Owner = $user

    $tempSourceLocation = $sourceLocation + 'Temp'
    if (Test-Path -Path $tempSourceLocation){
        Remove-Item $tempSourceLocation -force -recurse
    } else {
        mkdir $tempSourceLocation
    }

    $filesStr = ""
    $foldersStr = ""
    if(!([string]::IsNullOrEmpty($fileExtension))){
        $filesStr = $fileExtension
    }
    if(!([string]::IsNullOrEmpty($folderExclusion))){
        $foldersStr = $folderExclusion
    }
    [array]$files = $filesStr.Split(",") | Foreach-Object { $_.Trim() }
    $files = $files | Foreach-Object { if ($_.ToString().StartsWith('.')){ "*$_" } Else {"$_"} }
    [array]$foldersArr = $foldersStr.Split(",") | Foreach-Object { $_.Trim() }

    $zipfilename = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
    Add-Type -Assembly System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    [System.IO.Compression.ZipArchive] $arch = [System.IO.Compression.ZipFile]::Open($zipfilename,[System.IO.Compression.ZipArchiveMode]::Update)

    write-host "Zipping sources to $zipfilename" -foregroundcolor "green"
    Get-ChildItem $sourceLocation -Recurse -Exclude $files |
    Foreach-Object {
        $allowed = $true
        if(!(($foldersArr.Count -eq 1) -and ($foldersArr[0] -eq ""))){
            foreach ($folder in $foldersArr) {
                if ($_.FullName.Contains('\' + $folder) -or $_.FullName.Contains('\' + $folder + '\')) {
                    $allowed = $false
                    break
                }
            }
        }
        if ($allowed) {
            if(!(([IO.FileInfo]$_.FullName).Attributes -eq "Directory")){
                $loc = $_.FullName.Substring($sourceLocation.length + 1)
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($arch, $_.FullName, $loc, $compressionLevel)
            }
        }
    }
    $arch.Dispose()

    if(!(Test-Path -Path $zipfilename)){
        Write-Host "Zip file is empty: no source to scan"
        Write-Host "##vso[task.complete result=Skipped;]"
        Exit
    } Else {
        write-host "Zipped sources to $zipfilename" -foregroundcolor "green"
        $CliScanArgs.SrcCodeSettings.PackagedCode.ZippedFile = [System.IO.File]::ReadAllBytes($zipfilename)
        $CliScanArgs.SrcCodeSettings.PackagedCode.FileName = $zipfilename
    }

    [System.IO.File]::Delete($zipfilename)

    write-host "Starting Checkmarx scan..." -foregroundcolor "green"

    $scanResponse = $null
    try {
        $scanResponse = $proxy.Scan($sessionId,$CliScanArgs)
    } catch {
        write-host "Fail to init Checkmarx scan." -foregroundcolor "red"
        Write-Host "##vso[task.logissue type=error;]An error occurred while scanning."
        Write-Host "##vso[task.complete result=Failed;]DONE"
        Exit
    }

    If(-Not $scanResponse.IsSuccesfull)	{
		Write-Host "##vso[task.logissue type=error;]An error occurred while scanning: " ,  $scanResponse.ErrorMessage
        Write-Host "##vso[task.complete result=Failed;]DONE"
    }
    Else {
        if([System.Convert]::ToBoolean($syncMode)){
		    $scanStatusResponse = $proxy.GetStatusOfSingleScan($sessionId,$scanResponse.RunId)

		    If(-Not $scanResponse.IsSuccesfull) {
			    write-host  "Scan failed : " ,  $scanResponse.ErrorMessage  -foregroundcolor "red"
            } Else {
                while($scanStatusResponse.IsSuccesfull -ne 0 -and
                $scanStatusResponse.CurrentStatus -ne "Finished"  -and
                $scanStatusResponse.CurrentStatus -ne "Failed"  -and
                $scanStatusResponse.CurrentStatus -ne "Canceled"  -and
                $scanStatusResponse.CurrentStatus -ne "Deleted"
                ) {
                    write-host ("Scan status is : {0}, {1}%" -f $scanStatusResponse.CurrentStatus, $scanStatusResponse.TotalPercent) -foregroundcolor "green"
                    $scanStatusResponse = $proxy.GetStatusOfSingleScan($sessionId,$scanResponse.RunId)
                    Start-Sleep -s 10 # wait 10 seconds
                }

                If($scanStatusResponse.IsSuccesfull -ne 0 -and $scanStatusResponse.CurrentStatus -ne "Finished") {
                    Write-Host "##vso[task.logissue type=error;]Scan failed: " ,  $scanStatusResponse.ErrorMessage
                    Write-Host "##vso[task.complete result=Failed;]DONE"
                }
                Else {
                    [String]$scanId = $scanStatusResponse.ScanId
                    [String]$projectID = $scanResponse.ProjectID

                    $scanSummary = $proxy.GetScanSummary($sessionId,$scanId)
                    $resHigh = $scanSummary.High
                    $resMedium = $scanSummary.Medium
                    $resLow = $scanSummary.Low
                    Write-Host ("High Risk: {0}" -f $resHigh) -foregroundcolor "green"
                    Write-Host ("Medium Risk: {0}" -f $resMedium) -foregroundcolor "green"
                    Write-Host ("Low Risk: {0}" -f $resLow) -foregroundcolor "green"

                    $cxLink = ("{0}CxWebClient/ViewerMain.aspx?scanId={1}&ProjectID={2}" -f $serviceUrl, $scanId, $projectID)
                    Write-Host ("View scan results at {0}" -f $cxLink) -foregroundcolor "green"

                    CreateScanReport $reportPath $resHigh $resMedium $resLow $cxLink

                    [bool]$thresholdExceeded=$false
                    if([System.Convert]::ToBoolean($vulnerabilityThreshold)){
                        if([string]::IsNullOrEmpty($high)){
                            Write-Host "High threshold is not set."
                        } else {
                            [Int]$highNum = [convert]::ToInt32($high, 10)
                            [Int]$resHigh = [convert]::ToInt32($resHigh, 10)
                            if($resHigh -gt $highNum){
                                Write-Host  ("##vso[task.logissue type=error;]Threshold for high result exceeded. Threshold:  {0} , Detected: {1}" -f $highNum, $resHigh)
                                $thresholdExceeded=$true
                            }
                        }
                        if([string]::IsNullOrEmpty($medium)){
                             Write-Host "Medium threshold is not set."
                        } else {
                            [Int]$mediumNum = [convert]::ToInt32($medium, 10)
                            [Int]$resMedium = [convert]::ToInt32($resMedium, 10)
                            if($resMedium -gt $mediumNum){
                                Write-Host  ("##vso[task.logissue type=error;]Threshold for medium result exceeded. Threshold:  {0} , Detected: {1}" -f $mediumNum, $resMedium)
                                $thresholdExceeded=$true
                            }
                        }
                        if([string]::IsNullOrEmpty($low)){
                             Write-Host "Low threshold is not set."
                        } else {
                            [Int]$lowNum = [convert]::ToInt32($low, 10)
                            [Int]$resLow = [convert]::ToInt32($resLow, 10)
                            if($resLow -gt $lowNum){
                                Write-Host  ("##vso[task.logissue type=error;]Threshold for low result exceeded. Threshold:  {0} , Detected: {1}" -f $lowNum, $resLow)
                                $thresholdExceeded=$true
                            }
                        }
                        if($thresholdExceeded){
                            Write-Host "##vso[task.complete result=Failed;]DONE"
                        }
                    }
                }
            }
		}
    }

write-host "Logging out....." -foregroundcolor "green"

$loginResponse = $proxy.Logout($sessionId)
}

function IsIncRun{
    [CmdletBinding()]
    param ([Int]$fsois)

    [string]$fileName = "fullScanCount.txt"
    $contentTemplate = "autoFullScan: {0}, curRun: {1}"

    if(!(Test-Path $fileName)){
        New-Item $fileName -type file -value ($contentTemplate -f $fsois, 0) | Out-Null
    }
    $content = Get-Content $fileName

    [Int]$start = [convert]::ToInt32($content.IndexOf(":"), 10) + 1
    [Int]$end = [convert]::ToInt32($content.IndexOf(","), 10)
    $autoFullScan = $content.Substring($start, $end - $start).trim()
    [Int]$autoFullScan = [convert]::ToInt32($autoFullScan, 10)
    write-host ("autoFullScan: {0}" -f $autoFullScan)

    $curRun = $content.Substring($content.LastIndexOf(":") + 1).trim()
    [Int]$curRun = [convert]::ToInt32($curRun, 10) + 1
    write-host ("curRun: {0}" -f $curRun)

    if($fsois -ne $autoFullScan){
        [Int]$autoFullScan = $fsois
    }
    set-content $fileName ($contentTemplate -f $autoFullScan, $curRun)

    if($curRun -ge $autoFullScan){
        set-content $fileName ($contentTemplate -f $autoFullScan, 0)
      return $true;
    }
    return $false;
}