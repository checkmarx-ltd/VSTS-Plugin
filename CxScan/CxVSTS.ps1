[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $CheckmarxService,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $projectName,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $fullTeamName,
    $presetList,
    [String] $customPreset,
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


Write-Host "                                       "
Write-Host
          "         CxCxCxCxCxCxCxCxCxCxCxCx           `n" +
          "        CxCxCxCxCxCxCxCxCxCxCxCxCx`         `n" +
          "       CxCxCxCxCxCxCxCxCxCxCxCxCxCx`        `n" +
          "      CxCxCx                CxCxCxCx        `n" +
          "      CxCxCx                CxCxCxCx`       `n" +
          "      CxCxCx  CxCxCx      CxCxCxCxC         `n" +
          "      CxCxCx  xCxCxCx  .CxCxCxCxCx          `n" +
          "      CxCxCx   xCxCxCxCxCxCxCxCx            `n"  +
          "      CxCxCx    xCxCxCxCxCxCx               `n"  +
          "      CxCxCx     CxCxCxCxCx   CxCxCx        `n"  +
          "      CxCxCx       xCxCxC     CxCxCx        `n"  +
          "      CxCxCx                 CxCxCx         `n"  +
          "       CxCxCxCxCxCxCxCxCxCxCxCxCxCx         `n"  +
          "        CxCxCxCxCxCxCxCxCxCxCxCxCx          `n"  +
          "          CxCxCxCxCxCxCxCxCxCxCx            `n"  +
          "                                            `n" +
          "            C H E C K M A R X               `n"
Write-Host "                                               "







Write-Host "Starting Checkmarx scan"
$presetName;
$serviceEndpoint = Get-ServiceEndpoint -Context $distributedTaskContext -Name $CheckmarxService

if (!$serviceEndpoint){
    throw "Connected Service with name '$CheckmarxService' could not be found.  Ensure that this Connected Service was successfully provisioned using the services tab in the Admin UI."
}
$authScheme = $serviceEndpoint.Authorization.Scheme
if ($authScheme -ne 'UserNamePassword'){
	throw "The authorization scheme $authScheme is not supported for a CX server."
}

$agentProxy = [string]$serviceEndpoint.Authorization.Parameters.agentProxy


[String]$srcRepoType = [String]$env:BUILD_REPOSITORY_PROVIDER
if($srcRepoType -Match 'git'){
    [String]$branchName = [String]$env:BUILD_SOURCEBRANCHNAME
    if(!([string]::IsNullOrEmpty($env:SYSTEM_ACCESSTOKEN))){
        $resource = "$($env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)$env:SYSTEM_TEAMPROJECTID/_apis/build/definitions/$($env:SYSTEM_DEFINITIONID)?api-version=2.0"
        Write-Host "URL for build definition: $resource"
        [String]$defaultBranch = ""
        Try {
            $response;
            if([string]::IsNullOrEmpty($agentProxy)){
                $response = Invoke-RestMethod -Uri $resource -Headers @{Authorization = "Bearer $env:SYSTEM_ACCESSTOKEN"}
            } else {
                $response = Invoke-RestMethod -Uri $resource -Proxy $proxy -Headers @{Authorization = "Bearer $env:SYSTEM_ACCESSTOKEN"}
            }

            Try {
                $defaultBranch = $response.repository.defaultBranch
            } Catch {
                Write-Host "Fail to get default branch on first attempt"
            }
            if([string]::IsNullOrEmpty($defaultBranch)){
                Try {
                    $defaultBranch = $response.defaultBranch
                } Catch {
                    Write-Host ("##vso[task.logissue type=error;]Fail to read default branch from: {0}" -f $resource)
                    Exit
                }
            }

            $defaultBranch = $defaultBranch.Substring($defaultBranch.LastIndexOf("/") + 1)
            Write-Host ("Default branch: '{0}', Current Branch: '{1}'" -f $defaultBranch, $branchName)

            if(!($branchName -Like $defaultBranch)){
                Write-Host "Default branch not equal to branch that source was push to."
                Write-Host "##vso[task.complete result=Skipped;]"
                Exit
            }
        } Catch {
            Write-Host ("##vso[task.logissue type=error;]Fail to get default branch from server: {0}" -f $_.Exception.Message)
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


$ErrorActionPreference = "Stop"

$reportPath = [String]$env:COMMON_TESTRESULTSDIRECTORY
$sourceLocation = [String]$env:BUILD_SOURCESDIRECTORY
$sourceLocation = $sourceLocation.trim()



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

$resolverUrlExtension = 'Cxwebinterface/CxWSResolver.asmx?wsdl'
$resolverUrl = $serviceUrl + $resolverUrlExtension


. $PSScriptRoot/CxUtils.ps1
    Write-Host " "
    Write-Host "-------------------------------Configurations:--------------------------------";

    Write-Host ("URL: {0}" -f $serviceUrl)
    Write-Host ("Agent proxy: {0}" -f $(ResolveString $agentProxy))
    Write-Host ("Project name: {0}" -f $projectName)
    Write-Host ("Source location: {0}" -f $sourceLocation)
    Write-Host ("Scan timeout in minutes: {0}" -f $(ResolveString $scanTimeout))
    Write-Host ("Full team path: {0}" -f $fullTeamName)
    if (-not ([string]::IsNullOrEmpty($customPreset))){
      Write-Host ("Custom preset name: {0}" -f $customPreset)
    }else{
      Write-Host ("Preset name: {0}" -f $presetList)
    }

    Write-Host ("Is incremental scan: {0}" -f $(ResolveBool $incScan))
    Write-Host ("Folder exclusions: {0}" -f $( ResolveVal $folderExclusion))
    Write-Host ("File exclusions: {0}" -f $(ResolveVal $fileExtension))
    Write-Host ("Is synchronous scan: {0}" -f $(ResolveBool $syncMode))

    Write-Host ("CxSAST thresholds enabled: {0}" -f $vulnerabilityThreshold)
    if ($vulnerabilityThreshold -eq "True") {
     Write-Host ("CxSAST high threshold: {0}" -f $high)
     Write-Host ("CxSAST medium threshold: {0}" -f $medium)
     Write-Host ("CxSAST low threshold: {0}" -f $low)
    }
    Write-Host "------------------------------------------------------------------------------";
    Write-Host " "


$serviceUrl = $serviceUrl.TrimStart().TrimEnd()
$serviceUrl = $serviceUrl.Replace('CxWebClient', '').trim()
if ($serviceUrl.EndsWith('//')){
    $serviceUrl = $serviceUrl.Substring(0,$serviceUrl.Length -1)
}
if (-Not $serviceUrl.EndsWith('/')){
    $serviceUrl = $serviceUrl + '/'
}

$resolverUrlExtension = 'Cxwebinterface/CxWSResolver.asmx?wsdl'
$resolverUrl = $serviceUrl + $resolverUrlExtension

write-host "Connecting to Checkmarx at: $resolverUrl ....." -foregroundcolor "green"

$resolver = $null
try {
    $resolver = New-WebServiceProxy -Uri $resolverUrl -UseDefaultCredential
    $resolver.Timeout = 600000
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
$proxy.Timeout = 600000

if (!$proxy){
    write-host  "Could not find Checkmarx SDK service URL" -foregroundcolor "red"
    Exit
}

$namespace = $proxy.GetType().Namespace

$credentialsType = ($namespace + '.Credentials')
$credentials = New-Object ($credentialsType)
$credentials.User = $user
$credentials.Pass = $password

write-host  "Logging into the Checkmarx service..." -foregroundcolor "green"
$loginResponse = $proxy.Login($credentials, 1033)

. $PSScriptRoot/CxReport/CxReport.ps1

If(-Not $loginResponse.IsSuccesfull){
    Write-Host ("##vso[task.logissue type=error;]An Error occurred while logging in: {0}" -f $loginResponse.ErrorMessage)
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
            #write-host "todo: add scans count environment variable"
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
    #Write-Host ("Full team path: {0}" -f $fullTeamName)
	$CliScanArgs.PrjSettings.ProjectName = $fullTeamName + "\\" + $projectName

	$presetId

	if (-not ([string]::IsNullOrEmpty($customPreset))){

    $presetList = $proxy.GetPresetList($sessionId)
    $presets = New-Object 'System.Collections.Generic.Dictionary[String,String]'

    if ($presetList.IsSuccesfull -ne "True" ) {
        Write-Host ("##vso[task.logissue type=error;]Failed to retrieve preset list: {0}" -f $presetList.ErrorMessage)
        Write-Host "##vso[task.complete result=Failed;]DONE"
        Exit
        }

        #Write-Host ("Presets- IsSuccessful: {0}" -f $presetList.IsSuccessful);
        $presets = $presetList.PresetList;

		foreach ($_preset in $presets.GetEnumerator()) {
            if ($_preset[0].PresetName -eq  $customPreset.Trim()){
                $PresetId = $_preset[0].ID;
                $presetName = $_preset[0].PresetName;
            }

        }

        #The preset was not found
         if ($presetId -eq $null){
             Write-Host "##vso[task.logissue type=error;]The selected custom preset [$customPreset] does not exist. Please fix and re-run the scan";
             Write-Host "##vso[task.complete result=Failed;]DONE"
         Exit
        }

        Write-Host ("Custom preset was found. PresetId: {0}" -f $presetId)

	}else{
	  $presetName = $presetList;
        switch ($presetName){

            "Checkmarx Default"          {$presetId = 36}
            "All"                        {$presetId = 1 }
            "Android"                    {$presetId = 9 }
            "Apple Secure Coding Guide"  {$presetId = 19}
            "Default"                    {$presetId = 7 }
            "Default 2014"               {$presetId = 17}
            "Empty preset"               {$presetId = 6 }
            "Error handling"             {$presetId = 2 }
            "FISMA"                      {$presetId = 39}
            "High and Medium"            {$presetId = 3 }
            "High and Medium and Low"    {$presetId = 13}
            "HIPAA"                      {$presetId = 12}
            "JSSEC"                      {$presetId = 20}
            "MISRA_C"                    {$presetId = 10}
            "MISRA_CPP"                  {$presetId = 11}
            "Mobile"                     {$presetId = 14}
            "NIST"                       {$presetId = 40}
            "OWASP Mobile TOP 10 - 2016" {$presetId = 37}
            "OWASP TOP 10 - 2010"        {$presetId = 4 }
            "OWASP TOP 10 - 2013"        {$presetId = 15}
            "PCI"                        {$presetId = 5 }
            "SANS top 25"                {$presetId = 8 }
            "STIG"                       {$presetId = 38}
            "WordPress"                  {$presetId = 16}
            "XS"                         {$presetId = 35}
            "XSS and SQLi only"          {$presetId = 41}
        }
	}

    $CliScanArgs.PrjSettings.PresetID = $presetId
    $CliScanArgs.PrjSettings.IsPublic = 1 # true
    $CliScanArgs.PrjSettings.Owner = $user


    #Create Zip File
    . $PSScriptRoot/CxZipUtils.ps1
     $zipfilename = ZipSource $folderExclusion $fileExtension $sourceLocation

    if(!(Test-Path -Path $zipfilename)){
        Write-Host "Zip file is empty: no source to scan"
        Write-Host "##vso[task.complete result=Skipped;]"
        Exit
    } Else {
        write-host "Zipped sources to $zipfilename" -foregroundcolor "green"
        $CliScanArgs.SrcCodeSettings.PackagedCode.ZippedFile = [System.IO.File]::ReadAllBytes($zipfilename)
        $CliScanArgs.SrcCodeSettings.PackagedCode.FileName = $zipfilename
    }

    #Delete Zip File
    [System.IO.File]::Delete($zipfilename)



    write-host "Starting Checkmarx scan..." -foregroundcolor "green"

    try {
        $scanResponse = $proxy.Scan($sessionId,$CliScanArgs)
    } catch {
        write-host "Fail to init Checkmarx scan." -foregroundcolor "red"
        Write-Host ("##vso[task.logissue type=error;]An error occurred while scanning: {0}" -f  $_.Exception.Message)
        Write-Host "##vso[task.complete result=Failed;]DONE"
        Exit
    }

    If(-Not $scanResponse.IsSuccesfull)	{
		Write-Host ("##vso[task.logissue type=error;]An error occurred while scanning: {0}" -f $scanResponse.ErrorMessage)
        Write-Host "##vso[task.complete result=Failed;]DONE"
    }
    Else {
        if([System.Convert]::ToBoolean($syncMode)){
		    $scanStatusResponse = $proxy.GetStatusOfSingleScan($sessionId,$scanResponse.RunId)

		    If(-Not $scanStatusResponse.IsSuccesfull) {
		        Write-Host ("##vso[task.logissue type=error;]Scan failed: {0}" -f $scanStatusResponse.ErrorMessage)
                Write-Host "##vso[task.complete result=Failed;]DONE"
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

                If($scanStatusResponse.IsSuccesfull -ne 0 -and $scanStatusResponse.CurrentStatus -eq "Finished") {
                    Write-Host "Scan finished. Retrieving scan results"
                    [String]$scanId = $scanStatusResponse.ScanId
                    [String]$projectID = $scanResponse.ProjectID

                    $scanSummary = $proxy.GetScanSummary($sessionId,$scanId)
                    $resHigh = $scanSummary.High
                    $resMedium = $scanSummary.Medium
                    $resLow = $scanSummary.Low
                    $resInfo = $scanSummary.Info
                    $cxLink = ("{0}CxWebClient/ViewerMain.aspx?scanId={1}&ProjectID={2}" -f $serviceUrl, $scanId, $projectID)

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

                    #Write-Host "Creating CxSAST reports"
                    CreateScanReport $reportPath $resHigh $resMedium $resLow $cxLink

                    [bool]$thresholdExceeded=$false
                    if([System.Convert]::ToBoolean($vulnerabilityThreshold)){
                        if(-Not [string]::IsNullOrEmpty($high)){
                            [Int]$highNum = [convert]::ToInt32($high, 10)
                            [Int]$resHigh = [convert]::ToInt32($resHigh, 10)
                            if($resHigh -gt $highNum){
                                Write-Host  ("##vso[task.logissue type=error;]Threshold for high result exceeded. Threshold:  {0} , Detected: {1}" -f $highNum, $resHigh)
                                $thresholdExceeded=$true
                            }
                        }
                        if(-Not [string]::IsNullOrEmpty($medium)){
                            [Int]$mediumNum = [convert]::ToInt32($medium, 10)
                            [Int]$resMedium = [convert]::ToInt32($resMedium, 10)
                            if($resMedium -gt $mediumNum){
                                Write-Host  ("##vso[task.logissue type=error;]Threshold for medium result exceeded. Threshold:  {0} , Detected: {1}" -f $mediumNum, $resMedium)
                                $thresholdExceeded=$true
                            }
                        }
                        if(-Not [string]::IsNullOrEmpty($low)){
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
                Else {
                    Write-Host ("##vso[task.logissue type=error;]Scan failed: {0}" -f $scanStatusResponse.StageMessage)
                    Write-Host "##vso[task.complete result=Failed;]DONE"
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