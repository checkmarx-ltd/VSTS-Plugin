$AUTHENTICATION = "auth/identity/connect/token";
$CXPRESETS = "sast/presets";
$CXTEAMS = "auth/teams";
$CX_VERSION = "system/version";
$CX_ARM_URL = "/Configurations/Portal";
$CX_ARM_VIOLATION = "/cxarm/policymanager/projects/{projectId}/violations?provider={provider}";

#*********************************************************************#

function initRestClient($config){
    write-host "Initializing Cx client";
    $config.cxVersion = getCxVersion;
    $config.token = login
    if ($config.sastEnabled) {
        resolvePreset;
    }
    if ($config.enablePolicyViolations){
        resolveCxARMUrl;
    }

    resolveTeam;
    write-host "Resolving project";
    resolveProject;
}

function resolvePreset(){
    if ($config.presetId -eq $null) {
        $config.presetId =  getPresetIdByName $config.presetName;
    }
}

function resolveCxARMUrl() {
    try {
        $cxARMConfig = getCxARMConfig
        $config.cxARMUrl = $cxARMConfig.cxARMPolicyURL;

    } catch{
        write-error "CxARM is not available:  $_.Exception.Message"; #TODO
  }
}

function getCxVersion() {
    try {
        $version = getRequest $CX_VERSION $CONTENT_TYPE_APPLICATION_JSON_V1 200 "cx Version" $true;
        write-host("Checkmarx Server version [{0}]. Hotfix [{1}]." -f $version.version, $version.hotfix );
        return $version;
    } catch {
        write-debug ("Checkmarx Server version [lower than 9.0]");
        return $null;
    }
}


function getPresetIdByName($presetName) {
    $allPresets = getPresetList;
    foreach($preset in $allPresets){
        if ($preset.name -like $presetName) {
            return $preset.Id;
        }
    }

    throw ("Could not resolve preset ID from preset Name: {0}" -f $presetName);
}

function resolveTeam(){
    if ($config.teamId -eq $null) {
        $config.teamId =  getTeamIdByName $config.teamName;
    }
}

function getTeamIdByName($teamName) {
    $allTeams = getTeamList;
    foreach($team in $allTeams) {
        if ($team.fullName.Replace("/","\") -like $teamName) {
            return $team.id;
        }
    }
    throw ("Could not resolve team ID from teamName: {0}" -f $teamName);
}

function resolveProject() {
    $project = getProjectByName $config.projectName $config.teamId
    if ($project -eq $null) { #Project is new
        if ($config.denyProject -eq $true) {
            $errMsg = ("Creation of the new project [{0}] is not authorized. Please use an existing project." -f $config.projectName);
            $errMsg += " You can enable the creation of new projects by disabling the Deny new Checkmarx projects creation checkbox in the Checkmarx plugin global settings.";
            throw ($errMsg);
        }

    #Create newProject
    $projectRequest = New-Object System.Object
    $projectRequest | Add-Member -MemberType NoteProperty -Name name -Value $config.projectName;
    $projectRequest | Add-Member -MemberType NoteProperty -Name owningTeam -Value $config.teamId
    $projectRequest | Add-Member -MemberType NoteProperty -Name isPublic -Value $config.isPublic
    $project = createNewProject $projectRequest;
    $config.projectId = $project.Id;

    }else {
        $config.projectId = $project.Id;
    }
}

function getProjectByName ($projectName, $teamId){
    $projectNamePath = $SAST_GET_PROJECT.replace("{name}", $projectName).replace("{teamId}", $teamId);
    return getRequest $projectNamePath $CONTENT_TYPE_APPLICATION_JSON_V1 200 "project by name";
}

function getCxARMConfig(){
    return getRequest $CX_ARM_URL $CONTENT_TYPE_APPLICATION_JSON_V1 200 "CxARM URL" $true;
}

#function getViolations($cxARMUrl){
  #  $relPath = $CX_ARM_VIOLATION.replace("{projectId}", $config.projectId);
   # return getRequestFullPath  $cxARMUrl $relPath $CONTENT_TYPE_APPLICATION_JSON_V1 $null  200 "CxARM violations" $true; #todo fail messgae
#}

function getProjectViolations($provider){
    $relPath = $CX_ARM_VIOLATION.replace("{projectId}", $config.projectId).replace("{provider}", $provider);
    return getRequestFullPath $config.cxARMUrl $relPath $CONTENT_TYPE_APPLICATION_JSON_V1 $null 200 "CxARM $provider violations" $true;
}


#Config Public Methods
function getTeamList()  {
    return getRequest $CXTEAMS $CONTENT_TYPE_APPLICATION_JSON_V1 200 "team list" $true;
}

function getPresetList() {
    return getRequest $CXPRESETS $CONTENT_TYPE_APPLICATION_JSON_V1 200 "preset list" $true;
}

function getConfigurationSetList() {
    return getRequest $SAST_ENGINE_CONFIG $CONTENT_TYPE_APPLICATION_JSON_V1 200 "engine configurations" $true;
}

