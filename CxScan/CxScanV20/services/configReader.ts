import taskLib = require('azure-pipelines-task-lib/task');
import {
    Logger,
    ProxyConfig,    
    ScanConfig,
    SourceLocationType,
    TeamApiClient
} from "@checkmarx/cx-common-js-client";
import { SastConfig } from "@checkmarx/cx-common-js-client/dist/dto/sastConfig";
import { ScaConfig } from "@checkmarx/cx-common-js-client/dist/dto/sca/scaConfig";
import * as url from "url";
import { homedir } from 'os';
import path = require('path');
import { config } from 'process';
import { file } from 'tmp';
const os = require("os");
const fs = require('fs');

export class ConfigReader {
    private readonly devAzure = 'dev.azure.com';
    private readonly MAX_SIZE_CXORIGINURL = 128;
    private readonly SIZE_CXORIGIN = 50;    
    private readonly SCARESOLVER_FILENAME = "ScaResolver.exe";   
    
    constructor(private readonly log: Logger) {
    }

    private static getNumericInput(name: string): number | undefined {
        const rawValue = taskLib.getInput(name, false);
        let result;
        if (typeof rawValue !== 'undefined') {
            if (rawValue == null) {
                result = NaN;
            } else {
                result = +rawValue;
            }
        }
        return result;
    }

    /**
     * This method validates given scan level custom fields format
     * @param scanCustomFields - Input given to custom fields
     * @param log - Logger object 
     * @returns 
     */
    private static getCustomFieldJSONString(scanCustomFields: any, log: Logger): string {
        let customFieldJSONStr = "";
        if (scanCustomFields) {
            let keyValuePairs = scanCustomFields.split(',');
            for (const keyVal of keyValuePairs) {
                const [key, value] = keyVal.split(':');
                if (key && value) {
                    customFieldJSONStr = customFieldJSONStr + "\"" + key + "\"" + ":" + "\"" + value + "\",";
                } else {
                    log.error("Custom fields are not defined in correct format. Example: field1:value1,field2:value2");
                    customFieldJSONStr = "";
                    break;
                }
            }
            if (customFieldJSONStr && customFieldJSONStr.length > 0) {
                customFieldJSONStr = customFieldJSONStr.substring(0, customFieldJSONStr.length - 1);
                customFieldJSONStr = "{" + customFieldJSONStr + "}";
            }
        }
        return customFieldJSONStr;
    }

    readConfig(): ScanConfig {
        const SUPPORTED_AUTH_SCHEME = 'UsernamePassword';

        this.log.debug('Reading configuration.');


        const sastEnabled = taskLib.getBoolInput('enableSastScan', false);
        const dependencyScanEnabled = taskLib.getBoolInput('enableDependencyScan', false);
        const proxyEnabled = taskLib.getBoolInput('enableproxy', false);

        let endpointId;
        let authScheme;
        let sastServerUrl;
        let sastUsername;
        let sastPassword;
        let teamsSASTServiceCon;
        let presetSASTServiceCon;
        let isThisBuildIncremental = false;
        let FULL_SCAN_CYCLE_MIN = 1;
        let FULL_SCAN_CYCLE_MAX = 99;
        let isScheduledScan = false;
        let isIncremental = false;
        let scheduleCycle: string;
        let vulnerabilityThresholdEnabled = false;
        let failBuildForNewVulnerabilitiesEnabled = false;
        let failBuildForNewVulnerabilitiesSeverity = '';

        let buildId = taskLib.getVariable('Build.BuildId') || '';

        scheduleCycle = '';
        if (sastEnabled) {
            endpointId = taskLib.getInput('CheckmarxService', false) || '';
            authScheme = taskLib.getEndpointAuthorizationScheme(endpointId, false) || undefined;
            if (authScheme !== SUPPORTED_AUTH_SCHEME) {
                throw Error(`The authorization scheme ${authScheme} is not supported for a CX server.`);
            }
            sastServerUrl = taskLib.getEndpointUrl(endpointId, false) || '';
            sastUsername = taskLib.getEndpointAuthorizationParameter(endpointId, 'username', false) || '';
            teamsSASTServiceCon = taskLib.getEndpointAuthorizationParameter(endpointId, 'teams', true) || '';
            presetSASTServiceCon = taskLib.getEndpointAuthorizationParameter(endpointId, 'preset', true) || '';
            sastPassword = taskLib.getEndpointAuthorizationParameter(endpointId, 'password', false) || '';
            isIncremental = taskLib.getBoolInput('incScan', false) || false;
            // adding 
            if(isIncremental) {
            isScheduledScan = taskLib.getBoolInput('fullScansScheduled', false) || false;
            scheduleCycle = taskLib.getInput('fullScanCycle', false) || '';
            if (isScheduledScan && scheduleCycle) {
                let cycleNumber = parseInt(scheduleCycle);
                let buildIdForScan = parseInt(buildId);
                // if user entered invalid value for full scan cycle - all scans will be incremental

                if (cycleNumber < FULL_SCAN_CYCLE_MIN || cycleNumber > FULL_SCAN_CYCLE_MAX) {
                    isIncremental = true;
                } else
                    // If user asked to perform full scan after every 9 incremental scans -
                    // it means that every 10th scan should be full,
                    // that is the ordinal numbers of full scans will be "1", "11", "21" and so on...
                    isThisBuildIncremental = (buildIdForScan % (cycleNumber + 1) == 1);
                isIncremental = !isThisBuildIncremental;

            }
        }
            vulnerabilityThresholdEnabled = taskLib.getBoolInput('vulnerabilityThreshold', false) || false;
            failBuildForNewVulnerabilitiesEnabled = vulnerabilityThresholdEnabled ? taskLib.getBoolInput('failBuildForNewVulnerabilitiesEnabled', false) || false : false;
            failBuildForNewVulnerabilitiesSeverity = (vulnerabilityThresholdEnabled && failBuildForNewVulnerabilitiesEnabled) ? taskLib.getInput('failBuildForNewVulnerabilitiesSeverity', false) || '' : '';
        }

        let endpointIdSCA;
        let authSchemeSCA;
        let scaServerUrl;
        let scaTenant;
        let scaWebAppUrl;
        let scaAccessControlUrl;
        let scaUsername;
        let scaPassword;
        let scaConfigFiles;
        let scaEnvVars;
        let scaConfigFilesArray: string[] = [];
        let envVariables: Map<string, string> = new Map;
        let scaSASTServerUrl;
        let scaSASTUserName;
        let scaSASTPassword;
        let endPointIdScaSast;
        let scaSastProjectFullPath;
        let scaSastProjectId;
        let isExploitableSca;
        let scaTeamName;
        let teamsSCAServiceCon;
        if (dependencyScanEnabled) {
            endpointIdSCA = taskLib.getInput('dependencyServerURL', false) || '';
            scaTeamName = taskLib.getInput('scaTeam', false) || '',
                isExploitableSca = taskLib.getBoolInput('scaExploitablePath', false) || false;
            endPointIdScaSast = taskLib.getInput('CheckmarxServiceForSca', false) || '';
            scaSastProjectFullPath = taskLib.getInput('scaProjectFullPath', false) || '';
            scaSastProjectId = taskLib.getInput('scaProjectId', false) || '';
            scaConfigFiles = taskLib.getInput('scaConfigFilePaths', false);
            scaEnvVars = taskLib.getInput('scaEnvVariables', false);
            if (scaConfigFiles)
                scaConfigFilesArray = scaConfigFiles.split(',');
            if (scaEnvVars) {
                let keyValuePairs = scaEnvVars.split(',');
                envVariables = keyValuePairs.reduce((acc, curr) => {
                    const [key, value] = curr.split(':');
                    if (!acc.has(key)) {
                        acc.set(key, value);
                    }
                    return acc;
                }, new Map());
            }
            authSchemeSCA = taskLib.getEndpointAuthorizationScheme(endpointIdSCA, false) || undefined;
            if (authSchemeSCA !== SUPPORTED_AUTH_SCHEME) {
                throw Error(`The authorization scheme ${authSchemeSCA} is not supported for a CX server.`);
            }
            scaServerUrl = taskLib.getEndpointUrl(endpointIdSCA, false) || '';
            teamsSCAServiceCon = taskLib.getEndpointDataParameter(endpointIdSCA, 'teams', true) || '';

            try {
                scaTenant = taskLib.getEndpointDataParameter(endpointIdSCA, 'dependencyTenant', false) || '';
                if (!scaTenant || scaTenant == '') {
                    scaTenant = taskLib.getInput('dependencyTenant', false);
                }
            } catch (err) {
                scaTenant = taskLib.getInput('dependencyTenant', false);
            }
            try {
                scaAccessControlUrl = taskLib.getEndpointDataParameter(endpointIdSCA, 'dependencyAccessControlURL', false) || '';
                if (!scaAccessControlUrl || scaAccessControlUrl == '') {
                    scaAccessControlUrl = taskLib.getInput('dependencyAccessControlURL', false);
                }
            } catch (err) {
                scaAccessControlUrl = taskLib.getInput('dependencyAccessControlURL', false);
            }
            try {
                scaWebAppUrl = taskLib.getEndpointDataParameter(endpointIdSCA, 'dependencyWebAppURL', false) || '';
                if (!scaWebAppUrl || scaWebAppUrl == '') {
                    scaWebAppUrl = taskLib.getInput('dependencyWebAppURL', false);
                }
            } catch (err) {
                scaWebAppUrl = taskLib.getInput('dependencyWebAppURL', false);
            }

            scaUsername = taskLib.getEndpointAuthorizationParameter(endpointIdSCA, 'username', false) || '';
            scaPassword = taskLib.getEndpointAuthorizationParameter(endpointIdSCA, 'password', false) || '';
            //sca section sast credentials 
            if (isExploitableSca) {
                scaSASTServerUrl = taskLib.getEndpointUrl(endPointIdScaSast, false) || '';
                scaSASTUserName = taskLib.getEndpointAuthorizationParameter(endPointIdScaSast, 'username', false) || '';
                scaSASTPassword = taskLib.getEndpointAuthorizationParameter(endPointIdScaSast, 'password', false) || '';
            }
        }
        //
        if (teamsSCAServiceCon) {
            scaTeamName = teamsSCAServiceCon;
        }
        let proxy;
        let proxyUrl;
        let proxyUsername;
        let proxyPassword;
        let proxyPort;
        let sastProxyUrl;
        let scaProxyUrl;
        let proxyResult: ProxyConfig = {
            proxyHost: '',
            proxyPass: '',
            proxyPort: '',
            proxyUser: '',
            proxyUrl: '',
            sastProxyUrl: '',
            scaProxyUrl: '',
            resolvedProxyUrl: ''
        };
        if (proxyEnabled) {
            proxy = taskLib.getHttpProxyConfiguration();
            sastProxyUrl = taskLib.getInput('sastProxyUrl');
            scaProxyUrl = taskLib.getInput('scaProxyUrl');
            //add this 
            if (proxy) {
                if (!proxy.proxyUrl || proxy.proxyUrl == '') {
                    this.log.warning('Proxy is enabled but no proxy settings are defined.');
                } else {
                    proxyResult.proxyHost = proxy ? proxy.proxyUrl : '';
                    proxyResult.proxyPass = proxy ? proxy.proxyPassword : '';
                    proxyResult.proxyPort = '';
                    proxyResult.proxyUser = proxy ? proxy.proxyUsername : '';
                }
            }
            else if ((proxyUrl && proxyUrl != '') || (sastProxyUrl && sastProxyUrl != '') || (scaProxyUrl && scaProxyUrl != '')) {
                proxyResult.proxyUrl = proxyUrl ? proxyUrl : '';
                proxyResult.sastProxyUrl = sastProxyUrl ? sastProxyUrl : '';
                proxyResult.scaProxyUrl = scaProxyUrl ? scaProxyUrl : '';
            } else {
                this.log.warning('Proxy is enabled but no proxy settings are defined.');
            }
            proxyResult.proxyUrl = this.appendCredsToProxyUrl(proxyResult.proxyUrl);
            proxyResult.sastProxyUrl = this.appendCredsToProxyUrl(proxyResult.sastProxyUrl);
            proxyResult.scaProxyUrl = this.appendCredsToProxyUrl(proxyResult.scaProxyUrl);
        }
        //Create Job Link
        let collectionURI = taskLib.getVariable('System.TeamFoundationCollectionUri');
        let projectName = taskLib.getVariable('System.TeamProject');
        const pipelineId = taskLib.getVariable('System.DefinitionId');
        let cxOriginUrlNew = '';
        let cxOriginUrl: string = '';
        let jobOrigin = '';
        if (collectionURI) {            
            if (collectionURI.includes(this.devAzure)) {
                jobOrigin = 'ADO ' + this.devAzure + " " + projectName;
            } else {
                jobOrigin = 'TFS - ' + ConfigReader.getHostNameFromURL(collectionURI) + " " + projectName;
            }
            jobOrigin = jobOrigin.replace(/[^.a-zA-Z 0-9]/g, ' ');

            if (jobOrigin && jobOrigin.length > this.SIZE_CXORIGIN)
                jobOrigin = jobOrigin.substr(0, this.SIZE_CXORIGIN);

            //In collectionURI                        
            cxOriginUrl = collectionURI + projectName + '/' + '_build?definitionId=' + pipelineId;
            if(cxOriginUrl.toString().match(/[\u3400-\u9FBF]/)) {
            this.log.info("Original CxOriginUrl before replace:" + cxOriginUrl);            
            cxOriginUrlNew = cxOriginUrl.replace(/[^:.=?/\w\s]/g, '');
            }
            cxOriginUrl = cxOriginUrl.replace(/[^:.=?/\w\s]/g, '');
            if (cxOriginUrl.length <= this.MAX_SIZE_CXORIGINURL && !this.isValidUrl(cxOriginUrl)) {
                cxOriginUrl = this.extractBaseURL(cxOriginUrl);
            } else if (cxOriginUrl.length > this.MAX_SIZE_CXORIGINURL) {
                cxOriginUrl = this.extractBaseURL(cxOriginUrl);
            }
        }

        this.log.info("CxOrgin: " + jobOrigin);
        if(cxOriginUrlNew){
        this.log.info("CxOriginUrl after replace:" + cxOriginUrlNew);
        cxOriginUrl = cxOriginUrlNew;
        }
        else{
            this.log.info("CxOriginUrl:" + cxOriginUrl);
        }

        const sourceLocation = taskLib.getVariable('Build.SourcesDirectory');
        if (typeof sourceLocation === 'undefined') {
            throw Error('Sources directory is not provided.');
        }

        let rawTeamName;
        if (teamsSASTServiceCon) {
            rawTeamName = teamsSASTServiceCon;
        } else {
            rawTeamName = taskLib.getInput('fullTeamName', false) || '';
        }
        const scaCertFilePath = taskLib.getInput('scaCaChainFilePath', false) || '';
        const sastCertFilePath = taskLib.getInput('sastCaChainFilePath', false) || '';
        let presetName;
        const customPreset = taskLib.getInput('customPreset', false) || '';
        //if preset is given in service connection then it will take as first priority
        if (presetSASTServiceCon) {
            presetName = presetSASTServiceCon;
        } else if (customPreset) {
            presetName = customPreset;
        } else {
            presetName = taskLib.getInput('preset', false) || '';
        }


        const postScanAction = taskLib.getInput('postScanAction', false) || '';
        const avoidDuplicateProjectScans = taskLib.getBoolInput('avoidDuplicateScans', false);

        let rawTimeout = taskLib.getInput('scanTimeout', false) as any;

        let scanTimeoutInMinutes = +rawTimeout;
        
        let scaScanTimeout = taskLib.getInput('scaScanTimeout', false) as any;
        let scaScanTimeoutInMinutes = +scaScanTimeout;        
        
        const scaResult: ScaConfig = {
            scaSastTeam: TeamApiClient.normalizeTeamName(scaTeamName) || '',
            apiUrl: scaServerUrl || '',
            username: scaUsername || '',
            password: scaPassword || '',
            tenant: scaTenant || '',
            accessControlUrl: scaAccessControlUrl || '',
            webAppUrl: scaWebAppUrl || '',
            dependencyFileExtension: taskLib.getInput('dependencyFileExtension', false) || '',
            dependencyFolderExclusion: taskLib.getInput('dependencyFolderExclusion', false) || '',
            manifestPattern:taskLib.getInput('manifestPattern', false) || '',
            fingerprintPattern:taskLib.getInput('fingerprintPattern', false) || '',
            projectCustomTags: taskLib.getInput('projectCustomTags',false) || '',
            scanCustomTags: taskLib.getInput('scanCustomTags', false) || '',
            sourceLocationType: SourceLocationType.LOCAL_DIRECTORY,
            vulnerabilityThreshold: taskLib.getBoolInput('scaVulnerabilityThreshold', false) || false,
            highThreshold: ConfigReader.getNumericInput('scaHigh'),
            mediumThreshold: ConfigReader.getNumericInput('scaMedium'),
            lowThreshold: ConfigReader.getNumericInput('scaLow'),
            scaEnablePolicyViolations: taskLib.getBoolInput('scaEnablePolicyViolations', false) || false,
            includeSource: taskLib.getBoolInput('includeSource', false) || false,
            configFilePaths: scaConfigFilesArray || new Array<string>(),
            envVariables: envVariables || new Map(),
            sastProjectId: scaSastProjectId || '',
            sastProjectName: scaSastProjectFullPath || '',
            sastServerUrl: scaSASTServerUrl || '',
            sastUsername: scaSASTUserName || '',
            sastPassword: scaSASTPassword || '',
            isExploitable: isExploitableSca || false,
            cacert_chainFilePath: scaCertFilePath,

            isEnableScaResolver:taskLib.getBoolInput('isEnableScaResolver', false) || false,
            pathToScaResolver:taskLib.getInput('pathToScaResolver', false) || '',
            scaResolverAddParameters:taskLib.getInput('scaResolverAddParameters', false) || '',
            scaScanTimeoutInMinutes: scaScanTimeoutInMinutes || undefined
        };       
        
        var isSyncMode = taskLib.getBoolInput('syncMode', false);
        var  generatePDFReport = taskLib.getBoolInput('generatePDFReport', false) || false;
        if(!isSyncMode){
            generatePDFReport=false;
        }        

        const sastResult: SastConfig = {
            serverUrl: sastServerUrl || '',
            username: sastUsername || '',
            password: sastPassword || '',
            teamName: TeamApiClient.normalizeTeamName(rawTeamName) || '',
            denyProject: taskLib.getBoolInput('denyProject', false),
            folderExclusion: taskLib.getInput('folderExclusion', false) || '',
            fileExtension: taskLib.getInput('fileExtension', false) || '',
            overrideProjectSettings: taskLib.getBoolInput('overrideProjectSettings', false) || false,
            isIncremental: isIncremental,
            presetName,
            scanTimeoutInMinutes: scanTimeoutInMinutes || undefined,
            comment: taskLib.getInput('comment', false) || '',
            enablePolicyViolations: taskLib.getBoolInput('enablePolicyViolations', false) || false,

            generatePDFReport: generatePDFReport,
            vulnerabilityThreshold: vulnerabilityThresholdEnabled,
            highThreshold: ConfigReader.getNumericInput('high'),
            mediumThreshold: ConfigReader.getNumericInput('medium'),
            lowThreshold: ConfigReader.getNumericInput('low'),
            failBuildForNewVulnerabilitiesEnabled: failBuildForNewVulnerabilitiesEnabled,
            failBuildForNewVulnerabilitiesSeverity: failBuildForNewVulnerabilitiesSeverity,
            forceScan: (taskLib.getBoolInput('forceScan', false) && !taskLib.getBoolInput('incScan', false)) || false,
            isPublic: true,
            cacert_chainFilePath: sastCertFilePath,
            projectCustomFields: taskLib.getInput('projectcustomfields', false) || '',
            customFields: ConfigReader.getCustomFieldJSONString(taskLib.getInput('customfields', false), this.log),
            engineConfigurationId: ConfigReader.getNumericInput('engineConfigId'),
            postScanActionName: postScanAction,
            avoidDuplicateProjectScans: avoidDuplicateProjectScans,
        };

        const result: ScanConfig = {
            enableSastScan: taskLib.getBoolInput('enableSastScan', false),
            enableDependencyScan: taskLib.getBoolInput('enableDependencyScan', false),
            enableProxy: taskLib.getBoolInput('enableproxy', false),
            scaConfig: scaResult,
            sastConfig: sastResult,
            isSyncMode: taskLib.getBoolInput('syncMode', false),
            sourceLocation,
            cxOrigin: jobOrigin,
            cxOriginUrl: cxOriginUrl,
            projectName: taskLib.getInput('projectName', false) || '',
            proxyConfig: proxyResult
        };
        this.format(result);
        this.formatSCA(result);
        this.formatProxy(result);

        return result;
    }

    private appendCredsToProxyUrl(Url: string | undefined): string | undefined {

        if (Url) {
            let proxyUrl = Url;
            if (!Url.startsWith("https://") && !Url.startsWith("http://")) {
                this.log.warning("Protocol scheme is not specified in the proxy url. Assuming HTTP.");
                proxyUrl = "http://" + Url;
            }

            let urlParts = url.parse(Url);
            //if path in the url is / or empty, it is http proxy url. Add creds if needed.
            if (urlParts.path == undefined || urlParts.path == "" || urlParts.path == "/") {
                let proxyUsernameVar = taskLib.getVariable('proxy-username');
                let proxyPasswordVar = taskLib.getVariable('proxy-password');
                if (proxyPasswordVar && proxyUsernameVar) {
                    let splitUrl = Url.split("//");
                    proxyUrl = splitUrl[0] + '//' + proxyUsernameVar + ':' + proxyPasswordVar + '@' + splitUrl[1];
                }
            }
            return proxyUrl;
        }
        return Url;
    }

    private format(config: ScanConfig): void {
        const formatOptionalString = (input: string) => input || 'none';
        const formatOptionalNumber = (input: number | undefined) => (typeof input === 'undefined' ? 'none' : input);
        if (config.enableSastScan && config.sastConfig != null) {
            this.log.info(`
-------------------------------CxSAST Configurations:--------------------------------
URL: ${config.sastConfig.serverUrl}
Project name: ${config.projectName}
Source location: ${config.sourceLocation}
Full team path: ${config.sastConfig.teamName}
Preset name: ${config.sastConfig.presetName}
Deny project creation: ${config.sastConfig.denyProject}
Force scan : ${config.sastConfig.forceScan}
Is Override Project Settings: ${config.sastConfig.overrideProjectSettings}
Is incremental scan: ${config.sastConfig.isIncremental}`);
if (config.sastConfig.isIncremental) {
    let isScheduledScan = taskLib.getBoolInput('fullScansScheduled', false) || false;
    let scheduleCycle = taskLib.getInput('fullScanCycle', false) || '';
    this.log.info("Scheduled periodic full scan enabled:" + isScheduledScan);
    this.log.info("Scheduled full scan frequency:" + scheduleCycle);
}
if(config.sastConfig.scanTimeoutInMinutes != undefined){
    this.log.info(`Scan timeout in minutes: ${config.sastConfig.scanTimeoutInMinutes}`);
    }
this.log.info(`Folder exclusions: ${formatOptionalString(config.sastConfig.folderExclusion)}
Include/Exclude Wildcard Patterns: ${formatOptionalString(config.sastConfig.fileExtension)}
Is synchronous scan: ${config.isSyncMode}
SAST Comment: ${config.sastConfig.comment}
Project Custom Fields: ${config.sastConfig.projectCustomFields}
Scan Custom Fields: ${config.sastConfig.customFields}
Engine Configuration Id: ${config.sastConfig.engineConfigurationId}
Post Scan Action: ${config.sastConfig.postScanActionName}
Avoid Duplicate Project Scan: ${config.sastConfig.avoidDuplicateProjectScans}`);
            if (config.isSyncMode) {
                this.log.info(`
Generate PDF Report Enabled: ${config.sastConfig.generatePDFReport}
CxSAST thresholds enabled: ${config.sastConfig.vulnerabilityThreshold}`);


            if (config.sastConfig.vulnerabilityThreshold) {
                this.log.info(`CxSAST fail build for new vulnerabilities enabled: ${config.sastConfig.failBuildForNewVulnerabilitiesEnabled}`);
                this.log.info(`CxSAST fail build for the following severity or greater: ${config.sastConfig.failBuildForNewVulnerabilitiesSeverity}`);                    
                this.log.info(`CxSAST high threshold: ${formatOptionalNumber(config.sastConfig.highThreshold)}`);
                this.log.info(`CxSAST medium threshold: ${formatOptionalNumber(config.sastConfig.mediumThreshold)}`);
                this.log.info(`CxSAST low threshold: ${formatOptionalNumber(config.sastConfig.lowThreshold)}`);

            }
        }
    }
}

    private formatSCA(config: ScanConfig): void {
        if (config.enableDependencyScan && config.scaConfig != null) {
            const ourMap = config.scaConfig.envVariables;
            const envVar = JSON.stringify(Array.from(ourMap.entries()));
            this.log.info(`
-------------------------------SCA Configurations:--------------------------------
AccessControl: ${config.scaConfig.accessControlUrl}
ApiURL: ${config.scaConfig.apiUrl}
WebAppUrl: ${config.scaConfig.webAppUrl}
Account: ${config.scaConfig.tenant}
Include/Exclude Wildcard Patterns: ${config.scaConfig.dependencyFileExtension}
Folder Exclusion: ${config.scaConfig.dependencyFolderExclusion}
Manifest Pattern(Include/Exclude): ${config.scaConfig.manifestPattern}
Fingerprint Pattern(Include/Exclude): ${config.scaConfig.fingerprintPattern}
CxSCA Full team path: ${config.scaConfig.scaSastTeam}
Project custom tags: ${config.scaConfig.projectCustomTags}
Scan custom tags: ${config.scaConfig.scanCustomTags}
Package Manager's Config File(s) Path:${config.scaConfig.configFilePaths}
Private Registry Environment Variable:${envVar}
Include Sources:${config.scaConfig.includeSource}
Enable CxSCA Project's Policy Enforcement:${config.scaConfig.scaEnablePolicyViolations}
Vulnerability Threshold: ${config.scaConfig.vulnerabilityThreshold}
Enable SCA Resolver:${config.scaConfig.isEnableScaResolver}
`);
if(config.scaConfig.isEnableScaResolver) {
    
    var isScaResolverFileExists= fs.existsSync(config.scaConfig.pathToScaResolver + this.SCARESOLVER_FILENAME)

    if (!isScaResolverFileExists)
    {
        this.log.warning(`SCA Resolver file not found at path:${config.scaConfig.pathToScaResolver}`);
    }

    if (config.scaConfig.pathToScaResolver == '' || !isScaResolverFileExists){    
        config.scaConfig.pathToScaResolver = this.getPathToScaResolver(config.scaConfig.pathToScaResolver);
    }
    this.log.info(`Path To SCA Resolver:${config.scaConfig.pathToScaResolver}`);
    }
if(config.scaConfig.scaScanTimeoutInMinutes != undefined) {
    this.log.info(`Scan timeout in minutes: ${config.scaConfig.scaScanTimeoutInMinutes}`);
    }
            if (config.scaConfig.vulnerabilityThreshold) {
                this.log.info(`CxSCA High Threshold: ${config.scaConfig.highThreshold}
CxSCA Medium Threshold: ${config.scaConfig.mediumThreshold}
CxSCA Low Threshold: ${config.scaConfig.lowThreshold}`)
            }
            this.log.info('Enable Exploitable Path:' + config.scaConfig.isExploitable);
            if (config.scaConfig.isExploitable) {
                this.log.info(`Checkmarx SAST Endpoint:${config.scaConfig.sastServerUrl}
Checkmarx SAST Username: ${config.scaConfig.sastUsername}
Checkmarx SAST Password: *********
Project Full Path: ${config.scaConfig.sastProjectName}


Project ID: ${config.scaConfig.sastProjectId}`)
                if (!config.scaConfig.sastProjectId && !config.scaConfig.sastProjectName) {
                    this.log.error("Must provide value for either 'Project Full Path' or 'Project Id'");
                    throw "Must provide value for either 'Project Full Path' or 'Project Id'";
                    ;
                }
            }

            this.log.info('------------------------------------------------------------------------------');
        }
    }

    private formatProxy(config: ScanConfig): void {
        this.log.info(`
-------------------------------Proxy Configurations:--------------------------------
Proxy Enabled: ${config.enableProxy}`);
        if (config.enableProxy && config.proxyConfig != null && config.proxyConfig.proxyHost != '' && config.proxyConfig.proxyHost != null) {
            this.log.info(`Proxy URL: ${config.proxyConfig.proxyHost}`);
            if (config.proxyConfig.proxyUser != '' && config.proxyConfig.proxyUser != null) {
                this.log.info(`Proxy username: ${config.proxyConfig.proxyUser}
Proxy Pass: ******`);
            }
        } else if (config.enableProxy && config.proxyConfig != null && config.proxyConfig.proxyUrl != null && config.proxyConfig.proxyUrl != '') {
            this.log.info('Entered Proxy Url ' + config.proxyConfig.proxyUrl);
        }
        if (config.proxyConfig?.sastProxyUrl != '' && config.proxyConfig?.sastProxyUrl != null) {
            this.log.info(`SAST Proxy URL: ${config.proxyConfig.sastProxyUrl}`);
        }
        if (config.proxyConfig?.scaProxyUrl != '' && config.proxyConfig?.scaProxyUrl != null && config.enableDependencyScan) {
            this.log.info(`SCA Proxy URL: ${config.proxyConfig.scaProxyUrl}`);
        }
        this.log.info('------------------------------------------------------------------------------');
    }

    private static getHostNameFromURL(path: string): string {
        let host = url.parse(path).hostname;
        if (!host) {
            return '';
        }
        if (host.length > 43) {
            host = host.substring(0, 43);
        }
        return host;
    }

    private isValidUrl(url: string): boolean {
        let matcher = /(https?:\/\/(?:www\.|(?!www))[\w-]+\.[^\s]{2,}|www\.[\w-]+\.[^\s]{2,})/gi;
        return matcher.test(url);
    }

    private extractBaseURL(url: string): string {
        //look for index of first / that appears after host:port 
        var index = url.indexOf("/", url.indexOf("://") + 3);
        if (index > -1) {
            return url.substring(0, index);
        }
        else
            return "";
    }

    //To get path of SCA Resolver
    public getPathToScaResolver(config : string){  
        let pathToScaResolver;    
        try {
                let SCAResDowonloadCommand = '';
                const child_process = require('child_process');
                const userHomeDir = os.homedir();         
                pathToScaResolver = userHomeDir;
                    
                this.log.debug("Downloading SCA Resolver and extracting it to user home directory.");
                let osType = os.type();
                switch(osType) {
                case 'Darwin':
                this.log.debug("Downloading and extracting SCA Resolver for Mac operating system");
                SCAResDowonloadCommand = "curl -L https://sca-downloads.s3.amazonaws.com/cli/latest/ScaResolver-macos64.tar.gz -o ScaResolver.tar.gz && tar -vxzf ScaResolver.tar.gz && sudo mv ScaResolver " + userHomeDir + " && rm ScaResolver.tar.gz";   
                this.log.debug("Sca Resolver gets downloaded at location: "+userHomeDir);     
                break;
                case 'Linux': 
                this.log.debug("Downloading and extracting SCA Resolver for linux operating system");
                SCAResDowonloadCommand = "curl -L https://sca-downloads.s3.amazonaws.com/cli/latest/ScaResolver-linux64.tar.gz -o ScaResolver.tar.gz && tar -vxzf ScaResolver.tar.gz && sudo mv ScaResolver " + userHomeDir + " && rm ScaResolver.tar.gz";
                this.log.debug("Sca Resolver gets downloaded at location: "+userHomeDir);  
                break;
                case 'Windows_NT':
                this.log.debug("Downloading and extracting SCA Resolver for windows operating system");        
                SCAResDowonloadCommand = "curl -L https://sca-downloads.s3.amazonaws.com/cli/latest/ScaResolver-win64.zip -o ScaResolver.zip && tar -xf ScaResolver.zip && move ScaResolver.exe " + userHomeDir + " && del ScaResolver.zip";  
                this.log.debug("Sca Resolver gets downloaded at location: "+userHomeDir);         
                break;          
                }  
                this.log.debug("Command for SCA Resolver download and extract : " + SCAResDowonloadCommand); 
                try {     
                child_process.execSync(SCAResDowonloadCommand, { stdio: 'pipe' }); 
                }
                catch(ex :any) {           
                    this.log.debug(`Status Code: ${ex.status} with '${ex.message}'`);
                    throw Error("Error occured while downloading and extracting SCA Resolver automatically" + ex.message);
                }
            }
            catch(ex :any) {
                throw Error("Error occured while downloading and extracting SCA Resolver automatically" + ex.message);
                
            }    
    return pathToScaResolver;
    }
}