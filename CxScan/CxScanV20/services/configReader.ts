import taskLib = require('azure-pipelines-task-lib/task');
import {Logger} from "@checkmarx/cx-common-js-client";
import {ScanConfig} from "@checkmarx/cx-common-js-client";
import {TeamApiClient} from "@checkmarx/cx-common-js-client";
import {ScaConfig} from "@checkmarx/cx-common-js-client"

export class ConfigReader {
    constructor(private readonly log: Logger) {
    }
    readConfig(): ScanConfig {
        const SUPPORTED_AUTH_SCHEME = 'UsernamePassword';

        this.log.debug('Reading configuration.');

        const endpointId = taskLib.getInput('CheckmarxService', true) || '';
        //TODO: remove SCA stuff from comment once its decided to use SCA in VSTS.
        //const endpointIdSCA = taskLib.getInput('dependencyServerURL', true) || '';

        const sourceLocation = taskLib.getVariable('Build.SourcesDirectory');
        if (typeof sourceLocation === 'undefined') {
            throw Error('Sources directory is not provided.');
        }

        const authScheme = taskLib.getEndpointAuthorizationScheme(endpointId, false);
        if (authScheme !== SUPPORTED_AUTH_SCHEME) {
            throw Error(`The authorization scheme ${authScheme} is not supported for a CX server.`);
        }

       /* const authSchemeSCA = taskLib.getEndpointAuthorizationScheme(endpointIdSCA, false);
        if (authSchemeSCA !== SUPPORTED_AUTH_SCHEME) {
            throw Error(`The authorization scheme ${authSchemeSCA} is not supported for a CX server.`);
        }*/

        const rawTeamName = taskLib.getInput('fullTeamName', true);

        let presetName;
        const customPreset = taskLib.getInput('customPreset', false);
        if (customPreset) {
            presetName = customPreset;
        } else {
            presetName = taskLib.getInput('preset', true) || '';
        }

        let rawTimeout = taskLib.getInput('scanTimeout', false) as any;
        let scanTimeoutInMinutes = +rawTimeout;
        /*const scaResult: ScaConfig = {
            accessControlUrl: taskLib.getInput('dependencyAccessControlURL',false) || '',
            apiUrl: taskLib.getEndpointUrl(endpointIdSCA,false) || '',
            username: taskLib.getEndpointAuthorizationParameter(endpointIdSCA,'username',false) || '',
            password: taskLib.getEndpointAuthorizationParameter(endpointIdSCA,'password',false) || '',
            tenant: taskLib.getInput('dependencyTenant',false) || '',
            webAppUrl: taskLib.getInput('dependencyWebAppURL',false) || '',
            dependencyFileExtension: taskLib.getInput('dependencyFileExtension',false) || '',
            dependencyFolderExclusion:taskLib.getInput('dependencyFolderExclusion',false) || ''
        };*/
        const result: ScanConfig = {
            enableSastScan: true,
            serverUrl: taskLib.getEndpointUrl(endpointId, false),
            username: taskLib.getEndpointAuthorizationParameter(endpointId, 'username', false) || '',
            password: taskLib.getEndpointAuthorizationParameter(endpointId, 'password', false) || '',

            sourceLocation,
            projectName: taskLib.getInput('projectName', true) || '',
            teamName: TeamApiClient.normalizeTeamName(rawTeamName),
            denyProject: taskLib.getBoolInput('denyProject', false),
            folderExclusion: taskLib.getInput('folderExclusion', false) || '',
            fileExtension: taskLib.getInput('fileExtension', false) || '',
            isIncremental: taskLib.getBoolInput('incScan', true),
            isSyncMode: taskLib.getBoolInput('syncMode', false),
            presetName,
            scanTimeoutInMinutes: scanTimeoutInMinutes || undefined,
            comment: taskLib.getInput('comment', false) || '',

            enablePolicyViolations: taskLib.getBoolInput('enablePolicyViolations', false),
            vulnerabilityThreshold: taskLib.getBoolInput('vulnerabilityThreshold', false),
            highThreshold: ConfigReader.getNumericInput('high'),
            mediumThreshold: ConfigReader.getNumericInput('medium'),
            lowThreshold: ConfigReader.getNumericInput('low'),
            cxOrigin:'VSTS',
            forceScan: false,
            isPublic: true,
            enableDependencyScan:false,
            scaConfig: undefined
        };
        //this.formatSCA(scaResult);
        this.format(result);

        return result;
    }

    private static getNumericInput(name: string): number | undefined {
        const rawValue = taskLib.getInput(name, false);
        let result;
        if (typeof rawValue !== 'undefined') {
            if (rawValue == null) {
                result = NaN;
            }
            else {
                result = +rawValue;
            }
        }
        return result;
    }

    private format(config: ScanConfig): void {
        const formatOptionalString = (input: string) => input || 'none';
        const formatOptionalNumber = (input: number | undefined) => (typeof input === 'undefined' ? 'none' : input);

        this.log.info(`
-------------------------------CxSAST Configurations:--------------------------------
URL: ${config.serverUrl}
Project name: ${config.projectName}
Source location: ${config.sourceLocation}
Full team path: ${config.teamName}
Preset name: ${config.presetName}
Scan timeout in minutes: ${config.scanTimeoutInMinutes}
Deny project creation: ${config.denyProject}

Is incremental scan: ${config.isIncremental}
Folder exclusions: ${formatOptionalString(config.folderExclusion)}
File exclusions: ${formatOptionalString(config.fileExtension)}
Is synchronous scan: ${config.isSyncMode}

CxSAST thresholds enabled: ${config.vulnerabilityThreshold}`);

        if (config.vulnerabilityThreshold) {
            this.log.info(`CxSAST high threshold: ${formatOptionalNumber(config.highThreshold)}`);
            this.log.info(`CxSAST medium threshold: ${formatOptionalNumber(config.mediumThreshold)}`);
            this.log.info(`CxSAST low threshold: ${formatOptionalNumber(config.lowThreshold)}`);
        }

        this.log.info(`Enable Project Policy Enforcement: ${config.enablePolicyViolations}`);
        this.log.info('------------------------------------------------------------------------------');
    }

    private formatSCA(config: ScaConfig): void {
        const formatOptionalString = (input: string) => input || 'none';
        const formatOptionalNumber = (input: number | undefined) => (typeof input === 'undefined' ? 'none' : input);

        this.log.info(`
-------------------------------SCA Configurations:--------------------------------
AccessControl: ${config.accessControlUrl}
ApiURL: ${config.apiUrl}
WebAppUrl: ${config.webAppUrl}
Tenant: ${config.tenant}`);

        this.log.info('------------------------------------------------------------------------------');
    }
}