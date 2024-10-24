"use strict";
exports.__esModule = true;
var taskLib = require("azure-pipelines-task-lib/task");
var cx_common_js_client_1 = require("@checkmarx/cx-common-js-client");
var ConfigReader = /** @class */ (function () {
    function ConfigReader(log) {
        this.log = log;
    }
    ConfigReader.prototype.readConfig = function () {
        var SUPPORTED_AUTH_SCHEME = 'UsernamePassword';
        this.log.debug('Reading configuration.');
        var endpointId = taskLib.getInput('CheckmarxService', true) || '';
        //TODO: remove SCA stuff from comment once its decided to use SCA in VSTS.
        //const endpointIdSCA = taskLib.getInput('dependencyServerURL', true) || '';
        var sourceLocation = taskLib.getVariable('Build.SourcesDirectory');
        if (typeof sourceLocation === 'undefined') {
            throw Error('Sources directory is not provided.');
        }
        var authScheme = taskLib.getEndpointAuthorizationScheme(endpointId, false);
        if (authScheme !== SUPPORTED_AUTH_SCHEME) {
            throw Error("The authorization scheme " + authScheme + " is not supported for a CX server.");
        }
        /* const authSchemeSCA = taskLib.getEndpointAuthorizationScheme(endpointIdSCA, false);
         if (authSchemeSCA !== SUPPORTED_AUTH_SCHEME) {
             throw Error(`The authorization scheme ${authSchemeSCA} is not supported for a CX server.`);
         }*/
        var rawTeamName = taskLib.getInput('fullTeamName', true);
        var presetName;
        var customPreset = taskLib.getInput('customPreset', false);
        if (customPreset) {
            presetName = customPreset;
        }
        else {
            presetName = taskLib.getInput('preset', true) || '';
        }
        var rawTimeout = taskLib.getInput('scanTimeout', false);
        var scanTimeoutInMinutes = +rawTimeout;
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
        var result = {
            enableSastScan: true,
            serverUrl: taskLib.getEndpointUrl(endpointId, false),
            username: taskLib.getEndpointAuthorizationParameter(endpointId, 'username', false) || '',
            password: taskLib.getEndpointAuthorizationParameter(endpointId, 'password', false) || '',
            sourceLocation: sourceLocation,
            projectName: taskLib.getInput('projectName', true) || '',
            teamName: cx_common_js_client_1.TeamApiClient.normalizeTeamName(rawTeamName),
            denyProject: taskLib.getBoolInput('denyProject', false),
            folderExclusion: taskLib.getInput('folderExclusion', false) || '',
            fileExtension: taskLib.getInput('fileExtension', false) || '',
            isIncremental: taskLib.getBoolInput('incScan', true),
            isSyncMode: taskLib.getBoolInput('syncMode', false),
            presetName: presetName,
            scanTimeoutInMinutes: scanTimeoutInMinutes || undefined,
            comment: taskLib.getInput('comment', false) || '',
            enablePolicyViolations: taskLib.getBoolInput('enablePolicyViolations', false),
            vulnerabilityThreshold: taskLib.getBoolInput('vulnerabilityThreshold', false),
            criticalThreshold: ConfigReader.getNumericInput('critical'),
            highThreshold: ConfigReader.getNumericInput('high'),
            mediumThreshold: ConfigReader.getNumericInput('medium'),
            lowThreshold: ConfigReader.getNumericInput('low'),
            cxOrigin: 'VSTS',
            forceScan: false,
            isPublic: true,
            enableDependencyScan: false,
            scaConfig: undefined
        };
        //this.formatSCA(scaResult);
        this.format(result);
        return result;
    };
    ConfigReader.getNumericInput = function (name) {
        var rawValue = taskLib.getInput(name, false);
        var result;
        if (typeof rawValue !== 'undefined') {
            if (rawValue == null) {
                result = NaN;
            }
            else {
                result = +rawValue;
            }
        }
        return result;
    };
    ConfigReader.prototype.format = function (config) {
        var formatOptionalString = function (input) { return input || 'none'; };
        var formatOptionalNumber = function (input) { return (typeof input === 'undefined' ? 'none' : input); };
        this.log.info("\n-------------------------------CxSAST Configurations:--------------------------------\nURL: " + config.serverUrl + "\nProject name: " + config.projectName + "\nSource location: " + config.sourceLocation + "\nFull team path: " + config.teamName + "\nPreset name: " + config.presetName + "\nScan timeout in minutes: " + config.scanTimeoutInMinutes + "\nDeny project creation: " + config.denyProject + "\n\nIs incremental scan: " + config.isIncremental + "\nFolder exclusions: " + formatOptionalString(config.folderExclusion) + "\nFile exclusions: " + formatOptionalString(config.fileExtension) + "\nIs synchronous scan: " + config.isSyncMode + "\n\nCxSAST thresholds enabled: " + config.vulnerabilityThreshold);
        if (config.vulnerabilityThreshold) {
            this.log.info("CxSAST critical threshold: " + formatOptionalNumber(config.criticalThreshold));
            this.log.info("CxSAST high threshold: " + formatOptionalNumber(config.highThreshold));
            this.log.info("CxSAST medium threshold: " + formatOptionalNumber(config.mediumThreshold));
            this.log.info("CxSAST low threshold: " + formatOptionalNumber(config.lowThreshold));
        }
        this.log.info("Enable Project Policy Enforcement: " + config.enablePolicyViolations);
        this.log.info('------------------------------------------------------------------------------');
    };
    ConfigReader.prototype.formatSCA = function (config) {
        var formatOptionalString = function (input) { return input || 'none'; };
        var formatOptionalNumber = function (input) { return (typeof input === 'undefined' ? 'none' : input); };
        this.log.info("\n-------------------------------SCA Configurations:--------------------------------\nAccessControl: " + config.accessControlUrl + "\nApiURL: " + config.apiUrl + "\nWebAppUrl: " + config.webAppUrl + "\nTenant: " + config.tenant);
        this.log.info('------------------------------------------------------------------------------');
    };
    return ConfigReader;
}());
exports.ConfigReader = ConfigReader;
