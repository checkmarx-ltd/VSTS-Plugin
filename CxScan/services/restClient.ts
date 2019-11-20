import {ScanConfig} from "../dto/scanConfig";
import {HttpClient} from "./httpClient";
import Zipper from "./zipper";
import {TaskSkippedError} from "../dto/taskSkippedError";
import {ScanResults} from "../dto/scanResults";
import {SastClient} from "./sastClient";
import * as url from "url";
import {ArmClient} from "./armClient";
import {UpdateScanSettingsRequest} from "../dto/updateScanSettingsRequest";
import {Logger} from "./logger";
import {ReportingClient} from "./reportingClient";
import {ScanResultsEvaluator} from "./scanResultsEvaluator";
import {FilePathFilter} from "./filePathFilter";
import {FileUtil} from "./fileUtil";
import {TeamApiClient} from "./teamApiClient";

/**
 * High-level CX API client that uses specialized clients internally.
 */
export class RestClient {
    readonly scanResults: ScanResults;
    private readonly httpClient: HttpClient;
    private readonly sastClient: SastClient;
    private readonly armClient: ArmClient;

    private teamId = 0;
    private projectId = 0;
    private presetId = 0;
    private isPolicyEnforcementSupported = false;

    constructor(private readonly config: ScanConfig, private readonly log: Logger) {
        const baseUrl = url.resolve(this.config.serverUrl, 'CxRestAPI/');
        this.httpClient = new HttpClient(baseUrl, log);

        this.sastClient = new SastClient(this.config, this.httpClient, log);
        this.armClient = new ArmClient(this.httpClient, log);

        this.scanResults = new ScanResults(this.config);
    }

    async init(): Promise<void> {
        this.log.info('Initializing Cx client');

        await this.detectFeatureSupport();

        await this.httpClient.login(this.config.username, this.config.password);

        this.presetId = await this.sastClient.getPresetIdByName(this.config.presetName);

        if (this.config.enablePolicyViolations) {
            await this.armClient.init();
        }

        const teamApiClient = new TeamApiClient(this.httpClient, this.log);
        this.teamId = await teamApiClient.getTeamIdByName(this.config.teamName);

        await this.resolveProject();
    }

    async createSASTScan(): Promise<void> {
        this.log.info('-----------------------------------Create CxSAST Scan:-----------------------------------');
        await this.defineScanSettings();

        await this.uploadSourceCode();

        this.scanResults.scanId = await this.sastClient.createScan(this.projectId);

        const projectStateUrl = url.resolve(this.config.serverUrl, `CxWebClient/portal#/projectState/${this.projectId}/Summary`);
        this.log.info(`SAST scan created successfully. CxLink to project state: ${projectStateUrl}`);
    }

    async getSASTResults() {
        this.log.info('------------------------------------Get CxSAST Results:----------------------------------');
        this.log.info('Retrieving SAST scan results');

        await this.sastClient.waitForScanToFinish();

        await this.addStatisticsToScanResults();
        await this.addPolicyViolationsToScanResults();

        this.printStatistics();

        await this.addDetailedReportToScanResults();

        const evaluator = new ScanResultsEvaluator(this.scanResults, this.config, this.log, this.isPolicyEnforcementSupported);
        evaluator.evaluate();
    }

    private async resolveProject() {
        this.projectId = await this.getCurrentProjectId();

        if (this.projectId) {
            this.log.debug(`Resolved project ID: ${this.projectId}`);
        } else {
            this.log.info('Project not found, creating a new one.');

            if (this.config.denyProject) {
                throw Error(
                    `Creation of the new project [${this.config.projectName}] is not authorized. Please use an existing project.` +
                    " You can enable the creation of new projects by disabling the Deny new Checkmarx projects creation checkbox in the Checkmarx plugin global settings.");
            }

            this.projectId = await this.createNewProject();
        }
    }

    private async uploadSourceCode(): Promise<void> {
        const tempFilename = FileUtil.generateTempFileName({prefix: 'cxsrc-', postfix: '.zip'});
        this.log.info(`Zipping source code at ${this.config.sourceLocation} into file ${tempFilename}`);

        const filter = new FilePathFilter(this.config.fileExtension, this.config.folderExclusion);

        const zipper = new Zipper(this.log, filter);
        const zipResult = await zipper.zipDirectory(this.config.sourceLocation, tempFilename);

        if (zipResult.fileCount === 0) {
            throw new TaskSkippedError('Zip file is empty: no source to scan');
        }

        this.log.info(`Uploading the zipped source code.`);
        const urlPath = `projects/${this.projectId}/sourceCode/attachments`;
        await this.httpClient.postMultipartRequest(urlPath,
            {id: this.projectId},
            {zippedSource: tempFilename});
    }

    private async getCurrentProjectId(): Promise<number> {
        this.log.info(`Resolving project: ${this.config.projectName}`);
        let result;
        const encodedName = encodeURIComponent(this.config.projectName);
        const path = `projects?projectname=${encodedName}&teamid=${this.teamId}`;
        try {
            const projects = await this.httpClient.getRequest(path, {suppressWarnings: true});
            if (projects && projects.length) {
                result = projects[0].id;
            }
        } catch (err) {
            const isExpectedError = err.response && err.response.notFound;
            if (!isExpectedError) {
                throw err;
            }
        }
        return result;
    }

    private async createNewProject(): Promise<number> {
        const request = {
            name: this.config.projectName,
            owningTeam: this.teamId,
            isPublic: this.config.isPublic
        };

        const newProject = await this.httpClient.postRequest('projects', request);
        this.log.debug(`Created new project, ID: ${newProject.id}`);

        return newProject.id;
    }

    private async defineScanSettings() {
        const settingsResponse = await this.sastClient.getScanSettings(this.projectId);

        const engineConfigurationId = this.config.engineConfigurationId || settingsResponse.engineConfiguration.id;

        const request: UpdateScanSettingsRequest = {
            projectId: this.projectId,
            presetId: this.presetId,
            engineConfigurationId,
            emailNotifications: settingsResponse.emailNotifications
        };

        // TODO: PowerShell code uses postScanActionId = settingsResponse.postScanAction    - is this correct?
        if (settingsResponse.postScanAction) {
            request.postScanActionId = settingsResponse.postScanAction.id;
        }

        await this.sastClient.updateScanSettings(request);
    }

    private async addPolicyViolationsToScanResults() {
        if (!this.config.enablePolicyViolations) {
            return;
        }

        if (!this.isPolicyEnforcementSupported) {
            this.log.warning('Policy enforcement is not supported by the current Checkmarx server version.');
            return;
        }

        await this.armClient.waitForArmToFinish(this.projectId);

        const projectViolations = await this.armClient.getProjectViolations(this.projectId, 'SAST');
        for (const policy of projectViolations) {
            this.scanResults.sastPolicies.push(policy.policyName);
            for (const violation of policy.violations) {
                this.scanResults.sastViolations.push({
                    libraryName: violation.source,
                    policyName: policy.policyName,
                    ruleName: violation.ruleName,
                    detectionDate: (new Date(violation.firstDetectionDateByArm)).toLocaleDateString()
                });
            }
        }

        if (this.scanResults.sastViolations.length) {
            this.scanResults.policyViolated = true;
        }
    }

    private async addStatisticsToScanResults() {
        const statistics = await this.sastClient.getScanStatistics(this.scanResults.scanId);
        this.scanResults.highResults = statistics.highSeverity;
        this.scanResults.mediumResults = statistics.mediumSeverity;
        this.scanResults.lowResults = statistics.lowSeverity;
        this.scanResults.infoResults = statistics.infoSeverity;

        const sastScanPath = `CxWebClient/ViewerMain.aspx?scanId=${this.scanResults.scanId}&ProjectID=${this.projectId}`;
        this.scanResults.sastScanResultsLink = url.resolve(this.config.serverUrl, sastScanPath);

        const sastProjectLink = `CxWebClient/portal#/projectState/${this.projectId}/Summary`;
        this.scanResults.sastSummaryResultsLink = url.resolve(this.config.serverUrl, sastProjectLink);

        this.scanResults.sastResultsReady = true;
    }

    private async addDetailedReportToScanResults() {
        const client = new ReportingClient(this.httpClient, this.log);
        const reportXml = await client.generateReport(this.scanResults.scanId);

        const doc = reportXml.CxXMLResults;
        this.scanResults.scanStart = doc.$.ScanStart;
        this.scanResults.scanTime = doc.$.ScanTime;
        this.scanResults.locScanned = doc.$.LinesOfCodeScanned;
        this.scanResults.filesScanned = doc.$.FilesScanned;
        this.scanResults.queryList = RestClient.toJsonQueries(doc.Query);

        // TODO: PowerShell code also adds properties such as newHighCount, but they are not used in the UI.
    }

    private printStatistics() {
        this.log.info(`----------------------------Checkmarx Scan Results(CxSAST):-------------------------------
High severity results: ${this.scanResults.highResults}
Medium severity results: ${this.scanResults.mediumResults}
Low severity results: ${this.scanResults.lowResults}
Info severity results: ${this.scanResults.infoResults}

Scan results location:  ${this.scanResults.sastScanResultsLink}
------------------------------------------------------------------------------------------
`);
    }

    private static toJsonQueries(queries: any[] | undefined) {
        const SEPARATOR = ';';

        // queries can be undefined if no vulnerabilities were found.
        return (queries || []).map(query =>
            JSON.stringify({
                name: query.$.name,
                severity: query.$.Severity,
                resultLength: query.Result.length
            })
        ).join(SEPARATOR);
    }

    private async detectFeatureSupport() {
        try {
            const versionInfo = await this.httpClient.getRequest('system/version', {suppressWarnings: true});
            this.log.info(`Checkmarx server version [${versionInfo.version}]. Hotfix [${versionInfo.hotFix}].`);
            this.isPolicyEnforcementSupported = true;
        } catch (e) {
            this.log.info('Checkmarx server version is lower than 9.0.');
            this.isPolicyEnforcementSupported = false;
        }
    }
}