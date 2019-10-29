import {ScanConfig} from "../dto/scanConfig";
import {HttpClient} from "./httpClient";
import Zipper from "./zipper";
import {tmpNameSync} from 'tmp';
import * as fs from "fs";
import {TaskSkippedError} from "../dto/taskSkippedError";
import {ScanResults} from "../dto/scanResults";
import {SastClient} from "./sastClient";
import * as url from "url";
import {ArmClient} from "./armClient";
import {UpdateScanSettingsRequest} from "../dto/updateScanSettingsRequest";

/**
 * High-level CX API client that uses specialized clients internally.
 */
export class RestClient {
    readonly scanResults: ScanResults;
    private readonly httpClient: HttpClient;
    private readonly sastClient: SastClient;
    private readonly armClient: ArmClient;

    private readonly zipper = new Zipper();
    private teamId = 0;
    private projectId = 0;
    private presetId = 0;

    constructor(readonly config: ScanConfig) {
        const baseUrl = url.resolve(this.config.serverUrl, 'CxRestAPI/');
        this.httpClient = new HttpClient(baseUrl);

        this.sastClient = new SastClient(this.config, this.httpClient);
        this.armClient = new ArmClient(this.httpClient);
        this.scanResults = new ScanResults(this.config);
    }

    async init(): Promise<void> {
        await this.login();

        await this.resolvePreset();

        if (this.config.enablePolicyViolations) {
            await this.armClient.init();
        }

        await this.resolveTeam();
        await this.resolveProject();
    }

    async createSASTScan(): Promise<void> {
        await this.defineScanSettings();

        await this.uploadSourceCode();
        this.scanResults.scanId = await this.sastClient.createScan(this.projectId);

        const projectStateUrl = url.resolve(this.config.serverUrl, `CxWebClient/portal#/projectState/${this.projectId}/Summary`);
        console.log(`SAST scan created successfully. CxLink to project state: ${projectStateUrl}`);
    }

    async getSASTResults() {
        console.log('------------------------------------Get CxSAST Results:----------------------------------');
        console.log('Retrieving SAST scan results');
        await this.sastClient.waitForScanToFinish();

        await this.addStatisticsToScanResults();

        if (this.config.enablePolicyViolations) {
            await this.armClient.waitForArmToFinish(this.projectId);
            await this.addPolicyViolationsToScanResults();
        }

        // this.printScanResults();
    }

    private async login() {
        console.log('Logging into the Checkmarx service.');
        await this.httpClient.login(this.config.username, this.config.password);
    }

    private async resolvePreset() {
        this.presetId = await this.sastClient.getPresetIdByName(this.config.presetName);
    }

    private async resolveTeam() {
        console.log(`Resolving team: ${this.config.teamName}`);
        const allTeams = await this.httpClient.getRequest('auth/teams') as any[];
        const currentTeamName = RestClient.normalizeTeamName(this.config.teamName);
        const foundTeam = allTeams.find(team =>
            RestClient.normalizeTeamName(team.fullName) === currentTeamName
        );

        if (foundTeam) {
            this.teamId = foundTeam.id;
        } else {
            throw Error(`Could not resolve team ID from team name: ${this.config.teamName}`);
        }
    }

    private async resolveProject() {
        console.log(`Resolving project: ${this.config.projectName}`);

        this.projectId = await this.getCurrentProjectId();

        if (!this.projectId) {
            console.log('Project not found, creating a new one.');

            if (this.config.denyProject) {
                throw Error(
                    `Creation of the new project [${this.config.projectName}] is not authorized. Please use an existing project.` +
                    " You can enable the creation of new projects by disabling the Deny new Checkmarx projects creation checkbox in the Checkmarx plugin global settings.");
            }

            this.projectId = await this.createNewProject();
        }
    }

    private async uploadSourceCode(): Promise<void> {
        const tempFilename = tmpNameSync({postfix: '.zip'});

        console.log(`Zipping source code at ${this.config.sourceDir} into file ${tempFilename}`);
        await this.zipper.zipDirectory(this.config.sourceDir, tempFilename);

        if (!fs.existsSync(tempFilename)) {
            const error = new TaskSkippedError('Zip file is empty: no source to scan');
            console.log(error.message);
            throw error;
        }

        const urlPath = `projects/${this.projectId}/sourceCode/attachments`;
        console.log(`Uploading the zipped source code to ${urlPath}.`);
        await this.httpClient.postMultipartRequest(urlPath,
            {id: this.projectId},
            {zippedSource: tempFilename});

        console.log(`Removing ${tempFilename}`);
        fs.unlinkSync(tempFilename);
    }

    private async getCurrentProjectId(): Promise<number> {
        let result;
        const encodedName = encodeURIComponent(this.config.projectName);
        const path = `projects?projectname=${encodedName}&teamid=${this.teamId}`;
        try {
            const projects = await this.httpClient.getRequest(path);
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
        return newProject.id;
    }

    private static normalizeTeamName(path: string | undefined): string {
        // TODO: check if the normalization is correct: differences between powershell and common client.
        return (path || '').replace('\\', '/').toUpperCase();
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
}