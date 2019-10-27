import {ScanConfig} from "../dto/scanConfig";
import {HttpClient} from "./httpClient";
import Zipper from "./zipper";
import {tmpNameSync} from 'tmp';
import * as fs from "fs";
import {TaskSkippedError} from "../dto/taskSkippedError";
import {ScanResults} from "../dto/scanResults";
import {SastClient} from "./sastClient";
import * as url from "url";

export class RestClient {
    readonly scanResults: ScanResults;

    private readonly httpClient: HttpClient;
    private readonly sastClient: SastClient;
    private readonly zipper = new Zipper();

    private teamId = 0;
    private projectId = 0;

    constructor(readonly config: ScanConfig) {
        this.httpClient = new HttpClient(config.serverUrl, config.username, config.password);
        this.sastClient = new SastClient(this.config, this.httpClient);
        this.scanResults = this.initScanResults();
    }

    async init(): Promise<void> {
        await this.login();
        await this.resolveTeam();
        await this.resolveProject();
    }

    async createSASTScan(): Promise<void> {
        await this.uploadSourceCode();
        this.scanResults.scanId = await this.sastClient.createScan(this.projectId);

        const projectStateUrl = url.resolve(this.config.serverUrl, `CxWebClient/portal#/projectState/${this.projectId}/Summary`);
        console.log(`SAST scan created successfully. CxLink to project state: ${projectStateUrl}`);
    }

    async getSASTResults() {
        console.log('------------------------------------Get CxSAST Results:----------------------------------');
        console.log('Retrieving SAST scan results');
        await this.sastClient.waitForScanToFinish();
    }

    private initScanResults(): ScanResults {
        return {
            errorOccurred: false,
            buildFailed: false,
            url: this.config.serverUrl,
            syncMode: this.config.isSyncMode,
            osaEnabled: false,
            enablePolicyViolations: this.config.enablePolicyViolations,
            sastThresholdExceeded: false,
            sastResultsReady: false,
            scanId: null,
            thresholdEnabled: this.config.vulnerabilityThreshold,
            highThreshold: this.config.highThreshold,
            mediumThreshold: this.config.mediumThreshold,
            lowThreshold: this.config.lowThreshold,
            sastViolations: [],
            sastPolicies: []
        }
    }

    private async login() {
        console.log('Logging into the Checkmarx service.');
        await this.httpClient.login();
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
}