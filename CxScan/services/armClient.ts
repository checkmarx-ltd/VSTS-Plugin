import {HttpClient} from "./httpClient";
import {ArmStatus} from "../dto/armStatus";
import {Stopwatch} from "./stopwatch";
import {ScanProvider} from "../dto/scanProvider";
import {Waiter} from "./waiter";

/**
 * Works with policy-related APIs.
 */
export class ArmClient {
    private readonly stopwatch = new Stopwatch();

    private readonly generalHttpClient: HttpClient;

    private armHttpClient: HttpClient | null = null;

    constructor(httpClient: HttpClient) {
        this.generalHttpClient = httpClient;
    }

    async init() {
        console.log('Resolving CxARM URL.');
        const response = await this.generalHttpClient.getRequest('Configurations/Portal');
        this.armHttpClient = new HttpClient(response.cxARMPolicyURL, this.generalHttpClient.accessToken);
    }

    async waitForArmToFinish(projectId: number) {
        this.stopwatch.start();

        let lastStatus: ArmStatus;
        try {
            const waiter = new Waiter();
            lastStatus = await waiter.waitForTaskToFinish<ArmStatus>(
                () => this.checkIfPolicyCheckFinished(projectId),
                this.logWaitingProgress
            );
        } catch (e) {
            throw Error(`Waiting for server to retrieve policy violations has reached the time limit. (${Waiter.PollingSettings.masterTimeoutMinutes} minutes).`);
        }

        if (lastStatus !== ArmStatus.Finished) {
            throw Error(`Generation of scan report [id=${projectId}] failed.`);
        }
    }

    getProjectViolations(projectId: number, provider: ScanProvider) {
        const path = `/cxarm/policymanager/projects/${projectId}/violations?provider=${provider}`;
        if (!this.armHttpClient) {
            throw Error('The client was not initialized.');
        }

        return this.armHttpClient.getRequest(path);
    }

    private async checkIfPolicyCheckFinished(projectId: number) {
        const path = `sast/projects/${projectId}/publisher/policyFindings/status`;
        const statusResponse = await this.generalHttpClient.getRequest(path) as { status: ArmStatus };
        const {status} = statusResponse;
        if (status === ArmStatus.Finished ||
            status === ArmStatus.Failed ||
            status === ArmStatus.None) {
            return Promise.resolve(status);
        } else {
            return Promise.reject(status);
        }
    };

    private logWaitingProgress = (armStatus: ArmStatus) => {
        console.log(`Waiting for server to retrieve policy violations. Elapsed time: ${this.stopwatch.getElapsed()}. Status: ${armStatus}`)
    };
}