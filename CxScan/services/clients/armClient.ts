import {HttpClient} from "./httpClient";
import {ArmStatus} from "../../dto/api/armStatus";
import {Stopwatch} from "../stopwatch";
import {ScanProvider} from "../../dto/api/scanProvider";
import {Waiter} from "../waiter";
import {PolicyViolationGroup} from "../../dto/api/policyViolationGroup";
import {Logger} from "../logger";
import {PollingSettings} from "../../dto/pollingSettings";

/**
 * Works with policy-related APIs.
 */
export class ArmClient {
    private static readonly pollingSettings: PollingSettings = {
        intervalSeconds: 10,
        masterTimeoutMinutes: 20
    };

    private readonly stopwatch = new Stopwatch();

    private armUrl = '';

    constructor(private readonly httpClient: HttpClient, private readonly log: Logger) {
    }

    async init() {
        this.log.info('Resolving CxARM URL.');

        const response = await this.httpClient.getRequest('Configurations/Portal');
        this.armUrl = response.cxARMPolicyURL;
        this.log.debug(`Resolved CxARM URL: ${this.armUrl}`);
    }

    async waitForArmToFinish(projectId: number) {
        this.stopwatch.start();

        this.log.info('Waiting for server to retrieve policy violations.');
        let lastStatus = ArmStatus.None;
        try {
            const waiter = new Waiter();
            lastStatus = await waiter.waitForTaskToFinish<ArmStatus>(
                () => this.checkIfPolicyVerificationCompleted(projectId),
                this.logWaitingProgress,
                ArmClient.pollingSettings
            );
        } catch (e) {
            throw Error(`Waiting for server to retrieve policy violations has reached the time limit. (${ArmClient.pollingSettings.masterTimeoutMinutes} minutes).`);
        }

        if (lastStatus !== ArmStatus.Finished) {
            throw Error(`Generation of scan report [id=${projectId}] failed.`);
        }
    }

    getProjectViolations(projectId: number, provider: ScanProvider): Promise<PolicyViolationGroup[]> {
        const path = `/cxarm/policymanager/projects/${projectId}/violations?provider=${provider}`;
        return this.httpClient.getRequest(path, {baseUrlOverride: this.armUrl});
    }

    private async checkIfPolicyVerificationCompleted(projectId: number) {
        const path = `sast/projects/${projectId}/publisher/policyFindings/status`;
        const statusResponse = await this.httpClient.getRequest(path) as { status: ArmStatus };
        const {status} = statusResponse;

        const isCompleted =
            status === ArmStatus.Finished ||
            status === ArmStatus.Failed ||
            status === ArmStatus.None;

        if (isCompleted) {
            return Promise.resolve(status);
        } else {
            return Promise.reject(status);
        }
    };

    private logWaitingProgress = (armStatus: ArmStatus) => {
        this.log.info(`Waiting for server to retrieve policy violations. Elapsed time: ${this.stopwatch.getElapsedString()}. Status: ${armStatus}`)
    };
}