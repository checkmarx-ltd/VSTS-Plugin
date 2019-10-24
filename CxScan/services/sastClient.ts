import {ScanRequest} from "../dto/scanRequest";
import {ScanConfig} from "../dto/scanConfig";
import {HttpClient} from "./httpClient";
import promisePoller from "promise-poller";
// @ts-ignore
import Duration from "duration";
import {ScanStatus} from "../dto/scanStatus";
import {ScanStage} from "../dto/scanStage";

export class SastClient {
    private static readonly scanCompletedDetails = 'Scan completed';

    private static readonly pollingSettings = {
        scanTimeoutMinutes: 20,
        intervalSeconds: 10
    };

    private scanId: number = 0;
    private lastScanStart: Date = new Date(0);

    constructor(private config: ScanConfig, private httpClient: HttpClient) {
    }

    async createScan(projectId: number) {
        const request: ScanRequest = {
            projectId,
            isIncremental: this.config.isIncremental,
            isPublic: this.config.isPublic,
            forceScan: this.config.forceScan,
            comment: this.config.comment
        };

        const scan = await this.httpClient.postRequest('sast/scans', request);
        this.scanId = scan.id;

        this.lastScanStart = new Date();
        return scan.id;
    }

    async waitForScanToFinish() {
        console.log('Waiting for CxSAST scan to finish.');

        try {
            const lastStatus = await promisePoller({
                taskFn: this.checkIfScanFinished,
                progressCallback: this.logWaitingProgress,
                interval: SastClient.pollingSettings.intervalSeconds * 1000,
                masterTimeout: SastClient.pollingSettings.scanTimeoutMinutes * 60 * 1000,
                retries: Number.MAX_SAFE_INTEGER
            });

            if (SastClient.isFinishedSuccessfully(lastStatus)) {
                console.log('SAST scan successfully finished.');
            } else {
                console.log(`SAST scan status: ${lastStatus.stage.value}, details: ${lastStatus.stageDetails}`);
            }
        } catch (e) {
            console.log(`Waiting for CxSAST scan has reached the time limit (${SastClient.pollingSettings.scanTimeoutMinutes} minutes).`);
        }
    }

    private checkIfScanFinished = () => {
        return new Promise<ScanStatus>((resolve, reject) => {
            this.httpClient.getRequest(`sast/scansQueue/${this.scanId}`)
                .then((scanStatus: ScanStatus) => {
                    if (SastClient.isInProgress(scanStatus)) {
                        reject(scanStatus);
                    } else {
                        resolve(scanStatus);
                    }
                });
        });
    };

    private logWaitingProgress = (retriesRemaining: number, scanStatus: ScanStatus) => {
        const now = new Date();
        const duration = new Duration(this.lastScanStart, now);
        const elapsed = duration.toString('%H:%M:%S');
        const totalPercent = scanStatus ? scanStatus.totalPercent : 0;
        const padding = (totalPercent < 10 ? ' ' : '');
        const stage = scanStatus && scanStatus.stage ? scanStatus.stage.value : 'n/a';
        console.log(`Waiting for SAST scan results. Elapsed time: ${elapsed}. ${padding}${totalPercent}% processed. Status: ${stage}.`);
    };

    private static isFinishedSuccessfully(status: ScanStatus) {
        return status.stage.value === ScanStage.Finished ||
            status.stageDetails === SastClient.scanCompletedDetails;
    }

    private static isInProgress(scanStatus: ScanStatus) {
        let result = false;
        if (scanStatus && scanStatus.stage) {
            const stage = scanStatus.stage.value;
            result =
                stage !== ScanStage.Finished &&
                stage !== ScanStage.Failed &&
                stage !== ScanStage.Canceled &&
                stage !== ScanStage.Deleted &&
                scanStatus.stageDetails !== SastClient.scanCompletedDetails;
        }
        return result;
    }
}