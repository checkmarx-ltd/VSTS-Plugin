import {ScanRequest} from "../dto/scanRequest";
import {ScanConfig} from "../dto/scanConfig";
import {HttpClient} from "./httpClient";
import promisePoller from "promise-poller";
import {ScanStatus} from "../dto/scanStatus";
import {ScanStage} from "../dto/scanStage";
import {PollingSettings} from "../pollingSettings";
import {Stopwatch} from "./stopwatch";
import {UpdateScanSettingsRequest} from "../dto/updateScanSettingsRequest";

export class SastClient {
    private static readonly scanCompletedDetails = 'Scan completed';

    private readonly stopwatch = new Stopwatch();

    private scanId: number = 0;

    constructor(private readonly config: ScanConfig, private readonly httpClient: HttpClient) {
    }

    async getPresetIdByName(presetName: string) {
        console.log(`Getting preset ID by name: [${presetName}]`);
        const allPresets = await this.httpClient.getRequest('sast/presets') as [{ name: string, id: number }];
        const currentPresetName = this.config.presetName.toUpperCase();
        let result: number = 0;
        for (const preset of allPresets) {
            if (preset.name.toUpperCase() === currentPresetName) {
                result = preset.id;
                break;
            }
        }

        if (!result) {
            throw Error(`Could not resolve preset ID from preset Name: ${presetName}`);
        }

        return result;
    }

    getScanSettings(projectId: number) {
        console.log('Getting scan settings.');
        return this.httpClient.getRequest(`sast/scanSettings/${projectId}`);
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

        this.stopwatch.start();
        return scan.id;
    }

    getScanStatistics(scanId: number) {
        return this.httpClient.getRequest(`sast/scans/${scanId}/resultsStatistics`);
    }

    updateScanSettings(request: UpdateScanSettingsRequest) {
        console.log('Updating scan settings.');
        return this.httpClient.postRequest('sast/scanSettings', request);
    }

    async waitForScanToFinish() {
        console.log('Waiting for CxSAST scan to finish.');

        try {
            const lastStatus = await promisePoller({
                taskFn: this.checkIfScanFinished,
                progressCallback: this.logWaitingProgress,
                interval: PollingSettings.intervalSeconds * 1000,
                masterTimeout: PollingSettings.scanTimeoutMinutes * 60 * 1000,
                retries: Number.MAX_SAFE_INTEGER
            });

            if (SastClient.isFinishedSuccessfully(lastStatus)) {
                console.log('SAST scan successfully finished.');
            } else {
                console.log(`SAST scan status: ${lastStatus.stage.value}, details: ${lastStatus.stageDetails}`);
            }
        } catch (e) {
            console.log(`Waiting for CxSAST scan has reached the time limit (${PollingSettings.scanTimeoutMinutes} minutes).`);
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
        const elapsed = this.stopwatch.getElapsed();
        const stage = scanStatus && scanStatus.stage ? scanStatus.stage.value : 'n/a';
        console.log(`Waiting for SAST scan results. Elapsed time: ${elapsed}. ${scanStatus.totalPercent}% processed. Status: ${stage}.`);
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