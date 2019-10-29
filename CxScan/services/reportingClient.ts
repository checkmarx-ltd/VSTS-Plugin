import {HttpClient} from "./httpClient";
import {Logger} from "./logger";
import {Waiter} from "./waiter";
import {ReportStatus} from "../dto/reportStatus";
import {PollingSettings} from "../dto/pollingSettings";
import {Stopwatch} from "./stopwatch";

export class ReportingClient {
    private static readonly reportType = 'XML';

    private readonly stopwatch = new Stopwatch();

    private static pollingSettings: PollingSettings = {
        intervalSeconds: 5,
        masterTimeoutMinutes: 8
    };

    constructor(private readonly httpClient: HttpClient, private readonly log: Logger) {
    }

    async startReportCreation(scanId: number) {
        const request = {
            scanId: scanId,
            reportType: ReportingClient.reportType
        };
        const response = await this.httpClient.postRequest('reports/sastScan', request);
        return response.reportId;
    }

    async waitForReportToFinish(reportId: number) {
        this.stopwatch.start();

        this.log.info(`Waiting for server to generate ${ReportingClient.reportType} report.`);
        let lastStatus: ReportStatus;
        try {
            const waiter = new Waiter();
            lastStatus = await waiter.waitForTaskToFinish(
                () => this.checkIfReportIsCompleted(reportId),
                this.logWaitingProgress,
                ReportingClient.pollingSettings
            );
        } catch (e) {
            throw Error(`Waiting for ${ReportingClient.reportType} report generation has reached the time limit (${ReportingClient.pollingSettings.masterTimeoutMinutes} minutes).`);
        }

        if (lastStatus === ReportStatus.Created) {
            this.log.info(`${ReportingClient.reportType} report was created successfully.`);
        } else {
            throw Error(`${ReportingClient.reportType} report cannot be generated. Status [${lastStatus}].`);
        }
    }

    private async checkIfReportIsCompleted(reportId: number) {
        const path = `reports/sastScan/${reportId}/status`;
        const response = await this.httpClient.getRequest(path);
        const status = response.status.value;

        const isCompleted =
            status === ReportStatus.Deleted ||
            status === ReportStatus.Failed ||
            status === ReportStatus.Created;

        if (isCompleted) {
            return Promise.resolve(status);
        } else {
            return Promise.reject(status);
        }
    }

    private logWaitingProgress = () => {
        let secondsLeft = ReportingClient.pollingSettings.masterTimeoutMinutes * 60 - this.stopwatch.getElapsedSeconds();
        if (secondsLeft < 0) {
            secondsLeft = 0;
        }
        this.log.info(`Waiting for server to generate ${ReportingClient.reportType} report. ${secondsLeft} seconds left to timeout`);
    };
}