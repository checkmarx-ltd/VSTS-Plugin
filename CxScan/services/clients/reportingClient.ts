import {HttpClient} from "./httpClient";
import {Logger} from "../logger";
import {Waiter} from "../waiter";
import {ReportStatus} from "../../dto/api/reportStatus";
import {PollingSettings} from "../../dto/pollingSettings";
import {Stopwatch} from "../stopwatch";
import * as xml2js from "xml2js";

/**
 * Uses Cx API to generate and download XMl reports.
 */
export class ReportingClient {
    private static readonly REPORT_TYPE = 'XML';

    private static readonly pollingSettings: PollingSettings = {
        intervalSeconds: 5,
        masterTimeoutMinutes: 8
    };

    private readonly stopwatch = new Stopwatch();

    constructor(private readonly httpClient: HttpClient, private readonly log: Logger) {
    }

    async generateReport(scanId: number) {
        const reportId = await this.startReportGeneration(scanId);
        await this.waitForReportGenerationToFinish(reportId);
        return this.getReport(reportId);
    }

    private async startReportGeneration(scanId: number) {
        const request = {
            scanId: scanId,
            reportType: ReportingClient.REPORT_TYPE
        };
        const response = await this.httpClient.postRequest('reports/sastScan', request);
        return response.reportId;
    }

    private async waitForReportGenerationToFinish(reportId: number) {
        this.stopwatch.start();

        this.log.info(`Waiting for server to generate ${ReportingClient.REPORT_TYPE} report.`);
        let lastStatus: ReportStatus;
        try {
            const waiter = new Waiter();
            lastStatus = await waiter.waitForTaskToFinish(
                () => this.checkIfReportIsCompleted(reportId),
                this.logWaitingProgress,
                ReportingClient.pollingSettings
            );
        } catch (e) {
            throw Error(`Waiting for ${ReportingClient.REPORT_TYPE} report generation has reached the time limit (${ReportingClient.pollingSettings.masterTimeoutMinutes} minutes).`);
        }

        if (lastStatus === ReportStatus.Created) {
            this.log.info(`${ReportingClient.REPORT_TYPE} report was created successfully.`);
        } else {
            throw Error(`${ReportingClient.REPORT_TYPE} report cannot be generated. Status [${lastStatus}].`);
        }
    }

    private async getReport(reportId: number) {
        const reportBytes = await this.httpClient.getRequest(`reports/sastScan/${reportId}`) as Uint8Array;
        const reportBuffer = new Buffer(reportBytes);
        return xml2js.parseStringPromise(reportBuffer);
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
        const timeout = ReportingClient.pollingSettings.masterTimeoutMinutes as number;
        let secondsLeft = timeout * 60 - this.stopwatch.getElapsedSeconds();
        if (secondsLeft < 0) {
            secondsLeft = 0;
        }
        this.log.info(`Waiting for server to generate ${ReportingClient.REPORT_TYPE} report. ${secondsLeft} seconds left to timeout.`);
    };
}