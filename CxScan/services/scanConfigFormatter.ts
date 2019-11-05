import {ScanConfig} from "../dto/scanConfig";
import {Logger} from "./logger";

export class ScanConfigFormatter {
    constructor(private readonly log: Logger) {
    }

    format(config: ScanConfig): void {
        const formatOptionalString = (input: string) => input || 'none';
        const formatOptionalNumber = (input: number | undefined) => (typeof input === 'undefined' ? 'none' : input);

        this.log.info(`
-------------------------------Configurations:--------------------------------
URL: ${config.serverUrl}
Project name: ${config.projectName}
Source location: ${config.sourceLocation}
Full team path: ${config.teamName}
Preset name: ${config.presetName}
Scan timeout in minutes: ${config.scanTimeoutInMinutes}
Deny project creation: ${config.denyProject}

Is incremental scan: ${config.isIncremental}
Folder exclusions: ${formatOptionalString(config.folderExclusion)}
File exclusions: ${formatOptionalString(config.fileExtension)}
Is synchronous scan: ${config.isSyncMode}

CxSAST thresholds enabled: ${config.vulnerabilityThreshold}`);

        if (config.vulnerabilityThreshold) {
            this.log.info(`CxSAST high threshold: ${formatOptionalNumber(config.highThreshold)}`);
            this.log.info(`CxSAST medium threshold: ${formatOptionalNumber(config.mediumThreshold)}`);
            this.log.info(`CxSAST low threshold: ${formatOptionalNumber(config.lowThreshold)}`);
        }

        this.log.info(`Enable Project Policy Enforcement: ${config.enablePolicyViolations}`);
        this.log.info('------------------------------------------------------------------------------');
    }
}