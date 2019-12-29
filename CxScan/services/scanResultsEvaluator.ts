import {Logger} from "./logger";
import {ScanResults} from "../dto/scanResults";
import {ScanConfig} from "../dto/scanConfig";

/**
 * Determines if the current build has failed, using provided scan results and configuration.
 * Logs the reasons why the build has failed, if any.
 */
export class ScanResultsEvaluator {
    constructor(private readonly scanResults: ScanResults,
                private readonly config: ScanConfig,
                private readonly log: Logger,
                private readonly isPolicyEnforcementSupported: boolean) {
    }

    evaluate(): void {
        this.checkForPolicyViolations();
        this.checkForExceededThresholds();
    }

    private checkForPolicyViolations() {
        if (!this.config.enablePolicyViolations || !this.isPolicyEnforcementSupported) {
            return;
        }

        this.log.info(
            `-----------------------------------------------------------------------------------------
Policy Management:
--------------------`);

        if (!this.scanResults.sastPolicies.length) {
            this.log.info('Project policy status: compliant');
        } else {
            this.log.info('Project policy status: violated');

            const names = this.scanResults.sastPolicies.join(', ');
            this.log.info(`SAST violated policies names: ${names}`);
        }
        this.log.info('-----------------------------------------------------------------------------------------');

        if (this.scanResults.policyViolated) {
            this.logBuildFailure('Project policy status: violated');
        }
    }

    private checkForExceededThresholds() {
        if (this.config.vulnerabilityThreshold && this.checkIfSastThresholdExceeded()) {
            this.logBuildFailure('Exceeded CxSAST Vulnerability Threshold.');
        }
    }

    private checkIfSastThresholdExceeded() {
        const highExceeded = this.isLevelThresholdExceeded(this.scanResults.highResults, this.scanResults.highThreshold, 'high');
        const mediumExceeded = this.isLevelThresholdExceeded(this.scanResults.mediumResults, this.scanResults.mediumThreshold, 'medium');
        const lowExceeded = this.isLevelThresholdExceeded(this.scanResults.lowResults, this.scanResults.lowThreshold, 'low');
        return highExceeded || mediumExceeded || lowExceeded;
    }

    private isLevelThresholdExceeded(amountToCheck: number, threshold: number | undefined, severity: string): boolean {
        let result = false;
        if (typeof threshold !== 'undefined') {
            if (threshold < 0) {
                throw Error('Threshold must be 0 or greater');
            }

            if (amountToCheck > threshold) {
                this.logBuildFailure(`SAST ${severity} severity results are above threshold. Results: ${amountToCheck}. Threshold: ${threshold}`);
                result = true;
            }
        }
        return result;
    }

    private logBuildFailure(reason: string) {
        if (!this.scanResults.buildFailed) {
            this.log.error(
                `********************************************
The Build Failed for the Following Reasons:
********************************************`);

            this.scanResults.buildFailed = true;
        }
        this.log.error(reason);
    }
}