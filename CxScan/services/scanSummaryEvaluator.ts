import {Logger} from "./logger";
import {ScanResults} from "../dto/scanResults";
import {ScanConfig} from "../dto/scanConfig";
import {ScanSummary} from "../dto/scanSummary";
import {ThresholdError} from "../dto/thresholdError";

export class ScanSummaryEvaluator {
    constructor(private readonly config: ScanConfig,
                private readonly log: Logger,
                private readonly isPolicyEnforcementSupported: boolean) {
    }

    /**
     * Generates scan summary with error info, if any.
     */
    getScanSummary(scanResult: ScanResults): ScanSummary {
        const result = new ScanSummary();
        result.policyCheck = this.getPolicyCheckSummary(scanResult);
        result.thresholdErrors = this.getThresholdErrors(scanResult);
        return result;
    }

    private getPolicyCheckSummary(scanResult: ScanResults) {
        let result;
        if (this.config.enablePolicyViolations && this.isPolicyEnforcementSupported) {
            result = {
                wasPerformed: true,
                violatedPolicyNames: scanResult.sastPolicies
            };
        } else {
            result = {
                wasPerformed: false,
                violatedPolicyNames: []
            };
        }
        return result;
    }

    private getThresholdErrors(scanResult: ScanResults) {
        let result: ThresholdError[];
        if (this.config.vulnerabilityThreshold) {
            result = this.getSastThresholdErrors(scanResult);
        } else {
            result = [];
        }
        return result;
    }

    private getSastThresholdErrors(scanResult: ScanResults) {
        const result: ThresholdError[] = [];
        ScanSummaryEvaluator.addThresholdErrors(scanResult.highResults, this.config.highThreshold, 'high', result);
        ScanSummaryEvaluator.addThresholdErrors(scanResult.mediumResults, this.config.mediumThreshold, 'medium', result);
        ScanSummaryEvaluator.addThresholdErrors(scanResult.lowResults, this.config.lowThreshold, 'low', result);
        return result;
    }

    private static addThresholdErrors(amountToCheck: number,
                                      threshold: number | undefined,
                                      severity: string,
                                      target: ThresholdError[]) {
        if (typeof threshold !== 'undefined') {
            if (threshold < 0) {
                throw Error('Threshold must be 0 or greater');
            }

            if (amountToCheck > threshold) {
                target.push({
                    severity,
                    actualViolationCount: amountToCheck,
                    threshold
                });
            }
        }
    }
}