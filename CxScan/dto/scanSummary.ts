import {ThresholdError} from "./thresholdError";

export class ScanSummary {
    policyCheck: {
        wasPerformed: boolean,
        violatedPolicyNames: string[]
    } = {wasPerformed: false, violatedPolicyNames: []};

    thresholdErrors: ThresholdError[] = [];

    hasErrors = () => !!(this.policyCheck.violatedPolicyNames.length || this.thresholdErrors.length);
}

