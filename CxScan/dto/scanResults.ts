export interface ScanResults {
    errorOccurred: boolean;
    buildFailed: false;
    url: string;
    syncMode: boolean;
    osaEnabled: boolean;
    enablePolicyViolations: boolean;
    sastThresholdExceeded: boolean;
    sastResultsReady: boolean;
    scanId: number;
    thresholdEnabled: boolean;
    highThreshold: any;
    mediumThreshold: any;
    lowThreshold: any;
    sastViolations: {
        libraryName: string,
        policyName: string,
        ruleName: string,
        detectionDate: string
    }[];
    sastPolicies: string[];
    policyViolated: boolean;

    highResults: number;
    mediumResults: number;
    lowResults: number;
    infoResults: number;

    sastScanResultsLink?: string;
    sastSummaryResultsLink?: string;
}