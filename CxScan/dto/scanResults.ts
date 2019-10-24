export interface ScanResults {
    errorOccurred: boolean;
    buildFailed: false;
    url: string;
    syncMode: boolean;
    osaEnabled: boolean;
    enablePolicyViolations: boolean;
    sastThresholdExceeded: boolean;
    sastResultsReady: boolean;
    scanId: any;
    thresholdEnabled: boolean;
    highThreshold: any;
    mediumThreshold: any;
    lowThreshold: any;
    sastViolations: any[];
    sastPolicies: any[];
}