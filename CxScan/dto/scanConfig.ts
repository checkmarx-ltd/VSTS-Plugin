export interface ScanConfig {
    username: string;
    password: string;
    sourceDir: string;
    projectName: string;
    teamName?: string;
    serverUrl: string;
    isPublic: boolean;
    denyProject: boolean;
    isIncremental: boolean;
    forceScan: boolean;
    comment: string;
    isSyncMode: boolean;
    presetName: string;
    engineConfigurationId: number;

    enablePolicyViolations: boolean;
    vulnerabilityThreshold: boolean;
    highThreshold?: string;
    mediumThreshold?: string;
    lowThreshold?: string;
}