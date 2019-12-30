export interface ScanRequest {
    projectId: number,
    isIncremental: boolean,
    isPublic: boolean,
    forceScan: boolean,
    comment: string
}