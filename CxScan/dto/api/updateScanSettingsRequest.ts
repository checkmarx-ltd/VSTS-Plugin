export interface UpdateScanSettingsRequest {
    projectId: number,
    presetId: number,
    engineConfigurationId: number,
    postScanActionId?: number,
    emailNotifications?: object,
}