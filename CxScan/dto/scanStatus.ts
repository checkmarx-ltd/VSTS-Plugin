import {ScanStage} from "./scanStage";

export interface ScanStatus {
    stage: {
        value: ScanStage
    },
    stageDetails: string,
    totalPercent: number
}