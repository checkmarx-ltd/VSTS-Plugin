import {PolicyViolation} from "./policyViolation";

export interface PolicyViolationGroup {
    violations: PolicyViolation[];
    policyName: string;
}