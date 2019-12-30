import {ScanSummaryEvaluator} from "../services/scanSummaryEvaluator";
import {ScanResults} from "../dto/scanResults";
import {ScanConfig} from "../dto/scanConfig";
import {Logger} from "../services/logger";
import * as assert from "assert";

describe("ScanSummaryEvaluator", function () {
    it('should return violated policy names in summary', function () {
        const config = getScanConfig();
        config.enablePolicyViolations = true;

        const scanResults = new ScanResults(config);
        scanResults.sastPolicies = ['policy1', 'policy2'];

        const logger = getDummyLogger();

        const target = new ScanSummaryEvaluator(config, logger, true);
        const summary = target.getScanSummary(scanResults);
        assert.ok(summary);
        assert.ok(summary.policyCheck);
        assert.ok(summary.policyCheck.wasPerformed);
        assert.deepStrictEqual(summary.policyCheck.violatedPolicyNames, scanResults.sastPolicies);
    });
});

function getScanConfig(): ScanConfig {
    return {
        comment: "",
        denyProject: false,
        enablePolicyViolations: false,
        fileExtension: "",
        folderExclusion: "",
        forceScan: false,
        isIncremental: false,
        isPublic: false,
        isSyncMode: false,
        password: "",
        presetName: "",
        projectName: "",
        serverUrl: "",
        sourceLocation: "",
        teamName: "",
        username: "",
        vulnerabilityThreshold: false
    };
}

function getDummyLogger(): Logger {
    return {
        debug() {
        },
        error() {
        },
        info() {
        },
        warning() {
        }
    };
}
