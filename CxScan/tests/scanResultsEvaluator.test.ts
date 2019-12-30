import {ScanResultsEvaluator} from "../services/scanResultsEvaluator";
import {ScanResults} from "../dto/scanResults";
import {ScanConfig} from "../dto/scanConfig";
import {Logger} from "../services/logger";
import * as assert from "assert";

describe("ScanResultsEvaluator", function () {
    it('should mark build as failed if scan resulted in policy violation', function () {
        const config = getScanConfig();
        config.enablePolicyViolations = true;

        const scanResults = new ScanResults(config);
        scanResults.policyViolated = true;
        scanResults.buildFailed = false;

        const logger = getDummyLogger();

        const target = new ScanResultsEvaluator(scanResults, config, logger, true);
        target.evaluate();

        assert.equal(scanResults.buildFailed, true);
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
