import taskLib = require('azure-pipelines-task-lib/task');
import {ScanConfig} from "./dto/scanConfig";
import {RestClient} from "./services/restClient";
import {TaskSkippedError} from "./dto/taskSkippedError";
import * as path from "path";
import * as os from "os";
import * as fs from "fs";
import {ScanResults} from "./dto/scanResults";

const recursiveMkdir = require('mkdirp');

async function run() {
    const jsonReportFilename = 'cxreport.json';
    const reportAttachmentName = 'cxReport';

    // To run this task in console, the following environment variables must be defined:
    // INPUT_PROJECTNAME=VstsTest1;ENDPOINT_AUTH_PARAMETER_endpointId_USERNAME=myusername;
    // ENDPOINT_AUTH_PARAMETER_endpointId_PASSWORD=mypassword;INPUT_CheckmarxService=endpointId;
    // ENDPOINT_URL_endpointId=http://10.32.1.16;BUILD_SOURCESDIRECTORY=c:/cxdev/ProjectToScan;
    // INPUT_FULLTEAMNAME=CxServer

    try {
        const config = createConfig();

        const tempDir = createTempDirectory();
        const jsonReportPath = path.join(tempDir, jsonReportFilename);

        const restClient = new RestClient(config);
        await restClient.init();
        await restClient.createSASTScan();

        if (!config.isSyncMode) {
            console.log('Running in Asynchronous mode. Not waiting for scan to finish');
            await createJsonReport(restClient.scanResults, jsonReportPath);
            taskLib.addAttachment(reportAttachmentName, reportAttachmentName, jsonReportPath);
            return;
        }

        await restClient.getSASTResults();

    } catch (err) {
        console.log(err);
        let taskResult;
        if (err instanceof TaskSkippedError) {
            taskResult = taskLib.TaskResult.Skipped;
        } else {
            taskResult = taskLib.TaskResult.Failed;
        }
        taskLib.setResult(taskResult, err.message);
    }
}

function createConfig(): ScanConfig {
    const supportedAuthScheme = 'UserNamePassword';
    const endpointId = taskLib.getInput('CheckmarxService', true) || '';

    const sourceDir = taskLib.getVariable('Build.SourcesDirectory');
    if (typeof sourceDir === 'undefined') {
        throw Error('Sources directory is not provided.');
    }

    const authScheme = taskLib.getEndpointAuthorizationScheme(endpointId, false);
    if (authScheme !== supportedAuthScheme) {
        throw Error(`The authorization scheme ${authScheme} is not supported for a CX server.`);
    }

    return {
        serverUrl: taskLib.getEndpointUrl(endpointId, false),
        username: taskLib.getEndpointAuthorizationParameter(endpointId, 'username', false) || '',
        password: taskLib.getEndpointAuthorizationParameter(endpointId, 'password', false) || '',

        sourceDir,
        projectName: taskLib.getInput('projectName', true) || '',
        teamName: taskLib.getInput('fullTeamName', true),
        denyProject: taskLib.getBoolInput('denyProject', false),
        isIncremental: taskLib.getBoolInput('incScan', true),
        isSyncMode: taskLib.getBoolInput('syncMode', false),
        comment: taskLib.getInput('comment', false) || '',

        enablePolicyViolations: taskLib.getBoolInput('enablePolicyViolations', false),
        vulnerabilityThreshold: taskLib.getBoolInput('vulnerabilityThreshold', false),
        highThreshold: taskLib.getInput('high', false),
        mediumThreshold: taskLib.getInput('medium', false),
        lowThreshold: taskLib.getInput('low', false),

        // TODO: make sure the hardcoding is OK.
        forceScan: false,
        isPublic: true
    };
}

function createTempDirectory() {
    const tempDir = path.join(
        os.tmpdir(),
        'cx_temp',
        taskLib.getVariable('Build.DefinitionName') || '',
        taskLib.getVariable('Build.BuildNumber') || '');

    if (!fs.existsSync(tempDir)) {
        recursiveMkdir.sync(tempDir);
        console.log(`Build-specific Checkmarx reports folder created at: ${tempDir}`);
    }
    return tempDir;
}

function createJsonReport(scanResults: ScanResults, jsonReportPath: string) {
    const reportJson = JSON.stringify(scanResults);

    return new Promise(function (resolve, reject) {
        fs.writeFile(jsonReportPath, reportJson, err => {
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        });

    });
}

run();