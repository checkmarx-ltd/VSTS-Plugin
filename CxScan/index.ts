import taskLib = require('azure-pipelines-task-lib/task');
import {ScanConfig} from "./dto/scanConfig";
import {RestClient} from "./services/restClient";
import {TaskSkippedError} from "./dto/taskSkippedError";
import * as path from "path";
import * as os from "os";
import * as fs from "fs";
import {ScanResults} from "./dto/scanResults";

const recursiveMkdir = require('mkdirp');

class TaskRunner {
    private static readonly jsonReportFilename = 'cxreport.json';
    private static readonly reportAttachmentName = 'cxReport';

    /*
     To run this task in console, task inputs must be provided in environment variables.
     The names of the environment variables use prefixes and must look like this:
         INPUT_CheckmarxService=myendpoint123
         ENDPOINT_URL_myendpoint123=http://example.com
         ENDPOINT_AUTH_PARAMETER_myendpoint123_USERNAME=myusername
         ENDPOINT_AUTH_PARAMETER_myendpoint123_PASSWORD=mypassword
         ENDPOINT_AUTH_SCHEME_myendpoint123=UsernamePassword
         BUILD_SOURCESDIRECTORY=c:\projectsToScan\MyProject
         INPUT_PROJECTNAME=VstsTest1
         INPUT_FULLTEAMNAME=\CxServer
         ...
    */
    async run() {
        try {
            const config = TaskRunner.createConfig();

            const tempDir = TaskRunner.createTempDirectory();
            const jsonReportPath = path.join(tempDir, TaskRunner.jsonReportFilename);

            const restClient = new RestClient(config);
            await restClient.init();
            await restClient.createSASTScan();

            if (!config.isSyncMode) {
                console.log('Running in Asynchronous mode. Not waiting for scan to finish');
                await this.attachJsonReport(restClient.scanResults, jsonReportPath);
                return;
            }

            await restClient.getSASTResults();
            await this.attachJsonReport(restClient.scanResults, jsonReportPath);

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

    private static createConfig(): ScanConfig {
        const supportedAuthScheme = 'UsernamePassword';
        const endpointId = taskLib.getInput('CheckmarxService', true) || '';

        const sourceDir = taskLib.getVariable('Build.SourcesDirectory');
        if (typeof sourceDir === 'undefined') {
            throw Error('Sources directory is not provided.');
        }

        const authScheme = taskLib.getEndpointAuthorizationScheme(endpointId, false);
        if (authScheme !== supportedAuthScheme) {
            throw Error(`The authorization scheme ${authScheme} is not supported for a CX server.`);
        }

        let presetName;
        const customPreset = taskLib.getInput('customPreset', false);
        if (customPreset) {
            presetName = customPreset;
        } else {
            presetName = taskLib.getInput('preset', true) || '';
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
            presetName,
            comment: taskLib.getInput('comment', false) || '',

            enablePolicyViolations: taskLib.getBoolInput('enablePolicyViolations', false),
            vulnerabilityThreshold: taskLib.getBoolInput('vulnerabilityThreshold', false),
            highThreshold: TaskRunner.getNumericInput('high'),
            mediumThreshold: TaskRunner.getNumericInput('medium'),
            lowThreshold: TaskRunner.getNumericInput('low'),

            // TODO: make sure the hardcoding is OK.
            forceScan: false,
            isPublic: true,
            engineConfigurationId: 0
        };
    }

    private static getNumericInput(name: string): number | undefined {
        const rawValue = taskLib.getInput(name, false);
        let result;
        if (typeof rawValue !== 'undefined') {
            result = +rawValue;
        }
        return result;
    }

    private static createTempDirectory(): string {
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

    private async attachJsonReport(scanResults: ScanResults, jsonReportPath: string) {
        const reportJson = JSON.stringify(scanResults);

        await new Promise(function (resolve, reject) {
            fs.writeFile(jsonReportPath, reportJson, err => {
                if (err) {
                    reject(err);
                } else {
                    resolve();
                }
            });

        });

        taskLib.addAttachment(TaskRunner.reportAttachmentName, TaskRunner.reportAttachmentName, jsonReportPath);
    }
}

const runner = new TaskRunner();
runner.run();