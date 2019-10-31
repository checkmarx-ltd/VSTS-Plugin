import taskLib = require('azure-pipelines-task-lib/task');
import {ScanConfig} from "./dto/scanConfig";
import {RestClient} from "./services/restClient";
import {TaskSkippedError} from "./dto/taskSkippedError";
import * as path from "path";
import * as os from "os";
import * as fs from "fs";
import {ScanResults} from "./dto/scanResults";
import {Logger} from "./services/logger";
import {ConsoleLogger} from "./services/consoleLogger";
import {ScanConfigFormatter} from "./services/scanConfigFormatter";

const recursiveMkdir = require('mkdirp');

class TaskRunner {
    private static readonly JSON_REPORT_FILENAME = 'cxreport.json';
    private static readonly REPORT_ATTACHMENT_NAME = 'cxReport';

    private readonly log: Logger = new ConsoleLogger();

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
            this.printHeader();

            const tempDir = this.createTempDirectory();
            const jsonReportPath = path.join(tempDir, TaskRunner.JSON_REPORT_FILENAME);

            this.log.info('Entering CxScanner...');

            const config = TaskRunner.createConfig();

            const formatter = new ScanConfigFormatter(this.log);
            formatter.format(config);

            const restClient = new RestClient(config, this.log);
            await restClient.init();
            await restClient.createSASTScan();

            if (!config.isSyncMode) {
                this.log.info('Running in Asynchronous mode. Not waiting for scan to finish');
                await this.attachJsonReport(restClient.scanResults, jsonReportPath);
                return;
            }

            await restClient.getSASTResults();
            await this.attachJsonReport(restClient.scanResults, jsonReportPath);

            if (restClient.scanResults.buildFailed) {
                taskLib.setResult(taskLib.TaskResult.Failed, 'Build failed');
            }
        } catch (err) {
            this.log.info(err);

            if (err instanceof TaskSkippedError) {
                taskLib.setResult(taskLib.TaskResult.Skipped, err.message);
            } else {
                taskLib.setResult(taskLib.TaskResult.Failed, `Scan cannot be completed: ${err.message}`);
            }
        }
    }

    private static createConfig(): ScanConfig {
        const supportedAuthScheme = 'UsernamePassword';
        const endpointId = taskLib.getInput('CheckmarxService', true) || '';

        const sourceLocation = taskLib.getVariable('Build.SourcesDirectory');
        if (typeof sourceLocation === 'undefined') {
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

        let rawTimeout = taskLib.getInput('scanTimeout', false) as any;
        let scanTimeoutInMinutes = +rawTimeout;
        if (!scanTimeoutInMinutes) {
            scanTimeoutInMinutes = -1;
        }

        return {
            serverUrl: taskLib.getEndpointUrl(endpointId, false),
            username: taskLib.getEndpointAuthorizationParameter(endpointId, 'username', false) || '',
            password: taskLib.getEndpointAuthorizationParameter(endpointId, 'password', false) || '',

            sourceLocation,
            projectName: taskLib.getInput('projectName', true) || '',
            teamName: taskLib.getInput('fullTeamName', true) || '',
            denyProject: taskLib.getBoolInput('denyProject', false),
            folderExclusion: taskLib.getInput('folderExclusion', false) || '',
            fileExtension: taskLib.getInput('fileExtension', false) || '',
            isIncremental: taskLib.getBoolInput('incScan', true),
            isSyncMode: taskLib.getBoolInput('syncMode', false),
            presetName,
            scanTimeoutInMinutes,
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

    private createTempDirectory(): string {
        const tempDir = path.join(
            os.tmpdir(),
            'cx_temp',
            taskLib.getVariable('Build.DefinitionName') || '',
            taskLib.getVariable('Build.BuildNumber') || '');

        if (!fs.existsSync(tempDir)) {
            recursiveMkdir.sync(tempDir);
            this.log.info(`Build-specific Checkmarx reports folder created at: ${tempDir}`);
        }
        return tempDir;
    }

    private async attachJsonReport(scanResults: ScanResults, jsonReportPath: string) {
        const reportJson = JSON.stringify(scanResults);

        await new Promise((resolve, reject) => {
            fs.writeFile(jsonReportPath, reportJson, err => {
                if (err) {
                    reject(err);
                } else {
                    resolve();
                }
            });
        });

        taskLib.addAttachment(TaskRunner.REPORT_ATTACHMENT_NAME, TaskRunner.REPORT_ATTACHMENT_NAME, jsonReportPath);
        this.log.info('Generated Checkmarx summary results');
    }

    private printHeader() {
        this.log.info(`
         CxCxCxCxCxCxCxCxCxCxCxCx          
        CxCxCxCxCxCxCxCxCxCxCxCxCx         
       CxCxCxCxCxCxCxCxCxCxCxCxCxCx        
      CxCxCx                CxCxCxCx       
      CxCxCx                CxCxCxCx       
      CxCxCx  CxCxCx      CxCxCxCxC        
      CxCxCx  xCxCxCx  .CxCxCxCxCx         
      CxCxCx   xCxCxCxCxCxCxCxCx           
      CxCxCx    xCxCxCxCxCxCx              
      CxCxCx     CxCxCxCxCx   CxCxCx       
      CxCxCx       xCxCxC     CxCxCx       
      CxCxCx                 CxCxCx        
       CxCxCxCxCxCxCxCxCxCxCxCxCxCx        
        CxCxCxCxCxCxCxCxCxCxCxCxCx         
          CxCxCxCxCxCxCxCxCxCxCx           
                                           
            C H E C K M A R X              
                                           
Starting Checkmarx scan`);
    }
}

const runner = new TaskRunner();
runner.run();