import taskLib = require('azure-pipelines-task-lib/task');
import {Logger} from "./logger";
import {ConsoleLogger} from "./consoleLogger";
import {ConfigReader} from "./configReader";
import {CxClient} from "./clients/cxClient";
import {TaskSkippedError} from "../dto/taskSkippedError";
import {ScanResults} from "../dto/scanResults";
import {FileUtil} from "./fileUtil";
import * as fs from "fs";

export class TaskRunner {
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

            this.log.info('Entering CxScanner...');

            const reader = new ConfigReader(this.log);
            const config = reader.readConfig();

            const cxClient = new CxClient(this.log);
            const scanResults: ScanResults = await cxClient.scan(config);
            await this.attachJsonReport(scanResults);

            if (scanResults.buildFailed) {
                taskLib.setResult(taskLib.TaskResult.Failed, 'Build failed');
            }
        } catch (err) {
            if (err instanceof TaskSkippedError) {
                taskLib.setResult(taskLib.TaskResult.Skipped, err.message);
            } else if (err instanceof Error) {
                this.log.error(`Scan cannot be completed. ${err.stack}`);
                taskLib.setResult(taskLib.TaskResult.Failed, `Scan cannot be completed. ${err.message}`);
            } else {
                taskLib.setResult(taskLib.TaskResult.Failed, `Scan cannot be completed. ${err}`);
            }
        }
    }

    private async attachJsonReport(scanResults: ScanResults) {
        const jsonReportPath = FileUtil.generateTempFileName({prefix: 'cxreport-', postfix: '.json'});
        const reportJson = JSON.stringify(scanResults);

        this.log.debug(`Writing report to ${jsonReportPath}`);
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
        this.log.info('Generated Checkmarx summary results.');
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