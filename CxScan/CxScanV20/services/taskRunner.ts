import taskLib = require('azure-pipelines-task-lib/task');
import {ConsoleLogger} from "./consoleLogger";
import {ConfigReader} from "./configReader";
import * as fs from "fs";
import {tmpNameSync} from "tmp";
import {CxClient, ScanConfig,Logger,TaskSkippedError,ScanResults} from "@checkmarx/cx-common-js-client";
import * as path from "path";

export class TaskRunner {
    private static readonly REPORT_ATTACHMENT_NAME = 'cxReport';
    private static readonly PDF_REPORT_ATTACHMENT_NAME = 'cxPDFReport';
    private static readonly REPORT_SCA_PACKAGES = 'cxSCAPackages';
    private static readonly REPORT_SCA_FINDINGS = 'cxSCAVulnerabilities';
    private static readonly REPORT_SCA_SUMMARY = 'cxSCASummary';
    private static readonly CxSAST = 'SAST';
    private static readonly CxDependency = 'SCA';
    private readonly MinValue = 1;
    private readonly MaxValue = 60;

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
        const errorMessage = "cannot be completed";
        const avoidDuplicateErrorMessage = "Project scan is already in progress";
        try {
            this.printHeader();

            this.log.info('Entering CxScanner...');
            const reader = new ConfigReader(this.log);
            const config = reader.readConfig();

            if(this.validateConfigParameter(config))
            {
                this.log.info('Inside validateConfigParameter');
                const cxClient = new CxClient(this.log);
                const scanResults: ScanResults = await cxClient.scan(config);
                await this.attachJsonReport(scanResults);
                if (scanResults.buildFailed) {
                    taskLib.setResult(taskLib.TaskResult.Failed, 'Build failed');
                }
            }
        } catch (err) {
            if (err instanceof TaskSkippedError) {
                taskLib.setResult(taskLib.TaskResult.Skipped, err.message);
            } else if (err instanceof Error) {
                if(err.message.includes(errorMessage)){
                    taskLib.setResult(taskLib.TaskResult.Failed, err.message);
                }
                else if (err.message.includes(avoidDuplicateErrorMessage)){                    
                    taskLib.setResult(taskLib.TaskResult.Succeeded, `Scan cannot be completed. ${err.message}`);                       
                    this.log.warning(`Scan cannot be completed. ${err.message}`);
                }
                else{
                    taskLib.setResult(taskLib.TaskResult.Failed, `Scan cannot be completed. ${err.message}`);
                }

            } else {
                taskLib.setResult(taskLib.TaskResult.Failed, `Scan cannot be completed. ${err}`);
            }
        }
    }

    private async attachJsonReport(scanResults: ScanResults) {
        const jsonReportPath = TaskRunner.generateJsonReportPath(TaskRunner.REPORT_ATTACHMENT_NAME);

        const reportJson = JSON.stringify(scanResults);
        let pdfReportPath = '';
        let scaPackages ='';
        let scaFindings ='';
        let scaSummary ='';
        let scaPackagesPath = '';
        let scaFindingsPath = '';
        let scaSummaryPath = '';

        if(scanResults.generatePDFReport){
            pdfReportPath = TaskRunner.generateJsonReportPath(TaskRunner.PDF_REPORT_ATTACHMENT_NAME);
            this.log.info(`Build Directory: ${pdfReportPath}`);
        }

        if(scanResults.scaResults){
            scaPackages = JSON.stringify(scanResults.scaResults.packages);
            scaFindings = JSON.stringify(scanResults.scaResults.dependencyHighCVEReportTable.concat(scanResults.scaResults.dependencyMediumCVEReportTable,scanResults.scaResults.dependencyLowCVEReportTable));
            scaSummary = JSON.stringify(scanResults.scaResults.summary)
            scaPackagesPath= TaskRunner.generateJsonReportPath(TaskRunner.REPORT_SCA_PACKAGES);
            scaFindingsPath= TaskRunner.generateJsonReportPath(TaskRunner.REPORT_SCA_FINDINGS);
            scaSummaryPath= TaskRunner.generateJsonReportPath(TaskRunner.REPORT_SCA_SUMMARY);
        }


        await this.writeReportFile(jsonReportPath,reportJson);
        taskLib.addAttachment(TaskRunner.REPORT_ATTACHMENT_NAME, TaskRunner.REPORT_ATTACHMENT_NAME, jsonReportPath);

        if(scanResults.generatePDFReport){
            await this.writePDFReportFile(pdfReportPath, scanResults.reportPDF);
            taskLib.addAttachment(TaskRunner.PDF_REPORT_ATTACHMENT_NAME, TaskRunner.PDF_REPORT_ATTACHMENT_NAME, pdfReportPath);
        }
        
        if(scanResults.scaResults){
            await this.writeReportFile(scaPackagesPath,scaPackages);
            taskLib.addAttachment(TaskRunner.REPORT_SCA_PACKAGES, TaskRunner.REPORT_SCA_PACKAGES, scaPackagesPath);
            await this.writeReportFile(scaSummaryPath,scaSummary);
            taskLib.addAttachment(TaskRunner.REPORT_SCA_SUMMARY, TaskRunner.REPORT_SCA_SUMMARY, scaSummaryPath);
            await this.writeReportFile(scaFindingsPath,scaFindings);
            taskLib.addAttachment(TaskRunner.REPORT_SCA_FINDINGS, TaskRunner.REPORT_SCA_FINDINGS,scaFindingsPath);
        }
        this.log.info('Generated Checkmarx summary results.');
    }
    private async writePDFReportFile(pdfReportPath:string, pdfReport: any){
        this.log.info(`Writing PDF report to ${pdfReportPath}`);
        await new Promise((resolve, reject) => {
            fs.writeFile(pdfReportPath, pdfReport, err => {
                if (err) {
                    reject(err);
                } else {
                    resolve(pdfReportPath);
                }
            });
        });
    }

    private async writeReportFile(jsonReportPath:string,jsonReport:string){
        this.log.info(`Writing report to ${jsonReportPath}`);
        await new Promise((resolve, reject) => {
            fs.writeFile(jsonReportPath, jsonReport, err => {
                if (err) {
                    reject(err);
                } else {
                    resolve(jsonReportPath);
                }
            });
        });
    }

    private static generateJsonReportPath(reportType : string) {
        // A temporary folder that is cleaned after each pipeline run, so we don't have to remove
        // temp files manually.
        let buildDir = taskLib.getVariable('Agent.BuildDirectory');
        let buildNumber = taskLib.getVariable('Build.BuildNumber');


        if(buildDir && reportType !== TaskRunner.PDF_REPORT_ATTACHMENT_NAME){
            return buildDir+path.sep+reportType+'_'+buildNumber+'.json';
        }
        else if(buildDir && reportType === TaskRunner.PDF_REPORT_ATTACHMENT_NAME){
            return buildDir+path.sep+reportType+'_'+buildNumber+'.pdf';
        }
        // If the agent variable above is not specified (e.g. in debug environment), tempDir is undefined and
        // tmpNameSync function falls back to a default temp directory.
        let result;
        switch (reportType) {
            case TaskRunner.REPORT_ATTACHMENT_NAME:
                result = tmpNameSync({dir: buildDir, prefix: 'cxreport-', postfix: '.json'});
                break;
            case TaskRunner.PDF_REPORT_ATTACHMENT_NAME:
                result = tmpNameSync({dir: buildDir, prefix: 'cxPDFReport-', postfix: '.pdf'});
                break;
            case TaskRunner.REPORT_SCA_PACKAGES:
                result = tmpNameSync({dir: buildDir, prefix: this.REPORT_SCA_PACKAGES, postfix: '.json'});
                break;
            case TaskRunner.REPORT_SCA_FINDINGS:
                result = tmpNameSync({dir: buildDir, prefix: this.REPORT_SCA_FINDINGS, postfix: '.json'});
                break;
            case TaskRunner.REPORT_SCA_SUMMARY:
                result = tmpNameSync({dir: buildDir, prefix: this.REPORT_SCA_SUMMARY, postfix: '.json'});
                break;
            default:
                result =  tmpNameSync({dir: buildDir, prefix: 'cxreport-', postfix: '.json'});
                break;
        }
        return result;
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

    private validateConfigParameter(config :ScanConfig) : boolean
    {
        let sastWaitTime = taskLib.getInput('waitingTimeBeforeRetryScan', false) as any;
        let scaWaitTime = taskLib.getInput('waitingTimeBeforeRetrySCAScan', false) as any;
        if(config.enableSastScan && sastWaitTime!=undefined && sastWaitTime.trim() != '')
        {
            if(isNaN(sastWaitTime))
            {
                taskLib.setResult(taskLib.TaskResult.Failed, 'Waiting time before retry scan input is invalid value.');
                return false;
            }
            else if (sastWaitTime <= this.MinValue || sastWaitTime >= this.MaxValue) {
                taskLib.setResult(taskLib.TaskResult.Failed, `Waiting time before retry scan value must be a between ${this.MinValue} and ${this.MaxValue}.`);
                return false;
            }
        }  

        if(config.enableDependencyScan && scaWaitTime!= undefined && scaWaitTime.trim() != '')
        {
            this.log.info('inside function');
            if(isNaN(scaWaitTime))
            {
                taskLib.setResult(taskLib.TaskResult.Failed, 'Waiting time before retry sca scan input is invalid value.');
                return false;
            }
            else if (scaWaitTime <= this.MinValue || scaWaitTime >= this.MaxValue) {
                taskLib.setResult(taskLib.TaskResult.Failed, `Waiting time before retry sca scan value must be a between ${this.MinValue} and ${this.MaxValue}.`);
                return false;
            }
        }
        return true;
    }

}