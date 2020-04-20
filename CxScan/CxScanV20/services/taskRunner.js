"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
var taskLib = require("azure-pipelines-task-lib/task");
var consoleLogger_1 = require("./consoleLogger");
var configReader_1 = require("./configReader");
var fs = require("fs");
var tmp_1 = require("tmp");
var cx_common_js_client_1 = require("@checkmarx/cx-common-js-client");
var cx_common_js_client_2 = require("@checkmarx/cx-common-js-client");
var TaskRunner = /** @class */ (function () {
    function TaskRunner() {
        this.log = new consoleLogger_1.ConsoleLogger();
    }
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
    TaskRunner.prototype.run = function () {
        return __awaiter(this, void 0, void 0, function () {
            var reader, config, cxClient, scanResults, err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 3, , 4]);
                        this.printHeader();
                        this.log.info('Entering CxScanner...');
                        reader = new configReader_1.ConfigReader(this.log);
                        config = reader.readConfig();
                        cxClient = new cx_common_js_client_1.CxClient(this.log);
                        return [4 /*yield*/, cxClient.scan(config)];
                    case 1:
                        scanResults = _a.sent();
                        return [4 /*yield*/, this.attachJsonReport(scanResults)];
                    case 2:
                        _a.sent();
                        if (scanResults.buildFailed) {
                            taskLib.setResult(taskLib.TaskResult.Failed, 'Build failed');
                        }
                        return [3 /*break*/, 4];
                    case 3:
                        err_1 = _a.sent();
                        if (err_1 instanceof cx_common_js_client_2.TaskSkippedError) {
                            taskLib.setResult(taskLib.TaskResult.Skipped, err_1.message);
                        }
                        else if (err_1 instanceof Error) {
                            this.log.error("Scan cannot be completed. " + err_1.stack);
                            taskLib.setResult(taskLib.TaskResult.Failed, "Scan cannot be completed. " + err_1.message);
                        }
                        else {
                            taskLib.setResult(taskLib.TaskResult.Failed, "Scan cannot be completed. " + err_1);
                        }
                        return [3 /*break*/, 4];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    TaskRunner.prototype.attachJsonReport = function (scanResults) {
        return __awaiter(this, void 0, void 0, function () {
            var jsonReportPath, reportJson;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        jsonReportPath = TaskRunner.generateJsonReportPath();
                        reportJson = JSON.stringify(scanResults);
                        this.log.debug("Writing report to " + jsonReportPath);
                        return [4 /*yield*/, new Promise(function (resolve, reject) {
                                fs.writeFile(jsonReportPath, reportJson, function (err) {
                                    if (err) {
                                        reject(err);
                                    }
                                    else {
                                        resolve();
                                    }
                                });
                            })];
                    case 1:
                        _a.sent();
                        taskLib.addAttachment(TaskRunner.REPORT_ATTACHMENT_NAME, TaskRunner.REPORT_ATTACHMENT_NAME, jsonReportPath);
                        this.log.info('Generated Checkmarx summary results.');
                        return [2 /*return*/];
                }
            });
        });
    };
    TaskRunner.generateJsonReportPath = function () {
        // A temporary folder that is cleaned after each pipeline run, so we don't have to remove
        // temp files manually.
        var tempDir = taskLib.getVariable('Agent.TempDirectory');
        // If the agent variable above is not specified (e.g. in debug environment), tempDir is undefined and
        // tmpNameSync function falls back to a default temp directory.
        return tmp_1.tmpNameSync({ dir: tempDir, prefix: 'cxreport-', postfix: '.json' });
    };
    TaskRunner.prototype.printHeader = function () {
        this.log.info("\n         CxCxCxCxCxCxCxCxCxCxCxCx          \n        CxCxCxCxCxCxCxCxCxCxCxCxCx         \n       CxCxCxCxCxCxCxCxCxCxCxCxCxCx        \n      CxCxCx                CxCxCxCx       \n      CxCxCx                CxCxCxCx       \n      CxCxCx  CxCxCx      CxCxCxCxC        \n      CxCxCx  xCxCxCx  .CxCxCxCxCx         \n      CxCxCx   xCxCxCxCxCxCxCxCx           \n      CxCxCx    xCxCxCxCxCxCx              \n      CxCxCx     CxCxCxCxCx   CxCxCx       \n      CxCxCx       xCxCxC     CxCxCx       \n      CxCxCx                 CxCxCx        \n       CxCxCxCxCxCxCxCxCxCxCxCxCxCx        \n        CxCxCxCxCxCxCxCxCxCxCxCxCx         \n          CxCxCxCxCxCxCxCxCxCxCx           \n                                           \n            C H E C K M A R X              \n                                           \nStarting Checkmarx scan");
    };
    TaskRunner.REPORT_ATTACHMENT_NAME = 'cxReport';
    return TaskRunner;
}());
exports.TaskRunner = TaskRunner;
