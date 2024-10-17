var __extends = (this && this.__extends) || (function () {
        var extendStatics = Object.setPrototypeOf ||
            ({__proto__: []} instanceof Array && function (d, b) {
                d.__proto__ = b;
            }) ||
            function (d, b) {
                for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
            };
        return function (d, b) {
            extendStatics(d, b);
            function __() {
                this.constructor = d;
            }

            d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
        };
    })();
define(["require", "exports", "VSS/Controls", "TFS/DistributedTask/TaskRestClient"], function (require, exports, Controls, DT_Client) {
    "use strict";
    Object.defineProperty(exports, "__esModule", {value: true});
    var StatusSection = (function (_super) {
        __extends(StatusSection, _super);
        function StatusSection() {
            return _super.call(this) || this;
        }

        StatusSection.prototype.initialize = function () {
            _super.prototype.initialize.call(this);
            // Get configuration that's shared between extension and the extension host
            var sharedConfig = VSS.getConfiguration();
            var vsoContext = VSS.getWebContext();
            if (sharedConfig) {
                // register your extension with host through callback
                sharedConfig.onBuildChanged(function (build) {
                    var taskClient = DT_Client.getClient();
                    taskClient.getPlanAttachments(vsoContext.project.id, "build", build.orchestrationPlan.planId, "cxPDFReport").then(function(pdfTaskAttachments){
                        if(pdfTaskAttachments.length === 1) {
                            var recId = pdfTaskAttachments[0].recordId;
                            var timelineId = pdfTaskAttachments[0].timelineId;
                            taskClient.getAttachmentContent(vsoContext.project.id, "build", build.orchestrationPlan.planId, timelineId, recId, "cxPDFReport", "cxPDFReport").then(function(pdfAttachmentContent) {
                                var pdfAttachmentBytes = new Uint8Array(pdfAttachmentContent);
                                var blob = new Blob([pdfAttachmentBytes], {type: "application/pdf"});

                                try{
                                    $("#pdf-report-download-link").click(function(){
                                        var pdf_link = document.getElementById("pdf-report-download-link");
                                        pdf_link.href = window.URL.createObjectURL(blob);
                                        pdf_link.download = "CxPDFReport.pdf";
                                    });
                                }
                                catch(e){
                                    console.error("Failed to Download PDF Report: " + e);
                                }
                            });
                               
                        }
                    });
                    taskClient.getPlanAttachments(vsoContext.project.id, "build", build.orchestrationPlan.planId, "cxReport").then(function (taskAttachments) {
                        if (taskAttachments.length === 1) {
                            $(".cx-report-message").remove();
                            var recId = taskAttachments[0].recordId;
                            var timelineId = taskAttachments[0].timelineId;
                            taskClient.getAttachmentContent(vsoContext.project.id, "build", build.orchestrationPlan.planId, timelineId, recId, "cxReport", "cxReport").then(function (attachmentContent) {
                                // Convert attachment to object.
                                var attachmentBytes = new Uint8Array(attachmentContent);
                                var reportAsString = new TextDecoder().decode(attachmentBytes);
                                var resultObject = JSON.parse(reportAsString);

                                //---------------------------------------------------------- vars ---------------------------------------------------------------
                                var SEVERITY = {
                                    HIGH: {value: 3, name: "high"},
                                    MED: {value: 2, name: "medium"},
                                    LOW: {value: 1, name: "low"},
                                    CRITICAL: {value: 4, name: "critical"},
                                    OSA_HIGH: {value: 6, name: "high"},
                                    OSA_MED: {value: 7, name: "medium"},
                                    OSA_LOW: {value: 8, name: "low"},
                                    OSA_CRITICAL: {value: 5, name: "critical"},
                                };

                                //-------------------------- sast vars --------------------------------------
                                var sastResultsReady = resultObject.sastResultsReady;
                                var buildFailed = resultObject.buildFailed;

                                //thresholds
                                var thresholdsEnabled = resultObject.thresholdEnabled;
                                var criticalThreshold = resultObject.criticalThreshold;
                                var highThreshold = resultObject.highThreshold;
                                var medThreshold = resultObject.mediumThreshold;
                                var lowThreshold = resultObject.lowThreshold;

                                //links

                                var sastScanResultsLink = resultObject.sastScanResultsLink;
                                var sastSummaryResultsLink = resultObject.sastSummaryResultsLink;

                                //AsyncMode
                                var syncMode = resultObject.syncMode;
                                var generatePDFReport = resultObject.generatePDFReport;
                                var is_Pdf_link = document.getElementById("pdf-report-download-link");
                                var scaResults = resultObject.scaResults;

                                if (syncMode && (sastResultsReady || scaResults)) {
                                    //counts
                                    var criticalCount = resultObject.criticalResults;
                                    var highCount = resultObject.highResults;
                                    var medCount = resultObject.mediumResults;
                                    var lowCount = resultObject.lowResults;


                                    //-------------------------- osa vars --------------------------------------
                                    var osaEnabled = resultObject.osaEnabled;
                                    var osaFailed = resultObject.osaFailed;

                                    //libraries
                                    var osaVulnerableAndOutdatedLibs = resultObject.osaVulnerableLibraries;
                                    var okLibraries = resultObject.osaOkLibraries;

                                    //thresholds
                                    var osaThresholdsEnabled = resultObject.osaThresholdEnabled;
                                    var osaCriticalThreshold = resultObject.osaCriticalThreshold;
                                    var osaHighThreshold = resultObject.osaHighThreshold;
                                    var osaMedThreshold = resultObject.osaMediumThreshold;
                                    var osaLowThreshold = resultObject.osaLowThreshold;

                                    //links
                                    var osaSummaryResultsLink = resultObject.osaSummaryResultsLink;

                                    //counts
                                    var osaCriticalCount = resultObject.osaCriticalResults;
                                    var osaHighCount = resultObject.osaHighResults;
                                    var osaMedCount = resultObject.osaMediumResults;
                                    var osaLowCount = resultObject.osaLowResults;


                                    //-------------------------- full reports vars --------------------------------------
                                    //-------------- sast ------------------


                                    //full report info
                                    var sastStartDate = resultObject.scanStart;
                                    var sastScanTime = resultObject.scanTime;

                                

                                    var sastEndDate = calculateEndDate(sastStartDate, sastScanTime);
                                    var sastNumFiles = resultObject.filesScanned;
                                    var sastLoc = resultObject.locScanned;

                                    //lists
                                    var queryList = convertQueriesToList(resultObject.queryList);

                                    var isSastFullReady =
                                        sastStartDate != '' &&
                                        sastScanTime != '' &&
                                        sastNumFiles != null &&
                                        sastLoc != null &&
                                        queryList != null;


                                    var criticalCveList;
                                    var criticalCveList;
                                    var highCveList;
                                    var medCveList;
                                    var lowCveList;


                                    //-------------- osa ------------------
                                    //this is a solution to the case scenario where OSA is disabled and osaCveList returns null which crashes the javascript code
                                    var osaList = null;
                                    var osaLibraries = null;
                                    var osaStartDate = ' ';
                                    var osaEndDate = ' ';

                                    if (osaEnabled === true && osaFailed != true) {
                                        osaList = convertOSADataToList(resultObject.osaCveList);
                                        osaLibraries = convertOSADataToList(resultObject.osaLibraries);
                                        osaStartDate = adjustDateFormat(resultObject.osaStartTime);
                                        osaEndDate = adjustDateFormat(resultObject.osaEndTime);
                                    }


                                    //full report info
                                    var isOsaFullReady =
                                        osaStartDate != ' ' &&
                                        osaEndDate != ' ' &&
                                        osaLibraries != null &&
                                        osaList != null;

                                    var osaNumFiles;

                                    //cve lists
                                    var osaCriticalCveList;
                                    var osaHighCveList;
                                    var osaMedCveList;
                                    var osaLowCveList;


                                    //-------------------------- sca vars --------------------------------------

                                    if(scaResults || osaEnabled) {
                                        var scaResultReady = scaResults._resultReady;
                                        var scaCriticalVulnerability = scaResults._criticalVulnerability;
                                        var scaHighVulnerability = scaResults._highVulnerability;
                                        var scaMediumVulnerability = scaResults._mediumVulnerability;
                                        var scaLowVulnerability = scaResults._lowVulnerability;
                                        var scaSummaryLink = scaResults._summaryLink;
                                        var scaVulnerableAndOutdated = scaResults._vulnerableAndOutdated;
                                        var scaNonVulnerableLibraries = scaResults._nonVulnerableLibraries;
                                        var scaScanStartTime = scaResults._scanStartTime;
                                        var scaScanEndTime = scaResults._scanEndTime;
                                        var scaDependencyCriticalCVEReportTable = scaResults._dependencyCriticalCVEReportTable;
                                        var scaDependencyHighCVEReportTable = scaResults._dependencyHighCVEReportTable;
                                        var scaDependencyMediumCVEReportTable = scaResults._dependencyMediumCVEReportTable;
                                        var scaDependencyLowCVEReportTable = scaResults._dependencyLowCVEReportTable;
                                        var scaTotalLibraries = scaResults._totalLibraries;
                                        var scaThresholdEnabled = scaResults._vulnerabilityThreshold;
                                        var scaCriticalThreshold = scaResults._criticalThreshold;
                                        var scaHighThreshold = scaResults._highThreshold;
                                        var scaMediumThreshold = scaResults._mediumThreshold;
                                        var scaLowThreshold = scaResults._lowThreshold;


                                        //---------------------------- Dependency Results Variables ---------------

                                        var dependencyCriticalVulnerability;
                                        var dependencyHighVulnerability;
                                        var dependencyMediumVulnerability;
                                        var dependencyLowVulnerability;
                                        var dependencySummaryLink;
                                        var dependencyVulnerableAndOutdated;
                                        var dependencyNonVulnerableLibraries;
                                        var dependencyScanStartTime;
                                        var dependencyScanEndTime;
                                        var dependencyCriticalCVEReportTable;
                                        var dependencyHighCVEReportTable;
                                        var dependencyMediumCVEReportTable;
                                        var dependencyLowCVEReportTable;
                                        var dependencyTotalLibraries;
                                        var dependencyLibraries;
                                        var dependencyThresholdEnabled;
                                        var dependencyCriticalThreshold;
                                        var dependencyHighThreshold;
                                        var dependencyMediumThreshold;
                                        var dependencyLowThreshold;

                                        var isDependencyResultReady = isOsaFullReady || (scaResults != null && scaResultReady);

                                        if (scaResults != null && scaResultReady) {
                                            dependencyCriticalVulnerability = scaCriticalVulnerability;
                                            dependencyHighVulnerability = scaHighVulnerability;
                                            dependencyMediumVulnerability = scaMediumVulnerability;
                                            dependencyLowVulnerability = scaLowVulnerability;
                                            dependencySummaryLink = scaSummaryLink;
                                            dependencyVulnerableAndOutdated = scaVulnerableAndOutdated;
                                            dependencyNonVulnerableLibraries = scaNonVulnerableLibraries;
                                            dependencyScanStartTime = scaScanStartTime;
                                            dependencyScanEndTime = "";
                                            dependencyCriticalCVEReportTable = scaDependencyCriticalCVEReportTable;
                                            dependencyHighCVEReportTable = scaDependencyHighCVEReportTable;
                                            dependencyMediumCVEReportTable = scaDependencyMediumCVEReportTable;
                                            dependencyLowCVEReportTable = scaDependencyLowCVEReportTable;
                                            dependencyTotalLibraries = scaTotalLibraries;
                                            dependencyLibraries = dependencyLowCVEReportTable.concat(dependencyMediumCVEReportTable, dependencyLowCVEReportTable);
                                            dependencyThresholdEnabled = scaThresholdEnabled;
                                            dependencyCriticalThreshold = scaCriticalThreshold;
                                            dependencyHighThreshold = scaHighThreshold;
                                            dependencyMediumThreshold = scaMediumThreshold;
                                            dependencyLowThreshold =scaLowThreshold;

                                        } else if (osaEnabled && !osaFailed) {
                                            dependencyCriticalVulnerability = osaCriticalCount;
                                            dependencyHighVulnerability = osaHighCount;
                                            dependencyMediumVulnerability = osaMedCount;
                                            dependencyLowVulnerability = osaLowCount;
                                            dependencySummaryLink = osaSummaryResultsLink;
                                            dependencyVulnerableAndOutdated = osaVulnerableAndOutdatedLibs;
                                            dependencyNonVulnerableLibraries = okLibraries;
                                            dependencyScanStartTime = osaStartDate;
                                            dependencyScanEndTime = osaEndDate;
                                            dependencyCriticalCVEReportTable = osaCriticalCveList;
                                            dependencyHighCVEReportTable = osaHighCveList;
                                            dependencyMediumCVEReportTable = osaMedCveList;
                                            dependencyLowCVEReportTable = osaLowCveList;
                                            dependencyTotalLibraries = osaLibraries.length;
                                            dependencyLibraries = osaLibraries;
                                            dependencyThresholdEnabled = osaThresholdsEnabled;
                                            dependencyCriticalThreshold = osaCriticalThreshold;
                                            dependencyHighThreshold = osaHighThreshold;
                                            dependencyMediumThreshold = osaMedThreshold;
                                            dependencyLowThreshold =osaLowThreshold;
                                        }
                                    }

                                    //-------------------------- html vars --------------------------------------
                                    var thresholdExceededHtml =
                                        '<div class="threshold-exceeded">' +
                                        '<div class="threshold-exceeded-icon">' +
                                        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="12px" height="12px" viewBox="0 0 12 12" version="1.1"><defs/><g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd"><g id="Icons" transform="translate(-52.000000, -241.000000)"><g id="threshhold-icon" transform="translate(52.000000, 241.000000)"><g><path d="M8.0904685,3 L7.0904685,3 L7.0904685,5 L8.0904685,5 L8.0904685,11 L3.0904685,11 L3.0904685,0 L8.0904685,0 L8.0904685,3 Z M3.0904685,3 L3.0904685,5 L5.0904685,5 L5.0904685,3 L3.0904685,3 Z M5.0904685,3 L5.0904685,5 L7.0904685,5 L7.0904685,3 L5.0904685,3 Z" id="Combined-Shape" fill="#FFFFFF"/><path d="M10.5904685,11.5 L0.590468498,11.5" id="Line" stroke="#FFFFFF" stroke-linecap="square"/></g></g></g></g></svg>' +
                                        '</div>' +
                                        '<div class="threshold-exceeded-text">' +
                                        'Threshold Exceeded' +
                                        '</div>' +
                                        '</div>';

                                    var thresholdComplianceHtml =
                                        '<div class="threshold-compliance">' +
                                        '<div class="threshold-compliance-icon">' +
                                        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:svgjs="http://svgjs.com/svgjs" id="SvgjsSvg1050" version="1.1" width="13.99264158479491" height="13" viewBox="0 0 13.99264158479491 13"><title>Icon</title><desc>Created with Avocode.</desc><defs id="SvgjsDefs1051"><clipPath id="SvgjsClipPath1056"><path id="SvgjsPath1055" d="M1035.00736 793.9841L1035.00736 784.01589L1046.9926400000002 784.01589L1046.9926400000002 793.9841ZM1038.67 790.72L1036.68 788.72L1036 789.4L1038.67 792.0699999999999L1045.21 785.67L1044.54 785Z " fill="#ffffff"/></clipPath></defs><path id="SvgjsPath1052" d="M1033 789.5C1033 785.91015 1035.91015 783 1039.5 783C1043.08985 783 1046 785.91015 1046 789.5C1046 793.08985 1043.08985 796 1039.5 796C1035.91015 796 1033 793.08985 1033 789.5Z " fill="#21bf3f" fill-opacity="1" transform="matrix(1,0,0,1,-1033,-783)"/><path id="SvgjsPath1053" d="M1038.67 790.72L1036.68 788.72L1036 789.4L1038.67 792.0699999999999L1045.21 785.67L1044.54 785Z " fill="#ffffff" fill-opacity="1" transform="matrix(1,0,0,1,-1033,-783)"/><path id="SvgjsPath1054" d="M1038.67 790.72L1036.68 788.72L1036 789.4L1038.67 792.0699999999999L1045.21 785.67L1044.54 785Z " fill-opacity="0" fill="#ffffff" stroke-dasharray="0" stroke-linejoin="miter" stroke-linecap="butt" stroke-opacity="1" stroke="#ffffff" stroke-miterlimit="50" stroke-width="1.4" clip-path="url(&quot;#SvgjsClipPath1056&quot;)" transform="matrix(1,0,0,1,-1033,-783)"/></svg>' +
                                        '</div>' +
                                        '<div class="threshold-compliance-text">' +
                                        'Threshold Compliant' +
                                        '</div>' +
                                        '</div>';

                                }
                                //---------------------------------------------------------- sast ---------------------------------------------------------------
                                if (syncMode != false) { //Synchronous Mode
                                    document.getElementById("asyncMessage").setAttribute("style", "display:none");
                                    document.getElementById("onAsyncMode").setAttribute("style", "display:none");
                                    document.getElementById("results-report").setAttribute("style", "display:block");
                                    if(sastResultsReady != true){
                                        document.getElementById("sast-summary").setAttribute("style", "display:none");
                                    }
                                    if(!generatePDFReport){ //To hide pdf link
                                        is_Pdf_link.style.display = "none";
                                    }

                                    if (sastResultsReady == true) {
                                        try {
                                            document.getElementById("report-title").setAttribute("style", "display:block");

                                            //link
                                            document.getElementById("sast-summary-html-link").setAttribute("href", sastScanResultsLink);
                                            document.getElementById("sast-code-viewer-link").setAttribute("href", sastScanResultsLink);

                                            //set bars height and count
                                            if(criticalCount == undefined)
                                            {
                                                document.getElementById("critical-summary").style.display = "none";
                                            }
                                            document.getElementById("bar-count-critical").innerHTML = criticalCount;
                                            document.getElementById("bar-count-high").innerHTML = highCount;
                                            document.getElementById("bar-count-med").innerHTML = medCount;
                                            document.getElementById("bar-count-low").innerHTML = lowCount;

                                            var maxCount;
                                            if(criticalCount == undefined)
                                            {
                                                maxCount = Math.max(highCount, medCount, lowCount);
                                            }
                                            else
                                            {
                                                maxCount = Math.max(criticalCount,highCount, medCount, lowCount);
                                            }
                                            var maxHeight = maxCount * 100 / 90;
                                            document.getElementById("bar-critical").setAttribute("style", "height:" + criticalCount * 100 / maxHeight + "%");
                                            document.getElementById("bar-high").setAttribute("style", "height:" + highCount * 100 / maxHeight + "%");
                                            document.getElementById("bar-med").setAttribute("style", "height:" + medCount * 100 / maxHeight + "%");
                                            document.getElementById("bar-low").setAttribute("style", "height:" + lowCount * 100 / maxHeight + "%");
                                        } catch (e) {
                                            console.error("Element missing in SAST summary section " + e.message);
                                        }

                                        //if threshold is enabled
                                        if (thresholdsEnabled == true) {
                                            try {
                                                var isThresholdExceeded = false;
                                                var thresholdExceededComplianceElement = document.getElementById("threshold-exceeded-compliance");

                                                if (criticalThreshold != null  && criticalCount > criticalThreshold) {
                                                    document.getElementById("tooltip-critical").innerHTML = tooltipGenerator(SEVERITY.CRITICAL);
                                                    isThresholdExceeded = true;
                                                }

                                                if (highThreshold != null  && highCount > highThreshold) {
                                                    document.getElementById("tooltip-high").innerHTML = tooltipGenerator(SEVERITY.HIGH);
                                                    isThresholdExceeded = true;
                                                }

                                                if (medThreshold != null && medCount > medThreshold) {
                                                    document.getElementById("tooltip-med").innerHTML = tooltipGenerator(SEVERITY.MED);
                                                    isThresholdExceeded = true;
                                                }

                                                if (lowThreshold != null && lowCount > lowThreshold) {
                                                    document.getElementById("tooltip-low").innerHTML = tooltipGenerator(SEVERITY.LOW);
                                                    isThresholdExceeded = true;
                                                }


                                                //if threshold exceeded
                                                if (isThresholdExceeded == true) {
                                                    thresholdExceededComplianceElement.innerHTML = thresholdExceededHtml;
                                                }

                                                //else show threshold compliance element
                                                else {
                                                    thresholdExceededComplianceElement.innerHTML = thresholdComplianceHtml;
                                                }
                                            } catch (e) {
                                                console.error("Element missing in SAST threshold section " + e.message);
                                            }
                                        }
                                    }


                                    //---------------------------------------------------------- osa ---------------------------------------------------------------
                                    if(osaEnabled == true && osaFailed != true){
                                        document.getElementById("dependencyScanHeader").innerHTML = "CxOSA Vulnerabilities & Libraries";
                                        document.getElementById("dependencyLibrariesTables").innerHTML = "CxOSA";
                                    }else if(scaResultReady){
                                        document.getElementById("dependencyScanHeader").innerHTML = "CxSCA Vulnerabilities & Libraries";
                                        document.getElementById("dependencyLibrariesTables").innerHTML = "CxSCA";
                                    }else{
                                        document.getElementById("dependencyScanHeader").innerHTML = "Dependencies Vulnerabilities & Libraries";
                                        document.getElementById("dependencyLibrariesTables").innerHTML = "Cx Dependency Scan";
                                }

                                    if ((osaEnabled == true && osaFailed != true) || (scaResults !=null && scaResultReady)) {
                                        try {
                                            document.getElementById("report-title").setAttribute("style", "display:block");
                                            document.getElementById("osa-summary").setAttribute("style", "display:block");
                                            //link
                                            document.getElementById("osa-summary-html-link").setAttribute("href", dependencySummaryLink);

                                            //set bars height and count
                                            document.getElementById("osa-bar-count-critical").innerHTML = dependencyCriticalVulnerability;
                                            document.getElementById("osa-bar-count-high").innerHTML = dependencyHighVulnerability;
                                            document.getElementById("osa-bar-count-med").innerHTML = dependencyMediumVulnerability;
                                            document.getElementById("osa-bar-count-low").innerHTML = dependencyLowVulnerability;


                                            var dependencyMaxCount = Math.max(dependencyCriticalVulnerability,dependencyHighVulnerability, dependencyMediumVulnerability, dependencyLowVulnerability);
                                            var dependencyMaxHeight = dependencyMaxCount * 100 / 90;

                                            document.getElementById("osa-bar-critical").setAttribute("style", "height:" + dependencyCriticalVulnerability * 100 / dependencyMaxHeight + "%");
                                            document.getElementById("osa-bar-high").setAttribute("style", "height:" + dependencyHighVulnerability * 100 / dependencyMaxHeight + "%");
                                            document.getElementById("osa-bar-med").setAttribute("style", "height:" + dependencyMediumVulnerability * 100 / dependencyMaxHeight + "%");
                                            document.getElementById("osa-bar-low").setAttribute("style", "height:" + dependencyLowVulnerability * 100 / dependencyMaxHeight + "%");

                                            document.getElementById("vulnerable-libraries").innerHTML = numberWithCommas(dependencyVulnerableAndOutdated);
                                            document.getElementById("ok-libraries").innerHTML = dependencyNonVulnerableLibraries;
                                        }
                                        catch (e) {
                                            console.error("Element missing in OSA summary section " + e.message);
                                        }

                                        //if threshold is enabled
                                        if (dependencyThresholdEnabled == true) {
                                            try {
                                                var isDependencyThresholdExceeded = false;
                                                var osaThresholdExceededComplianceElement = document.getElementById("osa-threshold-exceeded-compliance");

                                                if (dependencyCriticalThreshold != null  && dependencyCriticalVulnerability > dependencyCriticalThreshold) {
                                                    document.getElementById("osa-tooltip-critical").innerHTML = tooltipGenerator(SEVERITY.OSA_CRITICAL);
                                                    isDependencyThresholdExceeded = true;
                                                }

                                                if (dependencyHighThreshold != null  && dependencyHighVulnerability > dependencyHighThreshold) {
                                                    document.getElementById("osa-tooltip-high").innerHTML = tooltipGenerator(SEVERITY.OSA_HIGH);
                                                    isDependencyThresholdExceeded = true;
                                                }

                                                if (dependencyMediumThreshold != null  && dependencyMediumVulnerability > dependencyMediumThreshold) {
                                                    document.getElementById("osa-tooltip-med").innerHTML = tooltipGenerator(SEVERITY.OSA_MED);
                                                    isDependencyThresholdExceeded = true;
                                                }

                                                if (dependencyLowThreshold != null  && dependencyLowVulnerability > dependencyLowThreshold) {
                                                    document.getElementById("osa-tooltip-low").innerHTML = tooltipGenerator(SEVERITY.OSA_LOW);
                                                    isDependencyThresholdExceeded = true;
                                                }


                                                //if threshold exceeded
                                                if (isDependencyThresholdExceeded == true) {
                                                    osaThresholdExceededComplianceElement.innerHTML = thresholdExceededHtml;
                                                }

                                                //else
                                                //show threshold compliance element
                                                else {
                                                    osaThresholdExceededComplianceElement.innerHTML = thresholdComplianceHtml;
                                                }
                                            } catch (e) {
                                                console.error("Element missing in OSA threshold section " + e.message);
                                            }
                                        }
                                        document.getElementById("sast-summary").setAttribute("class", "sast-summary chart-small");
                                    }
                                    else {
                                        document.getElementById("sast-summary").setAttribute("class", "sast-summary chart-large");
                                    }

                                    //---------------------------------------------------------- full reports ---------------------------------------------------------------
                                    if (isSastFullReady == true) {
                                        document.getElementById("sast-full").setAttribute("style", "display: block");

                                        //queries lists
                                        criticalCveList = generateQueryList(SEVERITY.CRITICAL);
                                        highCveList = generateQueryList(SEVERITY.HIGH);
                                        medCveList = generateQueryList(SEVERITY.MED);
                                        lowCveList = generateQueryList(SEVERITY.LOW);


                                        try {
                                            //sast links
                                            document.getElementById("sast-code-viewer-link").setAttribute("href", sastScanResultsLink);

                                            //sast info
                                            document.getElementById("sast-full-start-date").innerHTML = formatDate(sastStartDate, "dd/mm/yy hh:mm:ss");
                                            document.getElementById("sast-full-end-date").innerHTML = formatDate(sastEndDate, "dd/mm/yy hh:mm:ss");
                                            document.getElementById("sast-full-files").innerHTML = numberWithCommas(sastNumFiles);
                                            document.getElementById("sast-full-loc").innerHTML = numberWithCommas(sastLoc);

                                        } catch (e) {
                                            console.error("Element missing in full report info section " + e.message);
                                        }

                                        try {
                                            //generate full reports
                                            if (criticalCount == 0 && highCount == 0 && medCount == 0 && lowCount == 0) {
                                                document.getElementById("sast-full").setAttribute("style", "display: none");
                                            } else {
                                                if (criticalCount > 0) {
                                                    generateCveTable(SEVERITY.CRITICAL);
                                                }

                                                if (highCount > 0) {
                                                    generateCveTable(SEVERITY.HIGH);
                                                }
                                                if (medCount > 0) {
                                                    generateCveTable(SEVERITY.MED);
                                                }
                                                if (lowCount > 0) {
                                                    generateCveTable(SEVERITY.LOW);
                                                }
                                            }

                                        } catch (e) {
                                            console.error("Element missing in full report detailed table section " + e.message);
                                        }
                                    }

                                    if (isDependencyResultReady) {
                                        document.getElementById("osa-full").setAttribute("style", "display: block");
                                        if(osaEnabled){
                                            //cve lists
                                            dependencyCriticalCVEReportTable = generateOsaCveList(SEVERITY.OSA_CRITICAL);
                                            dependencyHighCVEReportTable = generateOsaCveList(SEVERITY.OSA_HIGH);
                                            dependencyMediumCVEReportTable = generateOsaCveList(SEVERITY.OSA_MED);
                                            dependencyLowCVEReportTable = generateOsaCveList(SEVERITY.OSA_LOW);
                                        }

                                        /*osaNumFiles = dependencyTotalLibraries;*/

                                        try {


                                            //osa links
                                            document.getElementById("osa-html-link").setAttribute("href", dependencySummaryLink);


                                            //osa info
                                            document.getElementById("osa-full-start-date").innerHTML = formatDate(dependencyScanStartTime, "dd/mm/yy hh:mm:ss");
                                            if(osaEnabled){
                                                document.getElementById("osa-full-end-date").innerHTML = formatDate(dependencyScanEndTime, "dd/mm/yy hh:mm:ss");
                                            }else if (scaResults!=null && scaResultReady){
                                                document.getElementById("osa-full-end-date").innerHTML = dependencyScanEndTime;
                                            }
                                            document.getElementById("osa-full-files").innerHTML = numberWithCommas(dependencyTotalLibraries);
                                        } catch (e) {
                                            console.error("Element missing in full report info section " + e.message);
                                        }

                                        try {
                                            //generate full reports
                                            if (dependencyLowCVEReportTable.length == 0 && dependencyMediumCVEReportTable.length == 0 && dependencyLowCVEReportTable.length == 0) {
                                                document.getElementById("osa-full").setAttribute("style", "display: none");
                                            } else {
                                                if (dependencyCriticalCVEReportTable.length > 0) {
                                                    generateCveTable(SEVERITY.OSA_CRITICAL);
                                                }
                                                if (dependencyHighCVEReportTable.length > 0) {
                                                    generateCveTable(SEVERITY.OSA_HIGH);
                                                }
                                                if (dependencyMediumCVEReportTable.length > 0) {
                                                    generateCveTable(SEVERITY.OSA_MED);
                                                }
                                                if (dependencyLowCVEReportTable.length > 0) {
                                                    generateCveTable(SEVERITY.OSA_LOW);
                                                }
                                            }
                                        } catch (e) {
                                            console.error("Element missing in full report detailed table section " + e.message);
                                        }
                                    }
                                }
                                else {  //AsyncMode
                                    if (buildFailed == true) {
                                        document.getElementById("onSastError").setAttribute("style", "display:block");
                                        document.getElementById("scanErrorMessage").setAttribute("style", "display:block");
                                    } else {
                                        var asyncModeMessage = "The scan is running in asynchronous mode. Once completed, the link to the results can be found in the log.";
                                        var asyncDiv = document.getElementById("asyncMessage");
                                        asyncDiv.innerHTML = asyncModeMessage;
                                        asyncDiv.setAttribute("style", "display:block");
                                        document.getElementById("onAsyncMode").setAttribute("style", "display:block");

                                    }
                                    is_Pdf_link.style.display = "none"; //to hide pdf link
                                }


                                //functions


                                function tooltipGenerator(severity) {
                                    var threshold = 0;
                                    var count = 0;
                                    var thresholdHeight = 0;
                                    //if severity high - threshold = highThreshold and count = highCount
                                    //if med - ...
                                    //if low - ...

                                    switch (severity) {
                                        case SEVERITY.CRITICAL:
                                            threshold = criticalThreshold;
                                            count = criticalCount;
                                            break;
                                        case SEVERITY.HIGH:
                                            threshold = highThreshold;
                                            count = highCount;
                                            break;
                                        case SEVERITY.MED:
                                            threshold = medThreshold;
                                            count = medCount;
                                            break;
                                        case SEVERITY.LOW:
                                            threshold = lowThreshold;
                                            count = lowCount;
                                            break;

                                        case SEVERITY.OSA_CRITICAL:
                                            threshold = dependencyCriticalThreshold;
                                            count = dependencyCriticalVulnerability;
                                            break;
                                            
                                        case SEVERITY.OSA_HIGH:
                                            threshold = dependencyHighThreshold;
                                            count = dependencyHighVulnerability;
                                            break;
                                        case SEVERITY.OSA_MED:
                                            threshold = dependencyMediumThreshold;
                                            count = dependencyMediumVulnerability;
                                            break;
                                        case SEVERITY.OSA_LOW:
                                            threshold = dependencyLowThreshold;
                                            count = dependencyLowVulnerability;
                                            break;
                                    }

                                    //calculate visual height
                                    thresholdHeight = threshold * 100 / count; //todo- exception?


                                    return '' +

                                        '<div class="tooltip-container" style="bottom:calc(' + thresholdHeight + '% - 1px)">' +
                                        '<div class="threshold-line">' +
                                        ' ' +
                                        '</div>' +
                                        '<div class="threshold-tooltip">' +
                                        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="12px" height="12px" viewBox="0 0 12 12" version="1.1"><defs/><g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd"><g id="Icons" transform="translate(-87.000000, -243.000000)"><g id="threshhold-icon-red" transform="translate(87.000000, 243.000000)"><g><path d="M8.0904685,3 L7.0904685,3 L7.0904685,5 L8.0904685,5 L8.0904685,11 L3.0904685,11 L3.0904685,0 L8.0904685,0 L8.0904685,3 Z M3.0904685,3 L3.0904685,5 L5.0904685,5 L5.0904685,3 L3.0904685,3 Z M5.0904685,3 L5.0904685,5 L7.0904685,5 L7.0904685,3 L5.0904685,3 Z" id="Combined-Shape" fill="#DA2945"/><path d="M10.5904685,11.5 L0.590468498,11.5" id="Line" stroke="#DA2945" stroke-linecap="square"/></g></g></g></g></svg>' +
                                        '<div class="tooltip-number">' + threshold + '</div>' +
                                        '</div>' +
                                        '</div>';

                                }

                                function generateCveTableTitle(severity) {
                                    var svgIcon;
                                    var severityNameTtl;
                                    var severityCountTtl;
                                    var svgCriticalIcon = '<svg width="16" height="20" viewBox="0 0 16 19" fill="none" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><title>Critical</title><path d="M0 10V4.31302C0 2.19129 1.0015 0.184893 3.11764 0.030931C3.39036 0.0110888 3.68409 0 4 0H11.5C12.0072 0 12.462 0.0210035 12.8688 0.0569225C14.9823 0.243543 16 2.19129 16 4.31302V10C16 12.3957 12.4926 16.7045 11.0796 18.3432C10.7135 18.7678 10.1808 19 9.6202 19H6.3798C5.81919 19 5.28652 18.7678 4.92042 18.3432C3.50742 16.7045 0 12.3957 0 10Z" fill="#F8788F"/>' +
                                                        '<rect id="Rectangle-22" fill="#BB1A34" mask="url(#mask-2)" x="8" y="0" width="8" height="20"></rect>' +
                                                        '<path d="M0 10V4.31302C0 2.19129 1.0015 0.184893 3.11764 0.030931C3.39036 0.0110888 3.68409 0 4 0H11.5C12.0072 0 12.462 0.0210035 12.8688 0.0569225C14.9823 0.243543 16 2.19129 16 4.31302V10C16 12.3957 12.4926 16.7045 11.0796 18.3432C10.7135 18.7678 10.1808 19 9.6202 19H6.3798C5.81919 19 5.28652 18.7678 4.92042 18.3432C3.50742 16.7045 0 12.3957 0 10Z" fill="#A00909" fill-opacity="0.5"/>' + 
                                                        '<path d="M8 0L14.186 0.883717C14.659 0.951285 15.0181 1.34399 15.0432 1.82111L15.5 10.5L11 18L8 19V0Z" fill="#F8788F"/>' + 
                                                        '<path d="M8 0L14.186 0.883717C14.659 0.951285 15.0181 1.34399 15.0432 1.82111L15.5 10.5L11 18L8 19V0Z" fill="#A00909" fill-opacity="0.9"/>' + 
                                                        '<path d="M0.5 10V4.31302C0.5 3.32304 0.734816 2.39306 1.18352 1.70803C1.62289 1.03727 2.2683 0.594047 3.15392 0.529613C3.41417 0.510678 3.69579 0.5 4 0.5H11.5C11.9935 0.5 12.4335 0.520434 12.8248 0.554985C13.718 0.633851 14.3695 1.07659 14.8113 1.73726C15.2621 2.41124 15.5 3.32511 15.5 4.31302V10C15.5 10.4919 15.3156 11.1324 14.9753 11.8757C14.6393 12.6095 14.1721 13.3998 13.6535 14.1783C12.6167 15.7348 11.4018 17.2038 10.7009 18.0167C10.4345 18.3257 10.0427 18.5 9.6202 18.5H6.3798C5.95733 18.5 5.56554 18.3257 5.29909 18.0167C4.59817 17.2038 3.38331 15.7348 2.34646 14.1783C1.82787 13.3998 1.36066 12.6095 1.02473 11.8757C0.684403 11.1324 0.5 10.4919 0.5 10Z" stroke="#F8788F" stroke-linecap="round"/>' + 
                                                        '<path d="M0.5 10V4.31302C0.5 3.32304 0.734816 2.39306 1.18352 1.70803C1.62289 1.03727 2.2683 0.594047 3.15392 0.529613C3.41417 0.510678 3.69579 0.5 4 0.5H11.5C11.9935 0.5 12.4335 0.520434 12.8248 0.554985C13.718 0.633851 14.3695 1.07659 14.8113 1.73726C15.2621 2.41124 15.5 3.32511 15.5 4.31302V10C15.5 10.4919 15.3156 11.1324 14.9753 11.8757C14.6393 12.6095 14.1721 13.3998 13.6535 14.1783C12.6167 15.7348 11.4018 17.2038 10.7009 18.0167C10.4345 18.3257 10.0427 18.5 9.6202 18.5H6.3798C5.95733 18.5 5.56554 18.3257 5.29909 18.0167C4.59817 17.2038 3.38331 15.7348 2.34646 14.1783C1.82787 13.3998 1.36066 12.6095 1.02473 11.8757C0.684403 11.1324 0.5 10.4919 0.5 10Z" stroke="#A00909" stroke-opacity="0.9" stroke-linecap="round"/>' + 
                                                        '<path d="M6.23439 11.7623L6.23499 11.7627C6.77633 12.0811 7.41934 12.2381 8.15998 12.2381C8.80302 12.2381 9.36527 12.1205 9.84355 11.8813C10.3203 11.643 10.696 11.3111 10.9679 10.8856C11.2428 10.4572 11.3951 9.96317 11.4267 9.40624L11.4327 9.30057H11.3269H9.47106H9.38478L9.37214 9.38591C9.33702 9.62298 9.26304 9.82226 9.15263 9.98646L9.15241 9.98679C9.04464 10.1484 8.90822 10.2705 8.74249 10.3548L8.74188 10.3551C8.57918 10.4392 8.39365 10.4824 8.18306 10.4824C7.89776 10.4824 7.65258 10.405 7.44336 10.2523C7.23385 10.0994 7.06725 9.87471 6.94658 9.57171C6.82927 9.26944 6.76886 8.89788 6.76886 8.45419C6.76886 8.01685 6.83075 7.65016 6.95092 7.35122C7.07162 7.05092 7.23674 6.82915 7.44316 6.67929L7.44336 6.67915C7.65258 6.52647 7.89775 6.44908 8.18306 6.44908C8.52133 6.44908 8.78543 6.5509 8.98536 6.74805L8.98535 6.74806L8.98636 6.74902C9.19268 6.94686 9.32255 7.21011 9.37213 7.54552L9.38475 7.63089H9.47106H11.3269H11.4321L11.4268 7.52585C11.3983 6.9623 11.2443 6.46735 10.9623 6.04432C10.681 5.62235 10.2991 5.29536 9.81927 5.06338C9.33854 4.83097 8.78147 4.71641 8.15075 4.71641C7.41901 4.71641 6.78204 4.87511 6.24381 5.19672C5.70714 5.51432 5.29258 5.9578 5.00108 6.52495L5.00098 6.52515C4.71252 7.08939 4.56992 7.74258 4.56992 8.48189C4.56992 9.21204 4.71101 9.86186 4.99606 10.4288L4.99626 10.4292C5.28469 10.9965 5.69775 11.4416 6.23439 11.7623Z" fill="white" stroke="white" stroke-width="0.2"/></svg>';
                                    var svgHighIcon = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="16" height="19" viewBox="0 0 16 19"><title>High</title><defs><path d="M1 1l7-1 7 1s1 3.015 1 6c0 6.015-5.323 11.27-5.323 11.27-.374.403-1.12.73-1.686.73H7.01c-.558 0-1.308-.333-1.675-.76C5.335 18.24 0 12.516 0 8c0-3.172 1-7 1-7z" id="a"/><path d="M1 1l7-1 7 1s1 3.015 1 6c0 6.015-5.323 11.27-5.323 11.27-.374.403-1.12.73-1.686.73H7.01c-.558 0-1.308-.333-1.675-.76C5.335 18.24 0 12.516 0 8c0-3.172 1-7 1-7z" id="c"/></defs><g fill="none" fill-rule="evenodd"><mask id="b" fill="#fff"><use xlink:href="#a"/></mask><use fill="#D82D49" xlink:href="#a"/><path stroke="#BB1A34" d="M1.404 1.447L8 .505l6.616.945.06.205c.114.402.23.85.336 1.334.298 1.342.48 2.682.488 3.924V7c0 2.52-.966 5.112-2.582 7.62-.57.884-1.18 1.694-1.79 2.41-.214.252-.41.472-.588.66-.104.113-.178.188-.215.224-.296.32-.91.586-1.334.586H7.01c-.42 0-1.028-.274-1.296-.585-.052-.056-.127-.14-.233-.26-.178-.202-.378-.436-.593-.697-.615-.747-1.23-1.564-1.804-2.422C2.097 13.06 1.34 11.62.906 10.284.64 9.462.5 8.697.5 8c0-.433.02-.895.056-1.38C.634 5.6.786 4.51.992 3.4c.108-.584.223-1.137.34-1.64.026-.118.05-.222.072-.313z"/><path fill="#BB1A34" mask="url(#b)" d="M8 0h8v20H8z"/><mask id="d" fill="#fff"><use xlink:href="#c"/></mask><path stroke="#BB1A34" d="M1.404 1.447L8 .505l6.616.945.06.205c.114.402.23.85.336 1.334.298 1.342.48 2.682.488 3.924V7c0 2.52-.966 5.112-2.582 7.62-.57.884-1.18 1.694-1.79 2.41-.214.252-.41.472-.588.66-.104.113-.178.188-.215.224-.296.32-.91.586-1.334.586H7.01c-.42 0-1.028-.274-1.296-.585-.052-.056-.127-.14-.233-.26-.178-.202-.378-.436-.593-.697-.615-.747-1.23-1.564-1.804-2.422C2.097 13.06 1.34 11.62.906 10.284.64 9.462.5 8.697.5 8c0-.433.02-.895.056-1.38C.634 5.6.786 4.51.992 3.4c.108-.584.223-1.137.34-1.64.026-.118.05-.222.072-.313z"/><path fill="#FFF" mask="url(#d)" d="M5 12h2V9.5h2V12h2V5H9v2.5H7V5H5"/></g></svg>';
                                    var svgMedIcon = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="16" height="20" viewBox="0 0 16 20"><title>Medium</title><defs><path d="M1 1.053L8 0l7 1.053s1 3.173 1 6.315c0 6.332-5.346 11.89-5.346 11.89-.36.41-1.097.742-1.663.742H7.01c-.558 0-1.3-.34-1.652-.77 0 0-5.358-6.056-5.358-10.81 0-3.338 1-7.367 1-7.367z" id="a"/><path d="M1 1.053L8 0l7 1.053s1 3.173 1 6.315c0 6.332-5.346 11.89-5.346 11.89-.36.41-1.097.742-1.663.742H7.01c-.558 0-1.3-.34-1.652-.77 0 0-5.358-6.056-5.358-10.81 0-3.338 1-7.367 1-7.367z" id="c"/></defs><g fill="none" fill-rule="evenodd"><mask id="b" fill="#fff"><use xlink:href="#a"/></mask><use fill="#FFAC00" xlink:href="#a"/><path stroke="#E49B16" d="M1.41 1.497L8 .507l6.61.993c.02.067.04.144.064.228.114.425.23.898.337 1.407.3 1.418.48 2.83.49 4.143v.09c0 2.665-.972 5.404-2.6 8.06-.57.934-1.185 1.79-1.8 2.55-.213.264-.412.498-.59.698-.105.118-.18.198-.216.237-.282.32-.882.587-1.302.587H7.01c-.414 0-1.01-.277-1.266-.587-.05-.06-.126-.146-.233-.274-.18-.216-.38-.464-.594-.74-.62-.79-1.237-1.654-1.814-2.56-.982-1.55-1.74-3.06-2.18-4.463C.645 9.994.5 9.17.5 8.42c0-.457.02-.944.057-1.457.077-1.072.23-2.22.435-3.392.11-.614.224-1.197.34-1.73L1.41 1.5z"/><path fill="#D79201" mask="url(#b)" d="M8 0h8v20H8z"/><mask id="d" fill="#fff"><use xlink:href="#c"/></mask><path stroke="#D49100" d="M1.41 1.497L8 .507l6.61.993c.02.067.04.144.064.228.114.425.23.898.337 1.407.3 1.418.48 2.83.49 4.143v.09c0 2.665-.972 5.404-2.6 8.06-.57.934-1.185 1.79-1.8 2.55-.213.264-.412.498-.59.698-.105.118-.18.198-.216.237-.282.32-.882.587-1.302.587H7.01c-.414 0-1.01-.277-1.266-.587-.05-.06-.126-.146-.233-.274-.18-.216-.38-.464-.594-.74-.62-.79-1.237-1.654-1.814-2.56-.982-1.55-1.74-3.06-2.18-4.463C.645 9.994.5 9.17.5 8.42c0-.457.02-.944.057-1.457.077-1.072.23-2.22.435-3.392.11-.614.224-1.197.34-1.73L1.41 1.5z"/><path fill="#472F00" mask="url(#d)" d="M4.28 12.632h1.9v-4.21l1.78 2.862H8L9.79 8.4v4.232h1.93v-7.37H9.67L8 8.117 6.33 5.263H4.28"/></g></svg>';
                                    var svgLowIcon = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="16" height="19" viewBox="0 0 16 19"><title>Low</title><defs><path d="M1 1l7-1 7 1s1 3.015 1 6c0 6.015-6 12-6 12H6S0 12.515 0 8c0-3.172 1-7 1-7z" id="a"/><path d="M1 1l7-1 7 1s1 3.015 1 6c0 6.015-6 12-6 12H6S0 12.515 0 8c0-3.172 1-7 1-7z" id="c"/></defs><g fill="none" fill-rule="evenodd"><path d="M7.96 17.32L8 .015l-6.5 1s-.96 4.5-.96 8.75c1.272 4.602 5.968 9.25 5.968 9.25h.163l1.29-1.695z" fill="#EDEFF5"/><mask id="b" fill="#fff"><use xlink:href="#a"/></mask><use fill="#FFEB3B" xlink:href="#a"/><path stroke="#E4D200" d="M1.404 1.447L8 .505l6.616.945.06.205c.114.402.23.85.336 1.334.298 1.34.48 2.68.488 3.923V7c0 2.515-1.09 5.243-2.916 7.978-.644.966-1.335 1.863-2.026 2.667-.24.28-.465.53-.665.745-.04.04-.074.077-.105.11H6.222l-.105-.118c-.202-.23-.427-.492-.67-.785-.694-.837-1.388-1.744-2.035-2.687-.89-1.298-1.62-2.56-2.128-3.738C.772 9.982.5 8.912.5 8c0-.433.02-.895.056-1.38.078-1.02.23-2.11.436-3.22.108-.584.223-1.137.34-1.64.026-.118.05-.222.072-.313z"/><path fill="#DDCE00" mask="url(#b)" d="M8-8h10v32H8z"/><mask id="d" fill="#fff"><use xlink:href="#c"/></mask><path stroke="#E4D200" d="M1.404 1.447L8 .505l6.616.945.06.205c.114.402.23.85.336 1.334.298 1.34.48 2.68.488 3.923V7c0 2.515-1.09 5.243-2.916 7.978-.644.966-1.335 1.863-2.026 2.667-.24.28-.465.53-.665.745-.04.04-.074.077-.105.11H6.222l-.105-.118c-.202-.23-.427-.492-.67-.785-.694-.837-1.388-1.744-2.035-2.687-.89-1.298-1.62-2.56-2.128-3.738C.772 9.982.5 8.912.5 8c0-.433.02-.895.056-1.38.078-1.02.23-2.11.436-3.22.108-.584.223-1.137.34-1.64.026-.118.05-.222.072-.313z"/><path fill="#605900" mask="url(#d)" d="M5.54 12h5.33v-1.7H7.48V5H5.54"/></g></svg>';

                                    switch (severity) {
                                        case SEVERITY.CRITICAL:
                                            svgIcon = svgCriticalIcon;
                                            severityNameTtl = "Critical";
                                            severityCountTtl = criticalCount;
                                            break;

                                        case SEVERITY.HIGH:
                                            svgIcon = svgHighIcon;
                                            severityNameTtl = "High";
                                            severityCountTtl = highCount;
                                            break;

                                        case SEVERITY.OSA_CRITICAL:
                                            svgIcon = svgCriticalIcon;
                                            severityNameTtl = "Critical";
                                            severityCountTtl = dependencyCriticalVulnerability;
                                            break;

                                        case SEVERITY.OSA_HIGH:
                                            svgIcon = svgHighIcon;
                                            severityNameTtl = "High";
                                            severityCountTtl = dependencyHighVulnerability;
                                            break;

                                        case SEVERITY.MED:
                                            svgIcon = svgMedIcon;
                                            severityNameTtl = "Medium";
                                            severityCountTtl = medCount;
                                            break;

                                        case SEVERITY.OSA_MED:
                                            svgIcon = svgMedIcon;
                                            severityNameTtl = "Medium";
                                            severityCountTtl = dependencyMediumVulnerability;
                                            break;

                                        case SEVERITY.LOW:
                                            svgIcon = svgLowIcon;
                                            severityNameTtl = "Low";
                                            severityCountTtl = lowCount;
                                            break;

                                        case SEVERITY.OSA_LOW:
                                            svgIcon = svgLowIcon;
                                            severityNameTtl = "Low";
                                            severityCountTtl = dependencyLowVulnerability;
                                            break;
                                    }

                                    return '' +
                                        '<div class="full-severity-title">' +
                                        '<div class="severity-icon">' +
                                        svgIcon +
                                        '</div>' +
                                        '<div class="severity-title-name">' + severityNameTtl + '</div>' +
                                        '<div class="severity-count">' + severityCountTtl + '</div>' +
                                        '</div>';
                                }

                                function generateSastCveTable(severity) {
                                    var severityCount ;
                                    var severityCveList;
                                    var tableElementId = "";

                                    switch (severity) {
                                        case SEVERITY.CRITICAL:
                                            severityCount = criticalCount;
                                            severityCveList = criticalCveList;
                                            tableElementId = "sast-cve-table-critical";
                                            break;

                                        case SEVERITY.HIGH:
                                            severityCount = highCount;
                                            severityCveList = highCveList;
                                            tableElementId = "sast-cve-table-high";
                                            break;

                                        case SEVERITY.MED:
                                            severityCount = medCount;
                                            severityCveList = medCveList;
                                            tableElementId = "sast-cve-table-med";
                                            break;

                                        case SEVERITY.LOW:
                                            severityCount = lowCount;
                                            severityCveList = lowCveList;
                                            tableElementId = "sast-cve-table-low";
                                            break;
                                    }

                                    //generate table title
                                    var severityTitle = generateCveTableTitle(severity);

                                    //generate table headers
                                    var tableHeadersNames = {h1: "Vulnerability Type", h2: "##"};
                                    var tableHeadersElement = generateCveTableHeaders(tableHeadersNames);

                                    //get container and create table element in it
                                    document.getElementById(tableElementId + '-container').innerHTML =
                                        severityTitle +
                                        '<table id="' + tableElementId + '" class="cve-table sast-cve-table ' + tableElementId + '">' +
                                        tableHeadersElement +
                                        '</table>';

                                    //get the created table
                                    var table = document.getElementById(tableElementId);

                                    //add rows to table
                                    var row;
                                    for (var cve in severityCveList) {
                                        row = table.insertRow();
                                        row.insertCell(0).innerHTML = cve;
                                        row.insertCell(1).innerHTML = severityCveList[cve];

                                    }
                                }

                                function addZero(i) {
                                    if (i < 10) {
                                        i = "0" + i;
                                    }
                                    return i;
                                }

                                function formatDate(date, format) {
                                    if(!isNaN(Date.parse(date)))
                                    {
                                        var d = new Date(date);
                                        var day = addZero(d.getDate());
                                        var month = addZero(d.getMonth() + 1); //starts from 0 (if the month is January getMonth returns 0)
                                        var year = d.getFullYear();
                                        var h = addZero(d.getHours());
                                        var m = addZero(d.getMinutes());
                                        var s = addZero(d.getSeconds());

                                        switch (format) {
                                            case "date":
                                            case "dd-mm-yyyy":
                                                return day + "-" + month + "-" + year;
                                                break;
                                            case "dateTime":
                                            case "dd/mm/yy hh:mm:ss":
                                                return day + "/" + month + "/" + year + " " + h + ":" + m + ":" + s;
                                                break;
                                            }
                                    }
                                    else
                                    {
                                        return date;
                                    }

                                }

                                function generateOsaCveTable(severity) {
                                    var severityCount;
                                    var severityCveList;
                                    var tableElementId = "";

                                    switch (severity) {
                                        case SEVERITY.OSA_CRITICAL:
                                            severityCount = dependencyCriticalVulnerability;
                                            severityCveList = dependencyCriticalCVEReportTable;
                                            tableElementId = "osa-cve-table-critical";
                                            break;

                                        case SEVERITY.OSA_HIGH:
                                            severityCount = dependencyHighVulnerability;
                                            severityCveList = dependencyHighCVEReportTable;
                                            tableElementId = "osa-cve-table-high";
                                            break;

                                        case SEVERITY.OSA_MED:
                                            severityCount = dependencyMediumVulnerability;
                                            severityCveList = dependencyMediumCVEReportTable;
                                            tableElementId = "osa-cve-table-med";
                                            break;

                                        case SEVERITY.OSA_LOW:
                                            severityCount = dependencyLowVulnerability;
                                            severityCveList = dependencyLowCVEReportTable;
                                            tableElementId = "osa-cve-table-low";
                                            break;
                                    }


                                    var libraryIdToName = libraryDictionary(dependencyLibraries);

                                    //create uniquness by key: cve + libraryId
                                    var osaCveMap = {};
                                    if(osaEnabled && osaFailed != true && severityCveList ){
                                       for (var i = 0; i < severityCveList.length; i++) {
                                           osaCveMap[severityCveList[i].cveName + "," + severityCveList[i].libraryId] = severityCveList[i];
                                       }
                                    }else if(scaResults !=null && scaResultReady){
                                        for (var i = 0; i < severityCveList.length; i++) {
                                            osaCveMap[severityCveList[i]._name + "," + severityCveList[i]._libraryName] = severityCveList[i];
                                        }
                                    }

                                    //generate table title
                                    var severityTitle = generateCveTableTitle(severity);

                                    //generate table headers
                                    var tableHeadersNames = {
                                        h1: "Vulnerability Type",
                                        h2: "Publish Date",
                                        h3: "Library"
                                    };
                                    var tableHeadersElement = generateCveTableHeaders(tableHeadersNames);

                                    //get container and create table element in it
                                    document.getElementById(tableElementId + '-container').innerHTML =
                                        severityTitle +
                                        '<table id="' + tableElementId + '" class="cve-table osa-cve-table ' + tableElementId + '">' +
                                        tableHeadersElement +
                                        '</table>';

                                    //get the created table
                                    var table = document.getElementById(tableElementId);

                                    //add rows to table
                                    var row;

                                    var i = 1;
                                    if(osaEnabled && osaFailed != true) {
                                        for (var key in osaCveMap) {
                                            row = table.insertRow(i);
                                            row.insertCell(0).innerHTML = osaCveMap[key].cveName;
                                            row.insertCell(1).innerHTML = formatDate(osaCveMap[key].publishDate, "dd-mm-yyyy");
                                            row.insertCell(2).innerHTML = libraryIdToName[osaCveMap[key].libraryId];
                                            if (osaCveMap[key].state != null && 'NOT_EXPLOITABLE' === osaCveMap[key].state.name) {
                                                row.classList.add('osa-cve-strike');
                                            }
                                            i++;
                                        }
                                    }else if(scaResults !=null && scaResultReady){
                                        for (var key in osaCveMap) {
                                            row = table.insertRow(i);
                                            row.insertCell(0).innerHTML = osaCveMap[key]._name;
                                            row.insertCell(1).innerHTML = formatDate(osaCveMap[key]._publishDate, "dd-mm-yyyy");
                                            row.insertCell(2).innerHTML = osaCveMap[key]._libraryName;
                                            if (osaCveMap[key]._state != null && 'NOT_EXPLOITABLE' === osaCveMap[key]._state) {
                                                row.classList.add('osa-cve-strike');
                                            }
                                            i++;
                                        }
                                    }
                                }

                                function generateCveTableHeaders(headers) {
                                    var ret = "<tr>";

                                    for (var h in headers) {
                                        ret += '<th>' + headers[h] + '</th>';
                                    }

                                    ret += "</tr>";
                                    return ret;
                                }

                                function generateCveTable(severity) {
                                    switch (severity) {
                                        case SEVERITY.CRITICAL:
                                        case SEVERITY.HIGH:
                                        case SEVERITY.MED:
                                        case SEVERITY.LOW:
                                            generateSastCveTable(severity);
                                            break;

                                        case SEVERITY.OSA_CRITICAL:
                                        case SEVERITY.OSA_HIGH:
                                        case SEVERITY.OSA_MED:
                                        case SEVERITY.OSA_LOW:
                                            generateOsaCveTable(severity);
                                            break;
                                    }
                                }

                                function numberWithCommas(x) {
                                    return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
                                }


                                function convertOSADataToList(cveAry) {
                                    var cveList = null;
                                    if (typeof cveAry != 'undefined' && cveAry != null) {
                                        cveAry = JSON.parse(cveAry);
                                        cveList = new Array();
                                        for (var i = 0; i < cveAry.length; i++) {
                                            //  var jsonObj = JSON.parse(cveAry[i]);
                                            //cveList.push(jsonObj);
                                            cveList.push(cveAry[i]);
                                        }
                                    }

                                    return cveList;
                                }


                                //query lists
                                function convertQueriesToList(querystr) {
                                    var queryAry = querystr.split(";");
                                    var queryList = new Array();
                                    for (var i = 0; i < queryAry.length - 1; i++) {
                                        var jsonObj = JSON.parse(queryAry[i]);
                                        queryList.push(jsonObj);
                                    }

                                    return queryList;
                                }


                                function generateQueryList(severity) {
                                    var severityQueryList = {};
                                    //loop through queries and push the relevant query - by severity - to the new list (lookup table)
                                    for (var i = 0; i < queryList.length; i++) {
                                        if (queryList[i].severity.toLowerCase() == severity.name || queryList[i].SeverityIndex == severity.value) {
                                            severityQueryList[queryList[i].name] = queryList[i].resultLength ? queryList[i].resultLength : 1;
                                        }
                                    }
                                    return severityQueryList;
                                }

                                //osa list
                                function generateOsaCveList(severity) {
                                    var severityOsaList = [];
                                    //loop through queries and push the relevant query - by severity - to the new list
                                    for (var i = 0; i < osaList.length; i++) {
                                        if (osaList[i].severity.name.toLowerCase() == severity.name) {
                                            severityOsaList.push(osaList[i]);
                                        }
                                    }
                                    return severityOsaList;
                                }

                                function libraryDictionary(osaLibraries) {
                                    var libraryIdToName = {};
                                    for (var i = 0; i < osaLibraries.length; i++) {
                                        libraryIdToName[osaLibraries[i].id] = osaLibraries[i].name;
                                    }
                                    return libraryIdToName;
                                }

                                function calculateEndDate(startDate, scanTime) {
                                    
                                    var start = new Date(startDate);
                                    //"00h:00m:00s"
                                    var scanTimeHours = scanTime.substring(0, 2);
                                    var scanTimeMinutes = scanTime.substring(4, 6);
                                    var scanTimeSeconds = scanTime.substring(8, 10);
                                    var scanTimeMillis = scanTimeHours * 3600000 + scanTimeMinutes * 60000 + scanTimeSeconds * 1000;

                                    if(!isNaN(Date.parse(startDate)))
                                    {
                                        return new Date(start.getTime() + scanTimeMillis);
                                    }
                                    else
                                    {
                                        return calculateEndDateOfOtherLanguages(startDate,scanTimeMillis);
                                    }

                                }

                                function calculateEndDateOfOtherLanguages(startDate,scanTimeMillis)
                                {
                                    let timeParts = startDate.split(' ')[ startDate.split(' ').length -1].split(':');
                                    let hours = parseInt(timeParts[0]);
                                    let minutes = parseInt(timeParts[1]);
                                    let seconds = parseInt(timeParts[2]);
                                    let date = new Date();
                                    date.setHours(hours, minutes, seconds, 0);
                                    date.setMilliseconds(date.getMilliseconds() + scanTimeMillis);
                                    return calculateDateUsingArray(startDate.split(' ')) + " " + date.toLocaleTimeString('en-US', { hour12: false})
                                }

                                function calculateDateUsingArray(startDate)
                                {
                                    let result = "";
                                    for (let i = 0; i < startDate.length - 1; i++) {
                                        result += startDate[i];
                                        if (i < startDate.length - 1) {
                                            result += " ";  // Add comma and space between elements
                                        }
                                    }
                                    return result;
                                }

                                function adjustDateFormat(date) {
                                    return date.substr(0, 10) + " " + date.substr(11);
                                }

                            });
                        }
                    }, function (error) {
                        console.log(error)
                    });
                });
            }
        };
        return StatusSection;
    }(Controls.BaseControl));
    exports.StatusSection = StatusSection;
    StatusSection.enhance(StatusSection, $(".cx-report"), {});
    VSS.notifyLoadSucceeded();
});
