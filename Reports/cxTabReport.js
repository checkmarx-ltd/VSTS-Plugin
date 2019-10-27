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
                                    HIGH: {value: 0, name: "high"},
                                    MED: {value: 1, name: "medium"},
                                    LOW: {value: 2, name: "low"},
                                    OSA_HIGH: {value: 3, name: "high"},
                                    OSA_MED: {value: 4, name: "medium"},
                                    OSA_LOW: {value: 5, name: "low"}
                                };

                                //-------------------------- sast vars --------------------------------------
                                var sastResultsReady = resultObject.sastResultsReady;
                                var buildFailed = resultObject.buildFailed;

                                //thresholds
                                var thresholdsEnabled = resultObject.thresholdEnabled;
                                var highThreshold = resultObject.highThreshold;
                                var medThreshold = resultObject.mediumThreshold;
                                var lowThreshold = resultObject.lowThreshold;

                                //links

                                var sastScanResultsLink = resultObject.sastScanResultsLink;
                                var sastSummaryResultsLink = resultObject.sastSummaryResultsLink;

                                //AsyncMode
                                var syncMode = resultObject.syncMode;

                                if (sastResultsReady == true) {
                                    //counts
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
                                    var osaHighThreshold = resultObject.osaHighThreshold;
                                    var osaMedThreshold = resultObject.osaMediumThreshold;
                                    var osaLowThreshold = resultObject.osaLowThreshold;

                                    //links
                                    var osaSummaryResultsLink = resultObject.osaSummaryResultsLink;

                                    //counts
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
                                    var osaHighCveList;
                                    var osaMedCveList;
                                    var osaLowCveList;


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
                                    if (sastResultsReady == true) {
                                        try {
                                            document.getElementById("results-report").setAttribute("style", "display:block");
                                            document.getElementById("report-title").setAttribute("style", "display:block");

                                            //link
                                            document.getElementById("sast-summary-html-link").setAttribute("href", sastScanResultsLink);
                                            document.getElementById("sast-code-viewer-link").setAttribute("href", sastScanResultsLink);

                                            //set bars height and count
                                            document.getElementById("bar-count-high").innerHTML = highCount;
                                            document.getElementById("bar-count-med").innerHTML = medCount;
                                            document.getElementById("bar-count-low").innerHTML = lowCount;

                                            var maxCount = Math.max(highCount, medCount, lowCount);
                                            var maxHeight = maxCount * 100 / 90;
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

                                                if (highThreshold != null && highThreshold != "" && highCount > highThreshold) {
                                                    document.getElementById("tooltip-high").innerHTML = tooltipGenerator(SEVERITY.HIGH);
                                                    isThresholdExceeded = true;
                                                }

                                                if (medThreshold != null && medThreshold != "" && medCount > medThreshold) {
                                                    document.getElementById("tooltip-med").innerHTML = tooltipGenerator(SEVERITY.MED);
                                                    isThresholdExceeded = true;
                                                }

                                                if (lowThreshold != null && lowThreshold != "" && lowCount > lowThreshold) {
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
                                    else {
                                        document.getElementById("onSastError").setAttribute("style", "display:block");
                                        document.getElementById("scanErrorMessage").setAttribute("style", "display:block");
                                    }

                                    //---------------------------------------------------------- osa ---------------------------------------------------------------
                                    if (osaEnabled == true && osaFailed != true) {
                                        try {
                                            document.getElementById("report-title").setAttribute("style", "display:block");
                                            document.getElementById("osa-summary").setAttribute("style", "display:block");
                                            //link
                                            document.getElementById("osa-summary-html-link").setAttribute("href", osaSummaryResultsLink);

                                            //set bars height and count
                                            document.getElementById("osa-bar-count-high").innerHTML = osaHighCount;
                                            document.getElementById("osa-bar-count-med").innerHTML = osaMedCount;
                                            document.getElementById("osa-bar-count-low").innerHTML = osaLowCount;


                                            var osaMaxCount = Math.max(osaHighCount, osaMedCount, osaLowCount);
                                            var osaMaxHeight = osaMaxCount * 100 / 90;

                                            document.getElementById("osa-bar-high").setAttribute("style", "height:" + osaHighCount * 100 / osaMaxHeight + "%");
                                            document.getElementById("osa-bar-med").setAttribute("style", "height:" + osaMedCount * 100 / osaMaxHeight + "%");
                                            document.getElementById("osa-bar-low").setAttribute("style", "height:" + osaLowCount * 100 / osaMaxHeight + "%");

                                            document.getElementById("vulnerable-libraries").innerHTML = numberWithCommas(osaVulnerableAndOutdatedLibs);
                                            document.getElementById("ok-libraries").innerHTML = numberWithCommas(okLibraries);
                                        }
                                        catch (e) {
                                            console.error("Element missing in OSA summary section " + e.message);
                                        }

                                        //if threshold is enabled
                                        if (osaThresholdsEnabled == true) {
                                            try {
                                                var isOsaThresholdExceeded = false;
                                                var osaThresholdExceededComplianceElement = document.getElementById("osa-threshold-exceeded-compliance");


                                                if (osaHighThreshold != null && osaHighThreshold != "" && osaHighCount > osaHighThreshold) {
                                                    document.getElementById("osa-tooltip-high").innerHTML = tooltipGenerator(SEVERITY.OSA_HIGH);
                                                    isOsaThresholdExceeded = true;
                                                }

                                                if (osaMedThreshold != null && osaMedThreshold != "" && osaMedCount > osaMedThreshold) {
                                                    document.getElementById("osa-tooltip-med").innerHTML = tooltipGenerator(SEVERITY.OSA_MED);
                                                    isOsaThresholdExceeded = true;
                                                }

                                                if (osaLowThreshold != null && osaMedThreshold != "" && osaLowCount > osaLowThreshold) {
                                                    document.getElementById("osa-tooltip-low").innerHTML = tooltipGenerator(SEVERITY.OSA_LOW);
                                                    isOsaThresholdExceeded = true;
                                                }


                                                //if threshold exceeded
                                                if (isOsaThresholdExceeded == true) {
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
                                    }
                                    else {
                                        document.getElementById("sast-summary").setAttribute("class", "sast-summary chart-large");
                                    }

                                    //---------------------------------------------------------- full reports ---------------------------------------------------------------
                                    if (isSastFullReady == true) {
                                        document.getElementById("sast-full").setAttribute("style", "display: block");

                                        //queries lists
                                        highCveList = generateQueryList(SEVERITY.HIGH);
                                        medCveList = generateQueryList(SEVERITY.MED);
                                        lowCveList = generateQueryList(SEVERITY.LOW);


                                        try {
                                            //sast links
                                            document.getElementById("sast-code-viewer-link").setAttribute("href", sastScanResultsLink);

                                            //sast info
                                            document.getElementById("sast-full-start-date").innerHTML = formatDate(sastStartDate, "dd/mm/yy hh:mm");
                                            document.getElementById("sast-full-end-date").innerHTML = formatDate(sastEndDate, "dd/mm/yy hh:mm");
                                            document.getElementById("sast-full-files").innerHTML = numberWithCommas(sastNumFiles);
                                            document.getElementById("sast-full-loc").innerHTML = numberWithCommas(sastLoc);

                                        } catch (e) {
                                            console.error("Element missing in full report info section " + e.message);
                                        }

                                        try {
                                            //generate full reports
                                            if (highCount == 0 && medCount == 0 && lowCount == 0) {
                                                document.getElementById("sast-full").setAttribute("style", "display: none");
                                            } else {
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

                                    if (isOsaFullReady == true) {
                                        document.getElementById("osa-full").setAttribute("style", "display: block");
                                        //cve lists
                                        osaHighCveList = generateOsaCveList(SEVERITY.OSA_HIGH);
                                        osaMedCveList = generateOsaCveList(SEVERITY.OSA_MED);
                                        osaLowCveList = generateOsaCveList(SEVERITY.OSA_LOW);

                                        osaNumFiles = osaLibraries.length;

                                        try {


                                            //osa links
                                            document.getElementById("osa-html-link").setAttribute("href", osaSummaryResultsLink);


                                            //osa info
                                            document.getElementById("osa-full-start-date").innerHTML = formatDate(osaStartDate, "dd/mm/yy hh:mm");
                                            document.getElementById("osa-full-end-date").innerHTML = formatDate(osaEndDate, "dd/mm/yy hh:mm");
                                            document.getElementById("osa-full-files").innerHTML = numberWithCommas(osaNumFiles);
                                        } catch (e) {
                                            console.error("Element missing in full report info section " + e.message);
                                        }

                                        try {
                                            //generate full reports
                                            if (osaHighCveList.length == 0 && osaMedCveList.length == 0 && osaLowCveList.length == 0) {
                                                document.getElementById("osa-full").setAttribute("style", "display: none");
                                            } else {
                                                if (osaHighCveList.length > 0) {
                                                    generateCveTable(SEVERITY.OSA_HIGH);
                                                }
                                                if (osaMedCveList.length > 0) {
                                                    generateCveTable(SEVERITY.OSA_MED);
                                                }
                                                if (osaLowCveList.length > 0) {
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
                                        var asyncModeMessage = "Scan was run in Asynchronous mode";
                                        var asyncDiv = document.getElementById("asyncMessage");
                                        asyncDiv.innerHTML = asyncModeMessage;
                                        asyncDiv.setAttribute("style", "display:block");
                                        document.getElementById("onAsyncMode").setAttribute("style", "display:block");

                                    }
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

                                        case SEVERITY.OSA_HIGH:
                                            threshold = osaHighThreshold;
                                            count = osaHighCount;
                                            break;
                                        case SEVERITY.OSA_MED:
                                            threshold = osaMedThreshold;
                                            count = osaMedCount;
                                            break;
                                        case SEVERITY.OSA_LOW:
                                            threshold = osaLowThreshold;
                                            count = osaLowCount;
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

                                    var svgHighIcon = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="16" height="19" viewBox="0 0 16 19"><title>Med</title><defs><path d="M1 1l7-1 7 1s1 3.015 1 6c0 6.015-5.323 11.27-5.323 11.27-.374.403-1.12.73-1.686.73H7.01c-.558 0-1.308-.333-1.675-.76C5.335 18.24 0 12.516 0 8c0-3.172 1-7 1-7z" id="a"/><path d="M1 1l7-1 7 1s1 3.015 1 6c0 6.015-5.323 11.27-5.323 11.27-.374.403-1.12.73-1.686.73H7.01c-.558 0-1.308-.333-1.675-.76C5.335 18.24 0 12.516 0 8c0-3.172 1-7 1-7z" id="c"/></defs><g fill="none" fill-rule="evenodd"><mask id="b" fill="#fff"><use xlink:href="#a"/></mask><use fill="#D82D49" xlink:href="#a"/><path stroke="#BB1A34" d="M1.404 1.447L8 .505l6.616.945.06.205c.114.402.23.85.336 1.334.298 1.342.48 2.682.488 3.924V7c0 2.52-.966 5.112-2.582 7.62-.57.884-1.18 1.694-1.79 2.41-.214.252-.41.472-.588.66-.104.113-.178.188-.215.224-.296.32-.91.586-1.334.586H7.01c-.42 0-1.028-.274-1.296-.585-.052-.056-.127-.14-.233-.26-.178-.202-.378-.436-.593-.697-.615-.747-1.23-1.564-1.804-2.422C2.097 13.06 1.34 11.62.906 10.284.64 9.462.5 8.697.5 8c0-.433.02-.895.056-1.38C.634 5.6.786 4.51.992 3.4c.108-.584.223-1.137.34-1.64.026-.118.05-.222.072-.313z"/><path fill="#BB1A34" mask="url(#b)" d="M8 0h8v20H8z"/><mask id="d" fill="#fff"><use xlink:href="#c"/></mask><path stroke="#BB1A34" d="M1.404 1.447L8 .505l6.616.945.06.205c.114.402.23.85.336 1.334.298 1.342.48 2.682.488 3.924V7c0 2.52-.966 5.112-2.582 7.62-.57.884-1.18 1.694-1.79 2.41-.214.252-.41.472-.588.66-.104.113-.178.188-.215.224-.296.32-.91.586-1.334.586H7.01c-.42 0-1.028-.274-1.296-.585-.052-.056-.127-.14-.233-.26-.178-.202-.378-.436-.593-.697-.615-.747-1.23-1.564-1.804-2.422C2.097 13.06 1.34 11.62.906 10.284.64 9.462.5 8.697.5 8c0-.433.02-.895.056-1.38C.634 5.6.786 4.51.992 3.4c.108-.584.223-1.137.34-1.64.026-.118.05-.222.072-.313z"/><path fill="#FFF" mask="url(#d)" d="M5 12h2V9.5h2V12h2V5H9v2.5H7V5H5"/></g></svg>';
                                    var svgMedIcon = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="16" height="20" viewBox="0 0 16 20"><title>Low</title><defs><path d="M1 1.053L8 0l7 1.053s1 3.173 1 6.315c0 6.332-5.346 11.89-5.346 11.89-.36.41-1.097.742-1.663.742H7.01c-.558 0-1.3-.34-1.652-.77 0 0-5.358-6.056-5.358-10.81 0-3.338 1-7.367 1-7.367z" id="a"/><path d="M1 1.053L8 0l7 1.053s1 3.173 1 6.315c0 6.332-5.346 11.89-5.346 11.89-.36.41-1.097.742-1.663.742H7.01c-.558 0-1.3-.34-1.652-.77 0 0-5.358-6.056-5.358-10.81 0-3.338 1-7.367 1-7.367z" id="c"/></defs><g fill="none" fill-rule="evenodd"><mask id="b" fill="#fff"><use xlink:href="#a"/></mask><use fill="#FFAC00" xlink:href="#a"/><path stroke="#E49B16" d="M1.41 1.497L8 .507l6.61.993c.02.067.04.144.064.228.114.425.23.898.337 1.407.3 1.418.48 2.83.49 4.143v.09c0 2.665-.972 5.404-2.6 8.06-.57.934-1.185 1.79-1.8 2.55-.213.264-.412.498-.59.698-.105.118-.18.198-.216.237-.282.32-.882.587-1.302.587H7.01c-.414 0-1.01-.277-1.266-.587-.05-.06-.126-.146-.233-.274-.18-.216-.38-.464-.594-.74-.62-.79-1.237-1.654-1.814-2.56-.982-1.55-1.74-3.06-2.18-4.463C.645 9.994.5 9.17.5 8.42c0-.457.02-.944.057-1.457.077-1.072.23-2.22.435-3.392.11-.614.224-1.197.34-1.73L1.41 1.5z"/><path fill="#D79201" mask="url(#b)" d="M8 0h8v20H8z"/><mask id="d" fill="#fff"><use xlink:href="#c"/></mask><path stroke="#D49100" d="M1.41 1.497L8 .507l6.61.993c.02.067.04.144.064.228.114.425.23.898.337 1.407.3 1.418.48 2.83.49 4.143v.09c0 2.665-.972 5.404-2.6 8.06-.57.934-1.185 1.79-1.8 2.55-.213.264-.412.498-.59.698-.105.118-.18.198-.216.237-.282.32-.882.587-1.302.587H7.01c-.414 0-1.01-.277-1.266-.587-.05-.06-.126-.146-.233-.274-.18-.216-.38-.464-.594-.74-.62-.79-1.237-1.654-1.814-2.56-.982-1.55-1.74-3.06-2.18-4.463C.645 9.994.5 9.17.5 8.42c0-.457.02-.944.057-1.457.077-1.072.23-2.22.435-3.392.11-.614.224-1.197.34-1.73L1.41 1.5z"/><path fill="#472F00" mask="url(#d)" d="M4.28 12.632h1.9v-4.21l1.78 2.862H8L9.79 8.4v4.232h1.93v-7.37H9.67L8 8.117 6.33 5.263H4.28"/></g></svg>';
                                    var svgLowIcon = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="16" height="19" viewBox="0 0 16 19"><title>Low</title><defs><path d="M1 1l7-1 7 1s1 3.015 1 6c0 6.015-6 12-6 12H6S0 12.515 0 8c0-3.172 1-7 1-7z" id="a"/><path d="M1 1l7-1 7 1s1 3.015 1 6c0 6.015-6 12-6 12H6S0 12.515 0 8c0-3.172 1-7 1-7z" id="c"/></defs><g fill="none" fill-rule="evenodd"><path d="M7.96 17.32L8 .015l-6.5 1s-.96 4.5-.96 8.75c1.272 4.602 5.968 9.25 5.968 9.25h.163l1.29-1.695z" fill="#EDEFF5"/><mask id="b" fill="#fff"><use xlink:href="#a"/></mask><use fill="#FFEB3B" xlink:href="#a"/><path stroke="#E4D200" d="M1.404 1.447L8 .505l6.616.945.06.205c.114.402.23.85.336 1.334.298 1.34.48 2.68.488 3.923V7c0 2.515-1.09 5.243-2.916 7.978-.644.966-1.335 1.863-2.026 2.667-.24.28-.465.53-.665.745-.04.04-.074.077-.105.11H6.222l-.105-.118c-.202-.23-.427-.492-.67-.785-.694-.837-1.388-1.744-2.035-2.687-.89-1.298-1.62-2.56-2.128-3.738C.772 9.982.5 8.912.5 8c0-.433.02-.895.056-1.38.078-1.02.23-2.11.436-3.22.108-.584.223-1.137.34-1.64.026-.118.05-.222.072-.313z"/><path fill="#DDCE00" mask="url(#b)" d="M8-8h10v32H8z"/><mask id="d" fill="#fff"><use xlink:href="#c"/></mask><path stroke="#E4D200" d="M1.404 1.447L8 .505l6.616.945.06.205c.114.402.23.85.336 1.334.298 1.34.48 2.68.488 3.923V7c0 2.515-1.09 5.243-2.916 7.978-.644.966-1.335 1.863-2.026 2.667-.24.28-.465.53-.665.745-.04.04-.074.077-.105.11H6.222l-.105-.118c-.202-.23-.427-.492-.67-.785-.694-.837-1.388-1.744-2.035-2.687-.89-1.298-1.62-2.56-2.128-3.738C.772 9.982.5 8.912.5 8c0-.433.02-.895.056-1.38.078-1.02.23-2.11.436-3.22.108-.584.223-1.137.34-1.64.026-.118.05-.222.072-.313z"/><path fill="#605900" mask="url(#d)" d="M5.54 12h5.33v-1.7H7.48V5H5.54"/></g></svg>';

                                    switch (severity) {
                                        case SEVERITY.HIGH:
                                            svgIcon = svgHighIcon;
                                            severityNameTtl = "High";
                                            severityCountTtl = highCount;
                                            break;

                                        case SEVERITY.OSA_HIGH:
                                            svgIcon = svgHighIcon;
                                            severityNameTtl = "High";
                                            severityCountTtl = osaHighCount;
                                            break;

                                        case SEVERITY.MED:
                                            svgIcon = svgMedIcon;
                                            severityNameTtl = "Medium";
                                            severityCountTtl = medCount;
                                            break;

                                        case SEVERITY.OSA_MED:
                                            svgIcon = svgMedIcon;
                                            severityNameTtl = "Medium";
                                            severityCountTtl = osaMedCount;
                                            break;

                                        case SEVERITY.LOW:
                                            svgIcon = svgLowIcon;
                                            severityNameTtl = "Low";
                                            severityCountTtl = lowCount;
                                            break;

                                        case SEVERITY.OSA_LOW:
                                            svgIcon = svgLowIcon;
                                            severityNameTtl = "Low";
                                            severityCountTtl = osaLowCount;
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
                                    var severityCount;
                                    var severityCveList;
                                    var tableElementId = "";

                                    switch (severity) {
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
                                    var d = new Date(date);
                                    var day = addZero(d.getDate());
                                    var month = addZero(d.getMonth() + 1); //starts from 0 (if the month is January getMonth returns 0)
                                    var year = d.getFullYear();
                                    var h = addZero(d.getHours());
                                    var m = addZero(d.getMinutes());

                                    switch (format) {
                                        case "date":
                                        case "dd-mm-yyyy":
                                            return day + "-" + month + "-" + year;
                                            break;
                                        case "dateTime":
                                        case "dd/mm/yy hh:mm":
                                            return day + "/" + month + "/" + year + " " + h + ":" + m;
                                            break;
                                    }

                                }

                                function generateOsaCveTable(severity) {
                                    var severityCount;
                                    var severityCveList;
                                    var tableElementId = "";

                                    switch (severity) {
                                        case SEVERITY.OSA_HIGH:
                                            severityCount = osaHighCount;
                                            severityCveList = osaHighCveList;
                                            tableElementId = "osa-cve-table-high";
                                            break;

                                        case SEVERITY.OSA_MED:
                                            severityCount = osaMedCount;
                                            severityCveList = osaMedCveList;
                                            tableElementId = "osa-cve-table-med";
                                            break;

                                        case SEVERITY.OSA_LOW:
                                            severityCount = osaLowCount;
                                            severityCveList = osaLowCveList;
                                            tableElementId = "osa-cve-table-low";
                                            break;
                                    }


                                    var libraryIdToName = libraryDictionary(osaLibraries);

                                    //create uniquness by key: cve + libraryId
                                    var osaCveMap = {};
                                    for (var i = 0; i < severityCveList.length; i++) {
                                        osaCveMap[severityCveList[i].cveName + "," + severityCveList[i].libraryId] = severityCveList[i];
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
                                        case SEVERITY.HIGH:
                                        case SEVERITY.MED:
                                        case SEVERITY.LOW:
                                            generateSastCveTable(severity);
                                            break;

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
                                        if (queryList[i].severity.toLowerCase() == severity.name) {
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

                                    return new Date(start.getTime() + scanTimeMillis);

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
