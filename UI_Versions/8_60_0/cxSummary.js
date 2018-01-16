var __extends = (this && this.__extends) || (function () {
        var extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return function (d, b) {
            extendStatics(d, b);
            function __() { this.constructor = d; }
            d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
        };
    })();
define(["require", "exports", "VSS/Controls", "TFS/DistributedTask/TaskRestClient"], function (require, exports, Controls, DT_Client) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
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
                            taskClient.getAttachmentContent(vsoContext.project.id, "build", build.orchestrationPlan.planId, timelineId, recId, "cxReport", "cxReport").then(function (attachementContent) {

                                function arrayBufferToString(buffer) {
                                    var bufView = new Uint16Array(buffer);
                                    var length = bufView.length;
                                    var result = '';
                                    var addition = Math.pow(2, 16) - 1;
                                    for (var i = 0; i < length; i += addition) {
                                        if (i + addition > length) {
                                            addition = length - i;
                                        }
                                        result += String.fromCharCode.apply(null, bufView.subarray(i, i + addition));
                                    }
                                    return result;
                                }



                                var summaryPageData = arrayBufferToString(attachementContent);
                                 var resultObject = JSON.parse(summaryPageData.replace(/[\u200B-\u200D\uFEFF]/g, ''));

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
                                var osaHtmlPath = osaSummaryResultsLink;
                                //counts
                                var osaHighCount = resultObject.osaHighResults;
                                var osaMedCount = resultObject.osaMediumResults;
                                var osaLowCount = resultObject.osaLowResults;



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


                                //---------------------------------------------------------- sast ---------------------------------------------------------------
                                if (syncMode != false) { //Synchronous Mode
                                    document.getElementById("asyncMessage").setAttribute("style", "display:none");
                                    document.getElementById("onAsyncMode").setAttribute("style", "display:none");
                                    if (sastResultsReady == true) {
                                        try {
                                            document.getElementById("results-report").setAttribute("style", "display:block");

                                            //link
                                            document.getElementById("sast-summary-html-link").setAttribute("href", sastScanResultsLink);

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

                                                if (medThreshold != null && medThreshold!="" && medCount > medThreshold) {
                                                    document.getElementById("tooltip-med").innerHTML = tooltipGenerator(SEVERITY.MED);
                                                    isThresholdExceeded = true;
                                                }

                                                if (lowThreshold != null && lowThreshold!= "" && lowCount > lowThreshold) {
                                                    document.getElementById("tooltip-low").innerHTML = tooltipGenerator(SEVERITY.LOW);
                                                    isThresholdExceeded = true;
                                                }


                                                //if threshold exceeded
                                                if (isThresholdExceeded  == true) {
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
                                            document.getElementById("osa-summary").setAttribute("style", "display:block");
                                            //link
                                            document.getElementById("osa-summary-html-link").setAttribute("href", osaHtmlPath);

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
                                        if (osaThresholdsEnabled  == true) {
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
                                                if (isOsaThresholdExceeded  == true) {
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
                                }
                                else {  //AsyncMode
                                    if (sastResultsReady != false) {
                                        var asyncModeMessage = "Cxscan was run in Asynchronous mode";
                                        var asyncDiv = document.getElementById("asyncMessage");
                                        asyncDiv.innerHTML = asyncModeMessage;
                                        asyncDiv.setAttribute("style", "display:block");
                                        document.getElementById("onAsyncMode").setAttribute("style", "display:block");
                                    }else {
                                        document.getElementById("onSastError").setAttribute("style", "display:block");
                                        document.getElementById("scanErrorMessage").setAttribute("style", "display:block");
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

                                function numberWithCommas(x) {
                                    return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
                                }


                            });
                        }
                    }, function(error){
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
