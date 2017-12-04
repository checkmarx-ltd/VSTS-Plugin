import Controls = require("VSS/Controls");
import VSS_Service = require("VSS/Service");
import TFS_Build_Contracts = require("TFS/Build/Contracts");
import TFS_Build_Extension_Contracts = require("TFS/Build/ExtensionContracts");

export class StatusSection extends Controls.BaseControl {
	constructor() {
		super();
	}

	public initialize(): void {
		super.initialize();
		// Get configuration that's shared between extension and the extension host
		var sharedConfig: TFS_Build_Extension_Contracts.IBuildResultsViewExtensionConfig = VSS.getConfiguration();
		var vsoContext = VSS.getWebContext();

		if (sharedConfig) {
			// register your extension with host through callback
			sharedConfig.onBuildChanged((build: TFS_Build_Contracts.Build) => {
				this._initBuildInfo(build);
				var taskClient = DT_Client.getClient();
				taskClient.getPlanAttachments(vsoContext.project.id, "build", build.orchestrationPlan.planId, "cxRiskReport").then((taskAttachments) => {

					if (taskAttachments.length === 1) {

						$(".risk-report-message").remove();

						var recId = taskAttachments[0].recordId;
						var timelineId = taskAttachments[0].timelineId;

						taskClient.getAttachmentContent(vsoContext.project.id, "build", build.orchestrationPlan.planId, timelineId, recId, "cxRiskReport", "riskreport").then((attachementContent) => {

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
console.log("fsfasfasf")
console.log(attachementContent[0].scanStartDate)
console.log(attachementContent[0])
console.log(attachementContent.scanStartDate)
							//var riskObject = JSON.parse(summaryPageData.replace(/[\u200B-\u200D\uFEFF]/g, ''));

							var projectVersion = "<div class='project-version'><span>" +
								"<a href='" + attachementContent[0].scanStartDate + "' target='_blank'>" + "projectName" + "</a></span>" +
								"<span class='project-version-separator'><i class='fa fa-caret-right'></i></span><span>" +
								"<a href='" + "projectVersionLink" + "' target='_blank'>" + attachementContent.scanStartDate + "</a></span></div>"

							var bomCount = $("<div>", {"class": "total-count", "text": "BOM Entries: " + "totalCount"});



							$(".risk-report").append(projectVersion);
							$(".risk-report").append(bomCount);


						});
					}
				});
			});
		}
	}
}

StatusSection.cxreport(StatusSection, $(".cx-risk-report"), {});

// Notify the parent frame that the host has been loaded
VSS.notifyLoadSucceeded();


