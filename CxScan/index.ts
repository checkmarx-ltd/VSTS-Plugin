import taskLib = require('azure-pipelines-task-lib/task');
import {ScanConfig} from "./scanConfig";
import {RestClient} from "./services/restClient";

async function run() {
    // To run this task in console, the following environment variables must be defined:
    // INPUT_PROJECTNAME=VstsTest1;ENDPOINT_AUTH_PARAMETER_endpointId_USERNAME=myusername;
    // ENDPOINT_AUTH_PARAMETER_endpointId_PASSWORD=mypassword;INPUT_CheckmarxService=endpointId;
    // ENDPOINT_URL_endpointId=http://10.32.1.16;BUILD_SOURCESDIRECTORY=c:/cxdev/ProjectToScan;
    // INPUT_FULLTEAMNAME=CxServer

    try {
        const config = createConfig();

        const restClient = new RestClient(config);
        await restClient.init();
        await restClient.createSASTScan();
    } catch (err) {
        console.log(err);
        taskLib.setResult(taskLib.TaskResult.Failed, err.message);
    }
}

function createConfig(): ScanConfig {
    const endpointId = taskLib.getInput('CheckmarxService', true) || '';

    const sourceDir = taskLib.getVariable('Build.SourcesDirectory');
    if (typeof sourceDir === 'undefined') {
        throw Error('Sources directory is not provided.');
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
        comment: taskLib.getInput('comment', false) || '',

        // TODO: make sure the hardcoding is OK.
        forceScan: false,
        isPublic: true
    };
}

run();