import taskLib = require('azure-pipelines-task-lib/task');
import { Client } from './services/client';

async function run() {
    // To run this task in console, the following environment variables must be defined:
    // INPUT_PROJECTNAME=VstsTest1;ENDPOINT_AUTH_PARAMETER_endpointId_USERNAME=myusername;
    // ENDPOINT_AUTH_PARAMETER_endpointId_PASSWORD=mypassword;INPUT_CheckmarxService=endpointId;
    // ENDPOINT_URL_endpointId=http://10.32.1.16;BUILD_SOURCESDIRECTORY=c:/cxdev/ProjectToScan;
    // INPUT_FULLTEAMNAME=CxServer

    try {
        const pathToSource = taskLib.getVariable('Build.SourcesDirectory');
        const projectName = taskLib.getInput('projectName', true);
        const owningTeam =  taskLib.getInput('fullTeamName', true);

        const endpointId: string = taskLib.getInput('CheckmarxService', true);
        const username = taskLib.getEndpointAuthorizationParameter(endpointId, 'username', false);
        const password = taskLib.getEndpointAuthorizationParameter(endpointId, 'password', false);
        const serverURL = taskLib.getEndpointUrl(endpointId, false);

        const client = new Client(serverURL);

        await client.login(username, password);

        const projectId: number = await client.createProject(owningTeam, projectName, true);
        const tempFilename: string = projectName + projectId;
        await client.uploadSourceCode(projectId, pathToSource, tempFilename);

        let scanId = await client.createNewScan(projectId, false, true, true, 'Scan from VSTS');
        console.log(`Scan ID: ${scanId}`);
    } catch (err) {
        console.log(err);
        taskLib.setResult(taskLib.TaskResult.Failed, err.message);
    }
}

run();