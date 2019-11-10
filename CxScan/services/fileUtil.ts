import {tmpNameSync} from "tmp";
import taskLib = require('azure-pipelines-task-lib/task');

export class FileUtil {
    static generateTempFileName(options: { prefix: string; postfix: string }): string {
        // A temporary folder that is cleaned after each pipeline run, so that we don't have to remove
        // temp files manually.
        const tempDir = taskLib.getVariable('Agent.TempDirectory');

        // If the agent variable above is not specified (e.g. in debug environment), tempDir is undefined and
        // tmpNameSync function falls back to a default temp directory.
        return tmpNameSync({dir: tempDir, ...options});
    }
}