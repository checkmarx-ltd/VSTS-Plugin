import {Logger} from "./logger";
import * as taskLib from "azure-pipelines-task-lib";

export class ConsoleLogger implements Logger {
    info(message: string): void {
        console.log(message);
    }

    error(message: string): void {
        // If we don't split the message into lines, taskLib will only highlight the first message line as an error.
        const lines = message.replace('\r\n', '\n')
            .split('\n');

        for (const line of lines){
            taskLib.error(line);
        }
    }

    debug(message: string): void {
        taskLib.debug(message);
    }
}