import promisePoller from "promise-poller";
import {PollingSettings} from "../dto/pollingSettings";

export class Waiter {
    waitForTaskToFinish<T>(
        taskFn: () => T | PromiseLike<T>,
        progressCallback: (error: any) => void,
        polling: PollingSettings): Promise<T> {
        return promisePoller({
            taskFn,
            progressCallback: (retriesRemaining, error) => progressCallback(error),
            interval: polling.intervalSeconds * 1000,
            masterTimeout: polling.masterTimeoutMinutes * 60 * 1000,
            retries: Number.MAX_SAFE_INTEGER
        });
    }
}