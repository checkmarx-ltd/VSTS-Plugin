import promisePoller from "promise-poller";
import {PollingSettings} from "../dto/pollingSettings";

export class Waiter {
    waitForTaskToFinish<T>(
        taskFn: () => T | PromiseLike<T>,
        progressCallback: (error: any) => void,
        polling: PollingSettings): Promise<T> {

        const UNLIMITED_TIMEOUT = undefined;

        let effectiveMasterTimeout;
        if (!polling.masterTimeoutMinutes) {
            effectiveMasterTimeout = UNLIMITED_TIMEOUT;
        }
        else {
            effectiveMasterTimeout = polling.masterTimeoutMinutes * 60 * 1000;
        }

        return promisePoller({
            taskFn,
            progressCallback: (retriesRemaining, error) => progressCallback(error),
            interval: polling.intervalSeconds * 1000,
            masterTimeout: effectiveMasterTimeout,
            retries: Number.MAX_SAFE_INTEGER
        });
    }
}