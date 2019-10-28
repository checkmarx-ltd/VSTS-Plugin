import promisePoller from "promise-poller";

export class Waiter {
    public static readonly PollingSettings = {
        masterTimeoutMinutes: 20,
        intervalSeconds: 10
    };

    waitForTaskToFinish<T>(taskFn: () => T | PromiseLike<T>, progressCallback: (error: any) => void): Promise<T> {
        return promisePoller({
            taskFn,
            progressCallback: (retriesRemaining, error) => progressCallback(error),
            interval: Waiter.PollingSettings.intervalSeconds * 1000,
            masterTimeout: Waiter.PollingSettings.masterTimeoutMinutes * 60 * 1000,
            retries: Number.MAX_SAFE_INTEGER
        });
    }
}