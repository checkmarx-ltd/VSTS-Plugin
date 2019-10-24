export class TaskSkippedError extends Error {
    constructor(message: string) {
        super(message);
    }
}