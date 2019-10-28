import parseMilliseconds = require("parse-ms");

export class Stopwatch {
    private lastOperationStart: Date = new Date(0);

    start() {
        this.lastOperationStart = new Date();
    }

    getElapsed(): string {
        let duration = parseMilliseconds(Date.now() - this.lastOperationStart.getTime());
        return `${Stopwatch.pad(duration.hours)}:${Stopwatch.pad(duration.minutes)}:${Stopwatch.pad(duration.seconds)}`;
    }

    private static pad(input: number) {
        const padding = input < 10 ? '0' : '';
        return padding + input;
    }
}