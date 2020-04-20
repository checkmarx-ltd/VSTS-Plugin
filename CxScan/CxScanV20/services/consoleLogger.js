"use strict";
exports.__esModule = true;
var taskLib = require("azure-pipelines-task-lib");
var ConsoleLogger = /** @class */ (function () {
    function ConsoleLogger() {
    }
    ConsoleLogger.prototype.info = function (message) {
        console.log(message);
    };
    ConsoleLogger.prototype.error = function (message) {
        // If we don't split the message into lines, taskLib will only highlight the first message line as an error.
        var lines = message.replace('\r\n', '\n')
            .split('\n');
        for (var _i = 0, lines_1 = lines; _i < lines_1.length; _i++) {
            var line = lines_1[_i];
            taskLib.error(line);
        }
    };
    ConsoleLogger.prototype.debug = function (message) {
        taskLib.debug(message);
    };
    ConsoleLogger.prototype.warning = function (message) {
        taskLib.warning(message);
    };
    return ConsoleLogger;
}());
exports.ConsoleLogger = ConsoleLogger;
