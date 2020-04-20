"use strict";
exports.__esModule = true;
var taskRunner_1 = require("./services/taskRunner");
// Plugin entry point.
var runner = new taskRunner_1.TaskRunner();
runner.run();
