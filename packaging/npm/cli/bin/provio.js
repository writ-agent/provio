#!/usr/bin/env node
"use strict";
// `provio` on the npm PATH: run the bundled binary with the caller's terminal,
// forward termination signals, and exit with the binary's status.

const { spawn } = require("node:child_process");
const { binaryPath } = require("../index.js");

let bin;
try {
  bin = binaryPath();
} catch (err) {
  process.stderr.write(`provio: ${err.message}\n`);
  process.exit(1);
}

const child = spawn(bin, process.argv.slice(2), { stdio: "inherit", windowsHide: false });
for (const sig of ["SIGTERM", "SIGHUP"]) {
  process.on(sig, () => child.kill(sig));
}
// Ctrl-C reaches the child through the shared terminal; don't die before it.
process.on("SIGINT", () => {});
child.on("error", (err) => {
  process.stderr.write(`provio: failed to start ${bin}: ${err.message}\n`);
  process.exit(1);
});
child.on("exit", (code, signal) => {
  if (signal) {
    process.removeAllListeners(signal);
    process.kill(process.pid, signal);
  } else {
    process.exit(code ?? 1);
  }
});
