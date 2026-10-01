"use strict";
// Locates the prebuilt `provio` binary shipped in the platform package that npm
// installed for this machine (an optionalDependency filtered by os/cpu).

const { existsSync } = require("node:fs");
const { dirname, join } = require("node:path");

const PLATFORMS = {
  "darwin-arm64": "provio-cli-darwin-arm64",
  "darwin-x64": "provio-cli-darwin-x64",
  "linux-arm64": "provio-cli-linux-arm64",
  "linux-x64": "provio-cli-linux-x64",
  "win32-x64": "provio-cli-windows-x64",
};

function platformPackage(platform = process.platform, arch = process.arch) {
  return PLATFORMS[`${platform}-${arch}`];
}

/** Absolute path of the bundled provio binary. Throws if none fits this machine. */
function binaryPath() {
  const key = `${process.platform}-${process.arch}`;
  const pkg = platformPackage();
  if (pkg === undefined) {
    throw new Error(
      `provio has no prebuilt binary for ${key}; supported: ${Object.keys(PLATFORMS).join(", ")}. ` +
        "Build from source: cargo install --git https://github.com/writ-agent/provio provio-cli",
    );
  }
  let dir;
  try {
    dir = dirname(require.resolve(`${pkg}/package.json`));
  } catch {
    throw new Error(
      `${pkg} is not installed. It is an optional dependency of provio; ` +
        "reinstall without --omit=optional / --no-optional.",
    );
  }
  const bin = join(dir, "bin", process.platform === "win32" ? "provio.exe" : "provio");
  if (!existsSync(bin)) throw new Error(`${pkg} is installed but has no binary at ${bin}`);
  return bin;
}

module.exports = { binaryPath, platformPackage, PLATFORMS };
