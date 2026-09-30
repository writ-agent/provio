import * as assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import { bundledProvio, locateProvio } from "../src/locate.js";

function fakeInstall(binaryExists: boolean): { root: string; from: string; bin: string } {
  const root = mkdtempSync(join(tmpdir(), "provio-bundled-"));
  const cli = join(root, "node_modules", "provio");
  mkdirSync(cli, { recursive: true });
  const bin = join(root, process.platform === "win32" ? "provio.exe" : "provio");
  if (binaryExists) writeFileSync(bin, "");
  writeFileSync(join(cli, "package.json"), JSON.stringify({ name: "provio", main: "index.js" }));
  writeFileSync(join(cli, "index.js"), `exports.binaryPath = () => ${JSON.stringify(bin)};\n`);
  return { root, from: pathToFileURL(join(root, "sdk.js")).href, bin };
}

test("bundledProvio finds the binary from an installed provio", () => {
  const f = fakeInstall(true);
  try {
    assert.equal(bundledProvio(f.from), f.bin);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("bundledProvio is undefined when the binary is missing or cli is absent", () => {
  const f = fakeInstall(false);
  const empty = mkdtempSync(join(tmpdir(), "provio-nocli-"));
  try {
    assert.equal(bundledProvio(f.from), undefined);
    assert.equal(bundledProvio(pathToFileURL(join(empty, "sdk.js")).href), undefined);
    assert.equal(bundledProvio(undefined), undefined);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
    rmSync(empty, { recursive: true, force: true });
  }
});

test("PROVIO_BIN still wins over any bundled binary", () => {
  const f = fakeInstall(true);
  try {
    const launch = locateProvio(undefined, { PROVIO_BIN: f.bin, PATH: "" });
    assert.equal(launch.command, f.bin);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});
