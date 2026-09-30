import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ProvioClient, type ProvioClientOptions } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
// Compiled tests live in build-test/test/; the fixture stays in test/fixtures/.
export const FAKE_PROVIO = resolve(here, "..", "..", "test", "fixtures", "fake-provio.mjs");

export interface FakeHarness {
  client: ProvioClient;
  logFile: string;
  /** Every JSON line the fake gateway logged (argv entries and requests). */
  log(): Array<Record<string, unknown>>;
  /** Only the requests with the given op. */
  requests(op?: string): Array<Record<string, unknown>>;
}

export function tempDir(prefix = "provio-sdk-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

/**
 * A client wired to the fake gateway through the explicit `command`/`args`
 * override (`node fake-provio.mjs ...`), which also works on Windows.
 */
export function fakeClient(options: ProvioClientOptions = {}, extraEnv: NodeJS.ProcessEnv = {}): FakeHarness {
  const logFile = join(tempDir(), "fake.log");
  const client = new ProvioClient({
    command: process.execPath,
    args: [FAKE_PROVIO],
    env: { ...process.env, FAKE_PROVIO_LOG: logFile, ...extraEnv },
    ...options,
  });
  const log = (): Array<Record<string, unknown>> =>
    existsSync(logFile)
      ? readFileSync(logFile, "utf8")
          .split("\n")
          .filter((l) => l.trim() !== "")
          .map((l) => JSON.parse(l) as Record<string, unknown>)
      : [];
  return {
    client,
    logFile,
    log,
    requests: (op?: string) => log().filter((e) => "op" in e && (op === undefined || e.op === op)),
  };
}

export function call(tool: string, args: Record<string, unknown> = {}) {
  return { session_id: "s-1", tool, args };
}
