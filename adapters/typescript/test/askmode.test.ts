import * as assert from "node:assert/strict";
import { test } from "node:test";

import { ProvioClient } from "../src/client.js";
import { ProvioError } from "../src/errors.js";

test('ask "ui" is accepted and waits longer by default', () => {
  const ui = new ProvioClient({ ask: "ui" }) as unknown as { timeoutMs: number; askMode: string };
  assert.equal(ui.askMode, "ui");
  assert.equal(ui.timeoutMs, 180_000);
  const explicit = new ProvioClient({ ask: "ui", timeoutMs: 5_000 }) as unknown as { timeoutMs: number };
  assert.equal(explicit.timeoutMs, 5_000);
  const plain = new ProvioClient() as unknown as { timeoutMs: number };
  assert.equal(plain.timeoutMs, 30_000);
  assert.throws(() => new ProvioClient({ ask: "maybe" as never }), ProvioError);
});
