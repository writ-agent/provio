// Run a Claude Agent SDK session with every tool call checked by provio.
// Requires `provio` on PATH (or PROVIO_BIN) and a provio.yaml in the working directory.
import { query } from "@anthropic-ai/claude-agent-sdk";

import { ProvioClient } from "provio-sdk";
import { createProvioIntegration } from "provio-sdk/claude-agent-sdk";

async function main(): Promise<void> {
  await using provio = new ProvioClient({ ask: "defer" });
  const { hooks, canUseTool } = createProvioIntegration({
    client: provio,
    // Deferred asks come here; return true only for an explicit human yes.
    approver: async ({ call, decision }) => {
      console.error(`approval needed for ${call.tool}: ${decision.reason ?? ""}`);
      return false;
    },
  });

  for await (const message of query({ prompt: "List the files in this repo", options: { hooks, canUseTool } })) {
    if (message.type === "result") console.log(message);
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
