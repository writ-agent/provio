// Wrap any tool function (or a record of { description, parameters, execute } tools).
import { ProvioBlockedError, ProvioClient, guard, guardTools } from "provio-sdk";

async function main(): Promise<void> {
  const provio = new ProvioClient({ policy: "provio.yaml", caller: { agent: "my-agent", agent_version: "1.0" } });
  try {
    const runQuery = guard(async (input: { query: string }) => `rows for ${input.query}`, {
      client: provio,
      tool: "postgres.query",
    });
    console.log(await runQuery({ query: "select email from users" })); // redacted if a redact rule matches

    const tools = guardTools(
      {
        weather: {
          description: "Get the weather for a city",
          parameters: { type: "object", properties: { city: { type: "string" } } },
          execute: async ({ city }: { city: string }) => `sunny in ${city}`,
        },
      },
      { client: provio, toolName: () => "http" },
    );
    console.log(await tools.weather.execute({ city: "Oslo" }));
  } catch (err) {
    if (err instanceof ProvioBlockedError) console.error(err.message); // names rule_id and provio.yaml:LINE
    else throw err;
  } finally {
    await provio.close();
  }
}

void main();
