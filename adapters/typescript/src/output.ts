/** Render a tool result as the text provio hashes (and redacts). */
export function outputText(result: unknown): string | undefined {
  if (result === undefined) return undefined;
  if (typeof result === "string") return result;
  if (result instanceof Uint8Array) return Buffer.from(result).toString("utf8");
  try {
    const json = JSON.stringify(result);
    return json === undefined ? String(result) : json;
  } catch {
    return String(result);
  }
}

/**
 * Map provio's redacted text back onto the original result's shape: strings stay
 * strings; structured results are re-parsed from the redacted JSON when that
 * still parses, otherwise the redacted text itself is returned.
 */
export function fromRedacted(redacted: string, original: unknown): unknown {
  if (typeof original === "string" || original === undefined || original instanceof Uint8Array) return redacted;
  try {
    return JSON.parse(redacted) as unknown;
  } catch {
    return redacted;
  }
}

/** Replacement text when a result must be withheld (redaction could not be applied). */
export const WITHHELD_OUTPUT = "[provio: tool output withheld because redaction could not be applied]";
