/** Absolute path of the prebuilt provio binary for this machine. Throws if unavailable. */
export function binaryPath(): string;
/** The platform package name for a platform/arch pair, if one is published. */
export function platformPackage(platform?: string, arch?: string): string | undefined;
export const PLATFORMS: Readonly<Record<string, string>>;
