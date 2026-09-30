// The URL of this module, used to resolve the optional provio
// package from where the SDK is installed. The emitted file is replaced per
// output format by scripts/postbuild.mjs (import.meta.url for ESM,
// __filename for CommonJS); this source value only applies if that step
// did not run, in which case the bundled-binary lookup is skipped.
export const selfUrl: string | undefined = undefined;
