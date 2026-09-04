export type { CompileOptions, CompileResult } from "./compile.ts";
export { compile } from "./compile.ts";
export { resolveLocalPointer } from "./operations.ts";
export type { CompileReleaseOptions } from "./release/compile-release.ts";
export { compileRelease } from "./release/compile-release.ts";
export type { CompilerLimits } from "./release/load-v4.ts";
export {
  DEFAULT_COMPILER_LIMITS,
  loadSpecV4,
  parseDocumentBytesV4,
  parseSpecBytesV4,
  redactSourcePath,
} from "./release/load-v4.ts";
export type {
  CompiledRelease,
  CompiledReleasePaths,
} from "./release/publish.ts";
export {
  discardCompiledRelease,
  publishRelease,
} from "./release/publish.ts";
export type {
  ReferenceMapEntryV1,
  ReferenceMapV1,
  ReferenceResolver,
  ResolvedReferenceV1,
} from "./release/reference-map.ts";
export {
  normalizeGraphUri,
  normalizeHttpsUri,
  referenceGraphDigest,
  sourceUriFromLabel,
} from "./release/reference-map.ts";
export {
  deriveReleasePublicKeyV4,
  generateKeypair,
  signArtifact,
  signReleaseManifestV4,
  verifyArtifact,
} from "./sign.ts";
export type {
  OperationRecord,
  PermConfidence,
  Risk,
  Safety,
  SchemaRecord,
} from "./types.ts";
