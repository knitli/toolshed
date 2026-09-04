import type { OpenApiValue } from "./types.ts";

export type OpenApiMcpErrorCode =
  | "ARTIFACT_FORMAT_UNSUPPORTED"
  | "MANIFEST_INVALID"
  | "MANIFEST_SIGNATURE_INVALID"
  | "MANIFEST_ROLLBACK_REJECTED"
  | "MANIFEST_GENERATION_CONFLICT"
  | "RECORD_NOT_ADMITTED"
  | "RECORD_DIGEST_MISMATCH"
  | "OPERATION_REF_INVALID"
  | "OPERATION_NOT_FOUND"
  | "SCHEMA_RESOLUTION_LIMIT"
  | "INPUT_INVALID"
  | "TOOL_SAFETY_MISMATCH"
  | "ACTION_CONFIRMATION_REQUIRED"
  | "ACTION_DENIED"
  | "ACTION_CONFIRMATION_EXPIRED"
  | "AUTH_PROFILE_INVALID"
  | "AUTH_REQUIRED"
  | "DESTINATION_DENIED"
  | "RESPONSE_LIMIT_EXCEEDED"
  | "PAGINATION_LIMIT_EXCEEDED"
  | "UPSTREAM_ERROR"
  | "UPSTREAM_OUTCOME_UNKNOWN";

/**
 * A stable, model-safe error. Callers must provide only pre-redacted details.
 */
export class OpenApiMcpError extends Error {
  readonly code: OpenApiMcpErrorCode;
  readonly retryable: boolean;
  readonly details: Readonly<Record<string, OpenApiValue>>;

  constructor(
    code: OpenApiMcpErrorCode,
    message = code,
    options: {
      retryable?: boolean;
      details?: Readonly<Record<string, OpenApiValue>>;
    } = {},
  ) {
    super(message);
    this.name = "OpenApiMcpError";
    this.code = code;
    this.retryable = options.retryable ?? false;
    this.details = options.details ?? {};
  }
}
