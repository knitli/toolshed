export type Safety = "read" | "write";
export type Risk = "routine" | "high";
export type PermConfidence = "exact" | "suffix" | "prefix";

export interface OperationRecord {
  qualifiedId: string;
  api: string;
  operationId: string;
  method: string;
  path: string;
  safety: Safety;
  risk: Risk;
  operationType: string | null;
  pageable: boolean;
  deprecated: boolean;
  permissions: string[] | null;
  permConfidence: PermConfidence | null;
  privilegeLevel: number | null;
  summary: string | null;
  tags: string | null;
  paramsJson: string;
  searchText: string;
  bodyRef: string | null;
  bodySchemaJson: string | null;
  bodyMediaType: string | null;
  serverUrl: string;
}

export interface SchemaRecord {
  api: string;
  name: string;
  json: string;
}

export type {
  CanonicalMediaTypeV4,
  EncodingHeaderV4,
  MediaEncodingV4,
  OperationRecordV4,
  ParameterLocationV4,
  ParameterRecordV4,
  ParameterStyleV4,
  RequestBodyMediaV4,
  RequestBodyRecordV4,
  SchemaRecordV4,
  SchemaUseV4,
} from "./runtime/types.ts";
