declare const actionDispatchPermitBrand: unique symbol;

/**
 * Engine-private proof that an exact authorized action was consumed.
 *
 * This module deliberately exposes no constructor or issuer. Runtime identity
 * is held by the authorization boundary that created the permit.
 */
export type ActionDispatchPermit = Readonly<{
  readonly [actionDispatchPermitBrand]: never;
}>;
