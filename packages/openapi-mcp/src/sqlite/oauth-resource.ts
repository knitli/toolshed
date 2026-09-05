/** Fixed OAuth audience metadata; this URI is never a credential destination. */
export function isOAuthResource(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2048 ||
    /[\s#]/u.test(value) ||
    [...value].some(
      (character) =>
        character.charCodeAt(0) < 0x20 || character.charCodeAt(0) === 0x7f,
    )
  )
    return false;
  try {
    return new URL(value).protocol.length > 1;
  } catch {
    return false;
  }
}
