/** Host-supplied policy; never populated from document or notebook configuration. */
export interface SecurityPolicy {
  /**
   * Additional schemes permitted only on HTML anchor hrefs, without a colon.
   * Names are case-insensitive. Invalid or reserved names throw TypeError.
   * Hosts must separately authorize the final URI before opening it.
   */
  readonly additionalLinkSchemes?: readonly string[];
}

const RESERVED_SCHEMES = new Set([
  'javascript',
  'vbscript',
  'data',
  'command',
  'blob',
  'filesystem',
  'file',
]);

/** Validate and snapshot a policy so caller mutations cannot change it. */
export function normalizeSecurityPolicy(
  policy: SecurityPolicy = {},
): SecurityPolicy {
  const schemes = policy.additionalLinkSchemes ?? [];
  if (!Array.isArray(schemes)) {
    throw new TypeError('additionalLinkSchemes must be an array');
  }
  const normalized = schemes.map((scheme: string) => {
    if (
      typeof scheme !== 'string' ||
      scheme !== scheme.trim() ||
      !/^[a-z][a-z0-9+.-]*$/i.test(scheme) ||
      RESERVED_SCHEMES.has(scheme.toLowerCase())
    ) {
      throw new TypeError('Invalid or reserved additional link scheme');
    }
    return scheme.toLowerCase();
  });
  return Object.freeze({
    additionalLinkSchemes: Object.freeze([...new Set(normalized)]),
  });
}

/** Match only a literal scheme; URI decoding belongs to the host opener. */
export function isAdditionalLinkUrl(
  value: string,
  schemes: readonly string[],
): boolean {
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(value)?.[1];
  return !!scheme && schemes.includes(scheme.toLowerCase());
}
