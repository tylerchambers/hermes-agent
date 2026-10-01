import type { VaultItem, VaultUpdateOriginsParams } from '@hermes/shared'

export interface OriginRuleDraft {
  origin: string
  additionalOrigins: string
  wildcardOrigins: string
}

export const EMPTY_ORIGIN_RULES: OriginRuleDraft = { origin: '', additionalOrigins: '', wildcardOrigins: '' }

type OriginPayload = Omit<VaultUpdateOriginsParams, 'id' | 'profile'>

export function exactOrigins(item: VaultItem): string[] {
  return [...new Set([...(item.origin ? [item.origin] : []), ...(item.allowed_origins ?? [])])]
}

export function originDraft(item: VaultItem): OriginRuleDraft {
  return {
    origin: item.origin ?? '',
    additionalOrigins: exactOrigins(item)
      .filter(origin => origin !== item.origin)
      .join('\n'),
    wildcardOrigins: (item.wildcard_origins ?? []).join('\n')
  }
}

function originLines(value: string): string[] {
  return value
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean)
}

function isValidOrigin(value: string): boolean {
  if (value.includes('*')) {
    return false
  }

  try {
    const url = new URL(value)

    return (url.protocol === 'https:' || url.protocol === 'http:') && !!url.hostname
  } catch {
    return false
  }
}

/** Full replacement, including empty wildcard grants so an edit can revoke them. */
export function originDraftToPayload(draft: OriginRuleDraft): OriginPayload | null {
  const origin = draft.origin.trim()
  const additionalOrigins = originLines(draft.additionalOrigins)

  if (!isValidOrigin(origin) || !additionalOrigins.every(isValidOrigin)) {
    return null
  }

  return {
    origin,
    allowed_origins: [...new Set([origin, ...additionalOrigins])],
    wildcard_origins: originLines(draft.wildcardOrigins)
  }
}

export function hasAdditionalOriginGrants(draft: OriginRuleDraft): boolean {
  return !!(draft.additionalOrigins.trim() || draft.wildcardOrigins.trim())
}
