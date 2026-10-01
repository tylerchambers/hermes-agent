import type { VaultAddResult, VaultItem, VaultUpdateOriginsParams } from '@hermes/shared'
import { useMutation } from '@tanstack/react-query'
import { useState } from 'react'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@/components/ui/dialog'
import { useI18n } from '@/i18n'
import { triggerHaptic } from '@/lib/haptics'
import { notify } from '@/store/notifications'

import { OriginRuleFields, WildcardConsent } from './vault-origin-fields'
import { originDraft, originDraftToPayload } from './vault-origin-rules'

interface VaultOriginEditDialogProps {
  item: VaultItem
  supportsOriginRules: boolean
  requestGateway: <T>(method: string, params: Record<string, unknown>) => Promise<T>
  onClose: () => void
  onSaved: () => void
}

/** Mounted for one selected item; closing or changing owners destroys its draft and consent. */
export function VaultOriginEditDialog({
  item,
  supportsOriginRules,
  requestGateway,
  onClose,
  onSaved
}: VaultOriginEditDialogProps) {
  const { t } = useI18n()
  const v = t.settings.vault
  const [rules, setRules] = useState(() => originDraft(item))
  const [error, setError] = useState<null | string>(null)
  const [wildcardAcknowledged, setWildcardAcknowledged] = useState(false)

  const mutation = useMutation({
    mutationFn: (payload: VaultUpdateOriginsParams) =>
      requestGateway<VaultAddResult>('vault.update_origins', { ...payload }),
    onSuccess: () => {
      triggerHaptic('success')
      notify({ kind: 'info', message: v.originsSaved })
      onSaved()
    },
    onError: err => setError(err instanceof Error ? err.message : String(err))
  })

  const submit = () => {
    setError(null)

    if (!supportsOriginRules) {
      return
    }

    const payload = originDraftToPayload(rules)

    if (!payload) {
      setError(v.originInvalid)

      return
    }

    if (payload.wildcard_origins.length > 0 && !wildcardAcknowledged) {
      setError(v.wildcardAcknowledgement)

      return
    }

    // Per-call callbacks do not run after this selected item's dialog unmounts.
    mutation.mutate({ id: item.id, ...payload }, { onSuccess: onClose })
  }

  return (
    <Dialog onOpenChange={open => !open && onClose()} open>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{v.editOriginsTitle}</DialogTitle>
          <DialogDescription>{item.label}</DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={e => {
            e.preventDefault()
            submit()
          }}
        >
          <OriginRuleFields
            {...rules}
            disabled={mutation.isPending}
            idPrefix="vault-edit"
            onChange={(field, value) => {
              setRules(draft => ({ ...draft, [field]: value }))

              if (field === 'wildcardOrigins') {
                setWildcardAcknowledged(false)
              }
            }}
            supportsOriginRules={supportsOriginRules}
          />
          {supportsOriginRules && rules.wildcardOrigins.trim() && (
            <WildcardConsent
              acknowledged={wildcardAcknowledged}
              disabled={mutation.isPending}
              onChange={setWildcardAcknowledged}
            />
          )}
          {error && <p className="text-xs text-destructive">{error}</p>}
          <DialogFooter>
            <Button onClick={onClose} size="sm" type="button" variant="ghost">
              {t.common.cancel}
            </Button>
            <Button
              disabled={
                mutation.isPending || !supportsOriginRules || (!!rules.wildcardOrigins.trim() && !wildcardAcknowledged)
              }
              size="sm"
              type="submit"
            >
              {mutation.isPending ? v.adding : t.common.save}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
