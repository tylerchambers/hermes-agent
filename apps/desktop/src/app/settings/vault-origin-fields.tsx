import { Checkbox } from '@/components/ui/checkbox'
import { Field, FieldHint } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { useI18n } from '@/i18n'

import type { OriginRuleDraft } from './vault-origin-rules'

interface OriginRuleFieldsProps extends OriginRuleDraft {
  onChange: (field: keyof OriginRuleDraft, value: string) => void
  supportsOriginRules: boolean
  disabled?: boolean
  idPrefix?: string
}

export function OriginRuleFields({
  origin,
  additionalOrigins,
  wildcardOrigins,
  onChange,
  supportsOriginRules,
  disabled,
  idPrefix = 'vault'
}: OriginRuleFieldsProps) {
  const { t } = useI18n()
  const v = t.settings.vault

  return (
    <>
      <Field htmlFor={`${idPrefix}-origin`} label={v.originField}>
        <Input
          disabled={disabled}
          id={`${idPrefix}-origin`}
          inputMode="url"
          onChange={e => onChange('origin', e.target.value)}
          placeholder={v.originPlaceholder}
          value={origin}
        />
      </Field>
      {supportsOriginRules && (
        <>
          <Field
            htmlFor={`${idPrefix}-additional-origins`}
            label={v.additionalOriginsField}
            optional
            optionalLabel={v.optional}
          >
            <Textarea
              disabled={disabled}
              id={`${idPrefix}-additional-origins`}
              onChange={e => onChange('additionalOrigins', e.target.value)}
              rows={2}
              value={additionalOrigins}
            />
            <FieldHint>{v.additionalOriginsHint}</FieldHint>
          </Field>
          <Field
            htmlFor={`${idPrefix}-wildcard-origins`}
            label={v.wildcardOriginsField}
            optional
            optionalLabel={v.optional}
          >
            <Textarea
              disabled={disabled}
              id={`${idPrefix}-wildcard-origins`}
              onChange={e => onChange('wildcardOrigins', e.target.value)}
              rows={2}
              value={wildcardOrigins}
            />
            <FieldHint>{v.wildcardOriginsHint}</FieldHint>
          </Field>
        </>
      )}
    </>
  )
}

interface WildcardConsentProps {
  acknowledged: boolean
  onChange: (value: boolean) => void
  disabled?: boolean
}

export function WildcardConsent({ acknowledged, onChange, disabled }: WildcardConsentProps) {
  const { t } = useI18n()
  const v = t.settings.vault

  return (
    <div className="grid gap-2">
      <FieldHint>{v.wildcardWarning}</FieldHint>
      <label className="flex items-start gap-2 text-xs text-foreground">
        <Checkbox checked={acknowledged} disabled={disabled} onCheckedChange={value => onChange(value === true)} />
        <span>{v.wildcardAcknowledgement}</span>
      </label>
    </div>
  )
}
