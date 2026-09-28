import type { PageAnalysisContext } from './types';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringList(value: unknown, maxItems: number, maxLength: number): value is string[] {
  return Array.isArray(value)
    && value.length <= maxItems
    && value.every((item) => typeof item === 'string' && item.length <= maxLength);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function isHttpUrl(value: unknown, maxLength: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) return false;
  try {
    return ['http:', 'https:'].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

function isFormMetadata(value: unknown): boolean {
  if (!isRecord(value)
    || !hasOnlyKeys(value, ['fields', 'action', 'method', 'buttonText', 'labelText', 'contextText', 'contextScope', 'identityText', 'sensitiveContexts'])
    || !isStringList(value.fields, 12, 180)
    || typeof value.action !== 'string' || value.action.length > 2048
    || typeof value.method !== 'string' || value.method.length > 16
    || typeof value.buttonText !== 'string' || value.buttonText.length > 240
    || typeof value.labelText !== 'string' || value.labelText.length > 400) return false;
  if (value.contextText !== undefined
    && (typeof value.contextText !== 'string' || value.contextText.length > 800)) return false;
  if (value.contextScope !== undefined
    && !['fieldset', 'form', 'local', 'group', 'section', 'article', 'none'].includes(String(value.contextScope))) return false;
  if (value.identityText !== undefined
    && (typeof value.identityText !== 'string' || value.identityText.length > 800)) return false;
  if (value.sensitiveContexts !== undefined) {
    if (!Array.isArray(value.sensitiveContexts) || value.sensitiveContexts.length > 12) return false;
    if (!value.sensitiveContexts.every((context) => isRecord(context)
      && hasOnlyKeys(context, ['field', 'identityText', 'contextScope'])
      && typeof context.field === 'string' && context.field.length <= 180
      && typeof context.identityText === 'string' && context.identityText.length <= 800
      && ['fieldset', 'form', 'local', 'group'].includes(String(context.contextScope)))) return false;
  }
  return true;
}

function isPageAnalysisContext(value: unknown): value is PageAnalysisContext {
  if (!isRecord(value)) return false;
  if (!hasOnlyKeys(value, ['referenceContent', 'credentialForm', 'links', 'linkMetadata', 'forms'])) return false;
  if (value.referenceContent !== undefined && typeof value.referenceContent !== 'boolean') return false;
  if (value.credentialForm !== undefined && typeof value.credentialForm !== 'boolean') return false;
  if (value.links !== undefined) {
    if (!isStringList(value.links, 30, 2048) || !value.links.every((url) => isHttpUrl(url, 2048))) return false;
  }
  if (value.linkMetadata !== undefined) {
    if (!Array.isArray(value.linkMetadata) || value.linkMetadata.length > 30) return false;
    if (!value.linkMetadata.every((link) => isRecord(link)
      && hasOnlyKeys(link, ['href', 'label'])
      && isHttpUrl(link.href, 2048)
      && typeof link.label === 'string' && link.label.length <= 200)) return false;
  }
  if (value.forms !== undefined
    && (!Array.isArray(value.forms) || value.forms.length > 12 || !value.forms.every(isFormMetadata))) return false;
  return true;
}

export function isPageAnalysisPayload(
  value: unknown,
): value is { url: string; text: string; context?: PageAnalysisContext } {
  if (!isRecord(value)
    || !hasOnlyKeys(value, ['url', 'text', 'context'])
    || !isHttpUrl(value.url, 2048)
    || typeof value.text !== 'string' || value.text.length > 12000) return false;
  return value.context === undefined || isPageAnalysisContext(value.context);
}

export function isAnalysisTextPayload(value: unknown): value is { text: string } {
  return isRecord(value)
    && hasOnlyKeys(value, ['text'])
    && typeof value.text === 'string'
    && value.text.length <= 12000;
}
