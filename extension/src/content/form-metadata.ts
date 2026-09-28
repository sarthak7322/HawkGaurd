import type { FormMetadata } from '../shared/types';

const SENSITIVE_FIELD_PATTERN = /(password|passcode|otp|one[- ]time|cvv|c\.v\.v|pin|card|account|aadhaar|pan|cc-(?:number|exp(?:-month|-year)?|csc))/i;
const DESCRIBED_FIELD_PATTERN = /(password|passcode|otp|one[- ]time|cvv|c\.v\.v|pin|card|account|aadhaar|pan|email|username|cc-(?:number|exp(?:-month|-year)?|csc))/i;

function safePageUrl(raw: string, pageUrl: string): string {
  try {
    const parsed = new URL(raw, pageUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) return '';
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return '';
  }
}

export function extractLinkMetadata(
  doc: Document,
  pageUrl: string,
  isVisible: (element: Element) => boolean,
): { href: string; label: string }[] {
  return Array.from(doc.querySelectorAll('a[href]'))
    .filter(isVisible)
    .slice(0, 30)
    .map((element) => {
      const href = safePageUrl(element.getAttribute('href') || '', pageUrl);
      const label = extractStaticPageText(element, isVisible, 200)
        || element.getAttribute('aria-label')
        || element.getAttribute('title')
        || '';
      return href ? { href, label } : null;
    })
    .filter((link): link is { href: string; label: string } => link !== null);
}

export function extractStaticPageText(
  root: Element,
  isVisible: (element: Element) => boolean,
  limit = 12000,
): string {
  const textUnits: string[] = [];
  let currentUnit: Element | null = null;
  let currentUnitParts: string[] = [];
  const flushTextUnit = () => {
    if (currentUnitParts.length) textUnits.push(currentUnitParts.join(' '));
    currentUnitParts = [];
  };
  let capturedLength = 0;
  let capturedNodes = 0;
  let visitedNodes = 0;
  const blockSelector = 'p, li, h1, h2, h3, h4, h5, h6, blockquote, label, button, td, th, figcaption, summary, dt, dd, legend, div';
  const pending: Node[] = [root];
  while (pending.length && capturedNodes < 600 && capturedLength < limit && visitedNodes < 4000) {
    const node = pending.pop()!;
    visitedNodes++;
    if (node.nodeType === 3) {
      const parent = node.parentElement;
      const part = (node.textContent || '').trim();
      if (!parent || !isVisible(parent) || !part) continue;
      const unit = parent.closest(blockSelector) || parent;
      if (currentUnit && unit !== currentUnit) flushTextUnit();
      currentUnit = unit;
      currentUnitParts.push(part);
      const remaining = limit - capturedLength;
      currentUnitParts[currentUnitParts.length - 1] = part.slice(0, remaining);
      capturedLength += Math.min(part.length, remaining);
      capturedNodes++;
      continue;
    }
    if (node.nodeType === 1 && !isVisible(node as Element)) continue;
    const children = Array.from(node.childNodes);
    const childLimit = Math.max(0, 4000 - visitedNodes - pending.length);
    for (let index = Math.min(children.length, childLimit) - 1; index >= 0; index--) pending.push(children[index]);
  }
  flushTextUnit();
  return textUnits.join('\n');
}

export function extractFormMetadata(
  doc: Document,
  pageUrl: string,
  isVisible: (element: Element) => boolean,
): { forms: FormMetadata[]; credentialForm: boolean } {
  const staticText = (container: Element, limit = 600): string => {
    return extractStaticPageText(container, isVisible, limit).replace(/\s+/g, ' ').trim();
  };

  const elementsById = new Map<string, Element[]>();
  const labelsByFor = new Map<string, Element[]>();
  let idIndexComplete = true;
  let labelIndexComplete = true;
  const idWalker = doc.createTreeWalker(doc, 1);
  let idElement = idWalker.nextNode() as Element | null;
  let visitedElements = 0;
  let indexedIds = 0;
  let indexedLabels = 0;
  while (idElement && visitedElements < 10000) {
    visitedElements++;
    const id = idElement.getAttribute('id');
    if (id) {
      indexedIds++;
      if (indexedIds > 2000) {
        idIndexComplete = false;
      } else {
        const matches = elementsById.get(id) || [];
        if (matches.length < 2) matches.push(idElement);
        elementsById.set(id, matches);
      }
    }

    if (idElement.tagName === 'LABEL' && idElement.hasAttribute('for')) {
      indexedLabels++;
      const labelId = idElement.getAttribute('for') || '';
      if (indexedLabels > 200) {
        labelIndexComplete = false;
      } else if (labelId) {
        const labels = labelsByFor.get(labelId) || [];
        if (labels.length < 2) labels.push(idElement);
        labelsByFor.set(labelId, labels);
      }
    }
    idElement = idWalker.nextNode() as Element | null;
  }
  if (idElement) {
    idIndexComplete = false;
    labelIndexComplete = false;
  }

  const associatedLabels = (element: Element, form: Element): Element[] => {
    const labels: Element[] = [];
    const wrappingLabel = element.closest('label');
    if (wrappingLabel && form.contains(wrappingLabel)) labels.push(wrappingLabel);

    const id = element.getAttribute('id');
    if (!id || !idIndexComplete || !labelIndexComplete) return labels;
    const idMatches = elementsById.get(id) || [];
    const explicitLabels = labelsByFor.get(id) || [];
    if (idMatches.length !== 1 || idMatches[0] !== element || explicitLabels.length !== 1) return labels;
    const label = explicitLabels[0];
    if (form.contains(label) && !labels.includes(label)) labels.push(label);
    return labels;
  };

  const fieldDescriptor = (element: Element, form: Element): string => {
    const type = element.tagName === 'INPUT' ? (element.getAttribute('type') || 'text').toLowerCase() : '';
    if (type === 'hidden') return '';
    const id = element.getAttribute('id');
    const labels = associatedLabels(element, form);
    return [
      type,
      element.getAttribute('autocomplete') || '',
      element.getAttribute('placeholder') || '',
      element.getAttribute('aria-label') || '',
      element.getAttribute('name') || '',
      id || '',
      ...labels.map((label) => staticText(label, 180)),
    ].join(' ').replace(/\s+/g, ' ').trim();
  };

  const fieldContext = (
    field: Element,
    form: Element,
    sensitiveFields: Element[],
  ): NonNullable<FormMetadata['sensitiveContexts']>[number] => {
    const fieldText = fieldDescriptor(field, form).slice(0, 180);
    const fieldset = field.closest('fieldset');
    if (fieldset && form.contains(fieldset)) {
      return {
        field: fieldText,
        identityText: `${staticText(fieldset)}\n${fieldText}`.slice(0, 800),
        contextScope: 'fieldset',
      };
    }

    let localContainer: Element | null = field.parentElement;
    while (localContainer && localContainer !== form) {
      if (localContainer.tagName === 'DIV'
        && !sensitiveFields.some((other) => other !== field && localContainer!.contains(other))) {
        return {
          field: fieldText,
          identityText: `${staticText(localContainer)}\n${fieldText}`.slice(0, 800),
          contextScope: 'local',
        };
      }
      localContainer = localContainer.parentElement;
    }

    const formParent = form.parentElement;
    const localChildren = new Set(['H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'LABEL', 'LEGEND', 'BUTTON']);
    if (sensitiveFields.length === 1
      && formParent?.tagName === 'DIV'
      && formParent.querySelectorAll('form').length === 1
      && Array.from(formParent.children).every((child) => child === form || localChildren.has(child.tagName))
      && !formParent.matches('section, article, [role="group"]')) {
      return {
        field: fieldText,
        identityText: `${staticText(formParent)}\n${fieldText}`.slice(0, 800),
        contextScope: 'local',
      };
    }

    const group = field.closest('[role="group"]');
    if (group && form.contains(group)) {
      return {
        field: fieldText,
        identityText: `${staticText(group)}\n${fieldText}`.slice(0, 800),
        contextScope: 'group',
      };
    }

    const submitButtons = Array.from(form.querySelectorAll('button, input[type="submit"], [role="button"]'))
      .filter(isVisible);
    const soleSubmitAction = sensitiveFields.length === 1 && submitButtons.length === 1
      ? (submitButtons[0].tagName === 'INPUT'
        ? submitButtons[0].getAttribute('value') || submitButtons[0].getAttribute('aria-label') || ''
        : staticText(submitButtons[0], 180) || submitButtons[0].getAttribute('aria-label') || '')
      : '';
    const directLabels = associatedLabels(field, form).map((label) => staticText(label, 180)).join('\n');
    return {
      field: fieldText,
      identityText: [fieldText, directLabels, soleSubmitAction].filter(Boolean).join('\n').slice(0, 800),
      contextScope: 'form',
    };
  };

  const formContext = (form: Element): {
    text: string;
    scope: NonNullable<FormMetadata['contextScope']>;
    identityText: string;
    sensitiveContexts: NonNullable<FormMetadata['sensitiveContexts']>;
  } => {
    const visibleFields = Array.from(form.querySelectorAll('input, textarea, select')).slice(0, 100)
      .filter(isVisible);
    const sensitiveFields = visibleFields
      .filter((element) => SENSITIVE_FIELD_PATTERN.test(fieldDescriptor(element, form)));
    const sensitiveContexts = sensitiveFields.slice(0, 12)
      .map((field) => fieldContext(field, form, sensitiveFields));
    const firstContext = sensitiveContexts[0];
    return {
      text: firstContext?.identityText || staticText(form),
      scope: firstContext?.contextScope || 'form',
      identityText: firstContext?.identityText || '',
      sensitiveContexts,
    };
  };

  const forms: FormMetadata[] = Array.from(doc.querySelectorAll('form'))
    .slice(0, 30)
    .filter(isVisible)
    .slice(0, 12)
    .map((form) => {
      const fields = Array.from(form.querySelectorAll('input, textarea, select')).slice(0, 100)
        .filter(isVisible)
        .map((element) => fieldDescriptor(element, form))
        .filter((descriptor) => DESCRIBED_FIELD_PATTERN.test(descriptor))
        .map((descriptor) => descriptor.slice(0, 180))
        .slice(0, 12);
      const buttonText = Array.from(form.querySelectorAll('button, input[type="submit"], [role="button"]')).slice(0, 12)
        .filter(isVisible)
        .map((button) => button.tagName === 'INPUT'
          ? button.getAttribute('value') || button.getAttribute('aria-label') || ''
          : staticText(button, 240) || button.getAttribute('aria-label') || '')
        .join(' ').replace(/\s+/g, ' ').trim().slice(0, 240);
      const labelText = Array.from(form.querySelectorAll('label')).slice(0, 20)
        .filter(isVisible)
        .map((label) => staticText(label, 180))
        .join(' ').replace(/\s+/g, ' ').trim().slice(0, 400);
      const context = formContext(form);
      const broadContext = form.closest('section, article');
      const contextText = context.text || (broadContext ? staticText(broadContext) : '');
      const contextScope = context.text
        ? context.scope
        : (broadContext?.tagName.toLowerCase() as 'section' | 'article' | undefined) || 'none';
      return {
        fields,
        action: safePageUrl(form.getAttribute('action') || pageUrl, pageUrl),
        method: (form.getAttribute('method') || 'get').toLowerCase(),
        buttonText,
        labelText,
        contextText,
        contextScope,
        identityText: context.identityText,
        sensitiveContexts: context.sensitiveContexts,
      };
    });

  const standaloneSensitiveFields = Array.from(doc.querySelectorAll('input, textarea, select'))
    .slice(0, 100)
    .filter((element) => !element.closest('form') && isVisible(element))
    .map((element) => fieldDescriptor(element, doc.body || doc.documentElement))
    .filter((descriptor) => SENSITIVE_FIELD_PATTERN.test(descriptor))
    .map((descriptor) => descriptor.slice(0, 180))
    .slice(0, 12);
  if (standaloneSensitiveFields.length) {
    forms.push({
      fields: standaloneSensitiveFields,
      action: safePageUrl(pageUrl, pageUrl),
      method: 'get',
      buttonText: '',
      labelText: '',
      contextScope: 'none',
      sensitiveContexts: [],
    });
  }

  return {
    forms,
    credentialForm: forms.some((form) => form.fields.some((field) => SENSITIVE_FIELD_PATTERN.test(field))),
  };
}
