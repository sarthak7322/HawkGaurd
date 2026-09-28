import type { FormMetadata } from '../shared/types';

const SENSITIVE_FIELD_PATTERN = /(password|passcode|otp|one[- ]time|cvv|c\.v\.v|pin|card|account|aadhaar|pan|usn|student[\s_-]*(?:id|number)|registration[\s_-]*number|date[\s_-]*of[\s_-]*birth|\bdob\b|cc-(?:number|exp(?:-month|-year)?|csc))/i;
const DESCRIBED_FIELD_PATTERN = /(password|passcode|otp|one[- ]time|cvv|c\.v\.v|pin|card|account|aadhaar|pan|usn|student[\s_-]*(?:id|number)|registration[\s_-]*number|date[\s_-]*of[\s_-]*birth|\bdob\b|email|username|cc-(?:number|exp(?:-month|-year)?|csc))/i;

export function boundedElements(
  root: Node,
  selector: string,
  limit: number,
  isVisible?: (element: Element) => boolean,
): Element[] {
  const matches: Element[] = [];
  const walker = root.ownerDocument?.createTreeWalker(root, 1)
    || (root as Document).createTreeWalker?.(root, 1);
  if (!walker) return matches;
  let element = walker.nextNode() as Element | null;
  let visited = 0;
  while (element && matches.length < limit && visited < 10000) {
    visited++;
    if (element.matches(selector) && (!isVisible || isVisible(element))) matches.push(element);
    element = walker.nextNode() as Element | null;
  }
  return matches;
}

function safePageUrl(raw: string, pageUrl: string): string {
  if (raw.length > 2048 || pageUrl.length > 2048) return '';
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
  return boundedElements(doc, 'a[href]', 30, isVisible)
    .map((element) => {
      const href = safePageUrl(element.getAttribute('href') || '', pageUrl);
      const label = extractStaticPageText(element, isVisible, 200)
        || element.getAttribute('aria-label')?.slice(0, 200)
        || element.getAttribute('title')?.slice(0, 200)
        || '';
      return href ? { href, label } : null;
    })
    .filter((link): link is { href: string; label: string } => link !== null);
}

export function extractStaticPageText(
  root: Element,
  isVisible: (element: Element) => boolean,
  limit = 12000,
  maxVisitedNodes = 4000,
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
  while (pending.length && capturedNodes < 600 && capturedLength < limit && visitedNodes < maxVisitedNodes) {
    const node = pending.pop()!;
    visitedNodes++;
    if (node.nodeType === 3) {
      const parent = node.parentElement;
      const remaining = limit - capturedLength;
      const part = (node.nodeValue || '').slice(0, remaining + 256).trim();
      if (!parent || !isVisible(parent) || !part) continue;
      const unit = parent.closest(blockSelector) || parent;
      if (currentUnit && unit !== currentUnit) flushTextUnit();
      currentUnit = unit;
      currentUnitParts.push(part);
      currentUnitParts[currentUnitParts.length - 1] = part.slice(0, remaining);
      capturedLength += Math.min(part.length, remaining);
      capturedNodes++;
      continue;
    }
    if (node.nodeType === 1) {
      const element = node as Element;
      if (element.matches('input, textarea, select, option, [contenteditable]:not([contenteditable="false"])')
        || !isVisible(element)) continue;
    }
    const childLimit = Math.max(0, 4000 - visitedNodes - pending.length);
    for (let index = Math.min(node.childNodes.length, childLimit) - 1; index >= 0; index--) {
      const child = node.childNodes.item(index);
      if (child) pending.push(child);
    }
  }
  flushTextUnit();
  return textUnits.join('\n');
}

export function extractFormMetadata(
  doc: Document,
  pageUrl: string,
  isVisible: (element: Element) => boolean,
): { forms: FormMetadata[]; credentialForm: boolean } {
  const staticTextCache = new WeakMap<Element, Map<number, string>>();
  const staticText = (container: Element, limit = 600): string => {
    let byLimit = staticTextCache.get(container);
    if (!byLimit) {
      byLimit = new Map<number, string>();
      staticTextCache.set(container, byLimit);
    }
    const cached = byLimit.get(limit);
    if (cached !== undefined) return cached;
    const text = extractStaticPageText(container, isVisible, limit, 300).replace(/\s+/g, ' ').trim();
    byLimit.set(limit, text);
    return text;
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
      if (indexedIds > 2000 || id.length > 256) {
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
      if (indexedLabels > 200 || labelId.length > 256) {
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
    if (!id || id.length > 256 || !idIndexComplete || !labelIndexComplete) return labels;
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
    const metadata = (name: string) => (element.getAttribute(name) || '').slice(0, 180);
    return [
      type,
      metadata('autocomplete'),
      metadata('placeholder'),
      metadata('aria-label'),
      metadata('name'),
      (id || '').slice(0, 180),
      ...labels.map((label) => staticText(label, 180)),
    ].join(' ').replace(/\s+/g, ' ').trim();
  };

  const fieldContext = (
    field: Element,
    form: Element,
    sensitiveFields: Element[],
    submitButtons: Element[],
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
      && boundedElements(formParent, 'form', 2).length === 1
      && formParent.children.length <= 20
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

    const soleSubmitAction = sensitiveFields.length === 1 && submitButtons.length === 1
      ? (submitButtons[0].tagName === 'INPUT'
        ? (submitButtons[0].getAttribute('value') || submitButtons[0].getAttribute('aria-label') || '').slice(0, 180)
        : (staticText(submitButtons[0], 180) || submitButtons[0].getAttribute('aria-label') || '').slice(0, 180))
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
    const visibleFields = boundedElements(form, 'input, textarea, select', 100, isVisible);
    const sensitiveFields = visibleFields
      .filter((element) => SENSITIVE_FIELD_PATTERN.test(fieldDescriptor(element, form)));
    const submitButtons = boundedElements(form, 'button, input[type="submit"], [role="button"]', 12, isVisible);
    const sensitiveContexts = sensitiveFields.slice(0, 12)
      .map((field) => fieldContext(field, form, sensitiveFields, submitButtons));
    const firstContext = sensitiveContexts[0];
    return {
      text: firstContext?.identityText || staticText(form),
      scope: firstContext?.contextScope || 'form',
      identityText: firstContext?.identityText || '',
      sensitiveContexts,
    };
  };

  const forms: FormMetadata[] = boundedElements(doc, 'form', 30)
    .filter(isVisible)
    .slice(0, 12)
    .map((form) => {
      const fields = boundedElements(form, 'input, textarea, select', 100, isVisible)
        .map((element) => fieldDescriptor(element, form))
        .filter((descriptor) => DESCRIBED_FIELD_PATTERN.test(descriptor))
        .map((descriptor) => descriptor.slice(0, 180))
        .slice(0, 12);
      const buttonText = boundedElements(form, 'button, input[type="submit"], [role="button"]', 12, isVisible)
        .map((button) => button.tagName === 'INPUT'
          ? (button.getAttribute('value') || button.getAttribute('aria-label') || '').slice(0, 240)
          : (staticText(button, 240) || button.getAttribute('aria-label') || '').slice(0, 240))
        .join(' ').replace(/\s+/g, ' ').trim().slice(0, 240);
      const labelText = boundedElements(form, 'label', 20, isVisible)
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

  const standaloneSensitiveFields = boundedElements(doc, 'input, textarea, select', 100)
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
