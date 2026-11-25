// Localize stable interface text before rendering user-supplied content.
'use strict';
const keysLocale = (() => {
  const storageKey = 'family-keys-language';
  let language = 'en';
  let messages = {};
  try {
    if (localStorage.getItem(storageKey) === 'ja') language = 'ja';
  } catch { /* Storage access is optional. */ }

  function translate(text) {
    if (!text || typeof text !== 'string') return text;
    if (Object.hasOwn(messages, text)) return messages[text];
    const rowNumber = text.match(/\bline (\d+)\b/);
    if (rowNumber) {
      const pattern = text.replace(/\bline \d+\b/, 'line %d');
      if (Object.hasOwn(messages, pattern)) return messages[pattern].replace('%d', rowNumber[1]);
    }
    return text;
  }

  async function init() {
    for (const select of document.querySelectorAll('[data-language]')) {
      select.value = language;
      select.addEventListener('change', () => {
        try {
          localStorage.setItem(storageKey, select.value);
          location.reload();
        } catch { select.value = language; }
      });
    }
    if (language === 'en') return;
    try {
      const response = await fetch('/assets/ja.json');
      if (!response.ok) return;
      messages = await response.json();
    } catch { return; }
    document.documentElement.lang = 'ja';
    document.title = translate(document.title);
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (node.parentElement.closest('script, style, textarea, [data-language]')) continue;
      node.nodeValue = node.nodeValue.replace(/^(\s*(?:[＋◇]\s*)?)(.*?)(\s*(?:↗\s*)?)$/s,
        (_value, prefix, text, suffix) => prefix + translate(text) + suffix);
    }
    for (const element of document.querySelectorAll('[aria-label], [placeholder]')) {
      for (const attribute of ['aria-label', 'placeholder']) {
        if (element.hasAttribute(attribute)) element.setAttribute(attribute, translate(element.getAttribute(attribute)));
      }
    }
  }
  return { translate, ready: init() };
})();
const t = keysLocale.translate;
