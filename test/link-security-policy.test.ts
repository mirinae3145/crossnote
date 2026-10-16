/** @jest-environment jsdom */

import { normalizeSecurityPolicy } from '../src/lib/security-policy';
import { createHtmlSanitizer } from '../src/webview/lib/sanitize';

describe('host link policy', () => {
  const sanitize = createHtmlSanitizer({
    additionalLinkSchemes: ['Zotero', 'obsidian'],
  });

  test('preserves approved links and keeps preview policies isolated', () => {
    const html = '<a href="zotero://select/items/ABC">paper</a>';
    expect(sanitize(html)).toBe(html);
    expect(createHtmlSanitizer()(html)).toBe('<a>paper</a>');
    expect(sanitize('<a href="OBSIDIAN://open">note</a>')).toContain(
      'href="OBSIDIAN://open"',
    );
    expect(sanitize('<a href="unknown://open">note</a>')).toBe('<a>note</a>');
  });

  test('does not extend resource, form, or SVG permissions', () => {
    const clean = sanitize(`
      <img src="zotero://image">
      <iframe src="zotero://frame" srcdoc="bad"></iframe>
      <form action="zotero://submit"><button formaction="zotero://submit">go</button></form>
      <svg><a href="zotero://open" xlink:href="zotero://open">x</a>
        <image href="zotero://image" /></svg>
    `);
    expect(clean).not.toContain('zotero:');
    expect(clean).not.toContain('srcdoc');
    expect(clean).toContain('sandbox=""');
  });

  test.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'java&#x09;script:alert(1)',
    'java&#x0a;script:alert(1)',
    '&#106;avascript:alert(1)',
    'vbscript:msgbox(1)',
    'data:text/html,bad',
    'command:workbench.action.closeWindow',
  ])('still removes dangerous href %s', (href: string) => {
    expect(sanitize(`<a href="${href}" onclick="alert(1)">x</a>`)).toBe(
      '<a>x</a>',
    );
  });

  test('keeps existing links and image data support', () => {
    const html =
      '<a href="https://example.com">web</a><a href="#title">title</a><a href="tag://topic">tag</a><img src="data:image/png;base64,AA==">';
    expect(sanitize(html)).toBe(html);
  });

  test.each([
    'javascript',
    'VBSCRIPT',
    'data',
    'command',
    'blob',
    'filesystem',
    'file',
    'zotero:',
    '.*',
    ' zotero',
    'zotero\n',
    '1scheme',
    'zotero|javascript',
  ])('rejects invalid or reserved policy entry %s', (scheme: string) => {
    expect(() =>
      createHtmlSanitizer({ additionalLinkSchemes: [scheme] }),
    ).toThrow(TypeError);
  });

  test('copies and freezes the policy', () => {
    const schemes = ['ZOTERO', 'zotero'];
    const policy = normalizeSecurityPolicy({ additionalLinkSchemes: schemes });
    schemes.push('obsidian');
    expect(policy.additionalLinkSchemes).toEqual(['zotero']);
    expect(Object.isFrozen(policy)).toBe(true);
    expect(Object.isFrozen(policy.additionalLinkSchemes)).toBe(true);
  });
});
