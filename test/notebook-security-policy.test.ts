import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as cheerio from 'cheerio';
import { Notebook } from '../src/notebook';

// LESS compilation is unrelated to policy transport; match other preview tests.
jest.mock('less', () => ({
  render: (
    _input: string,
    _options: unknown,
    callback: (error: unknown, output: { css: string }) => void,
  ) => callback(null, { css: '' }),
}));

describe('notebook host policy transport', () => {
  let directory: string;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'crossnote-policy-'));
  });

  afterEach(() => {
    fs.rmSync(directory, { recursive: true, force: true });
  });

  test('serializes host policy separately from configuration and frontmatter', async () => {
    fs.mkdirSync(path.join(directory, '.crossnote'));
    fs.writeFileSync(
      path.join(directory, '.crossnote/config.js'),
      '({ securityPolicy: { additionalLinkSchemes: ["command"] } })',
    );
    const schemes = ['Zotero'];
    const notebook = await Notebook.init({
      notebookPath: directory,
      config: { markdownParser: 'markdown-it' },
      securityPolicy: { additionalLinkSchemes: schemes },
    });
    schemes.push('obsidian');
    const untrustedConfig = {
      securityPolicy: { additionalLinkSchemes: ['command'] },
      additionalLinkSchemes: ['command'],
      markdownParser: 'markdown-it' as const,
    };
    notebook.updateConfig(untrustedConfig);
    const engine = notebook.getNoteMarkdownEngine(
      path.join(directory, 'note.md'),
    );
    const html = await engine.generateHTMLTemplateForPreview({
      inputString:
        '---\nsecurityPolicy:\n  additionalLinkSchemes: [command]\n---\n[paper](zotero://select/items/ABC)',
      config: untrustedConfig,
      vscodePreviewPanel: null,
    });
    const $ = cheerio.load(html);
    const rendered = await engine.parseMD(
      '[paper](zotero://select/items/ABC)',
      {
        isForPreview: true,
        useRelativeFilePath: false,
        hideFrontMatter: false,
      },
    );
    expect(rendered.html).toContain('href="zotero://select/items/ABC"');
    expect(
      JSON.parse($('#crossnote-data').attr('data-security-policy')!),
    ).toEqual({ additionalLinkSchemes: ['zotero'] });
    expect(notebook.securityPolicy.additionalLinkSchemes).toEqual(['zotero']);
    const other = await Notebook.init({
      notebookPath: directory,
      config: untrustedConfig,
    });
    expect(other.securityPolicy.additionalLinkSchemes).toEqual([]);
  });
});
