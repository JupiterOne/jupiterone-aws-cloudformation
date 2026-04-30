import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, sep } from 'node:path';
import { syncTemplates } from '../lib/sync';

const fixture = JSON.parse(
  readFileSync(
    join(__dirname, '__fixtures__', 'ingestion-sources.json'),
    'utf8',
  ),
);

describe('syncTemplates', () => {
  it('produces nine writes - 3 files for each of 3 variants', async () => {
    const writes = await syncTemplates(fixture, { repoRoot: '/repo' });
    assert.equal(writes.length, 9);
    const filenames = writes.map((w) => w.path.split(sep).pop()!);
    assert.equal(
      filenames.filter((f) => f === 'cloudformation-template.json').length,
      3,
    );
    assert.equal(filenames.filter((f) => f === 'managed-policy.md').length, 3);
    assert.equal(filenames.filter((f) => f === 'terraform.tf').length, 3);
  });

  it('refuses to write empty templates', async () => {
    await assert.rejects(() =>
      syncTemplates({ ingestionSourcesConfig: [] }, { repoRoot: '/repo' }),
    );
  });

  it('is byte-identical across runs (idempotency)', async () => {
    const a = await syncTemplates(fixture, { repoRoot: '/repo' });
    const b = await syncTemplates(fixture, { repoRoot: '/repo' });
    for (let i = 0; i < a.length; i++) {
      assert.equal(a[i].path, b[i].path);
      assert.equal(a[i].content, b[i].content);
    }
  });

  it('writes valid JSON to every cloudformation-template.json', async () => {
    const writes = await syncTemplates(fixture, { repoRoot: '/repo' });
    for (const w of writes) {
      if (w.path.endsWith('cloudformation-template.json')) {
        const parsed = JSON.parse(w.content);
        assert.ok(parsed.Resources);
      }
    }
  });
});
