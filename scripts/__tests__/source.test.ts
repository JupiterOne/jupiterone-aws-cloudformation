import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { extractPermissions } from '../lib/source';

const fixture = JSON.parse(
  readFileSync(
    join(__dirname, '__fixtures__', 'ingestion-sources.json'),
    'utf8',
  ),
);

describe('extractPermissions', () => {
  it('flattens permissions across roots and children, dedupes, sorts', () => {
    const result = extractPermissions(fixture);
    // Plain action `ec2:DescribeVpcs` appears twice in the fixture - dedup it.
    const occurrences = result.exactActions.filter(
      (a) => a === 'ec2:DescribeVpcs',
    ).length;
    assert.equal(occurrences, 1);
    assert.deepEqual(
      result.exactActions,
      [...result.exactActions].sort((a, b) => a.localeCompare(b)),
    );
    assert.ok(result.exactActions.includes('iam:GetUser'));
    assert.ok(result.exactActions.includes('organizations:ListAccounts'));
    assert.ok(result.exactActions.includes('ec2:DescribeFlowLogs'));
  });

  it('separates wildcard `roles[]` entries into wildcardActions', () => {
    const result = extractPermissions(fixture);
    assert.deepEqual(
      [...result.wildcardActions].sort(),
      [
        'ec2:Describe*',
        'iam:Get*',
        'iam:List*',
        'organizations:Describe*',
        'organizations:List*',
      ],
    );
    // Wildcards must not leak into the exact-action bucket.
    for (const w of result.wildcardActions) {
      assert.ok(!result.exactActions.includes(w));
    }
  });

  it('parses "action arn:resource" permissions[] entries into resourcePermissions', () => {
    const result = extractPermissions(fixture);
    const apigw = result.resourcePermissions.find(
      (p) => p.action === 'apigateway:GET',
    );
    assert.ok(apigw, 'expected apigateway:GET resource permission');
    assert.deepEqual(apigw!.resources.slice(0, 2), [
      'arn:aws:apigateway:*::/apis',
      'arn:aws:apigateway:*::/apis/*/integrations',
    ]);
    assert.equal(apigw!.resources.length, 4);
    // The plain action form must NOT appear in exactActions.
    assert.ok(!result.exactActions.includes('apigateway:GET'));
  });

  it('parses "action arn:resource" roles[] entries into wildcardResourcePermissions', () => {
    const result = extractPermissions(fixture);
    const apigw = result.wildcardResourcePermissions.find(
      (p) => p.action === 'apigateway:GET',
    );
    assert.ok(apigw, 'expected apigateway:GET wildcard-resource permission');
    assert.deepEqual(apigw!.resources, ['arn:aws:apigateway:*::/*']);
    // The action must NOT leak into exactActions or wildcardActions.
    assert.ok(!result.exactActions.includes('apigateway:GET'));
    assert.ok(!result.wildcardActions.includes('apigateway:GET'));
  });

  it('tolerates `authorization` wrapper shape', () => {
    const result = extractPermissions({
      ingestionSourcesConfig: [
        {
          id: 'wrapper',
          authorization: {
            permissions: ['s3:ListAllMyBuckets'],
            roles: ['s3:Get*'],
          },
        } as never,
      ],
    });
    assert.deepEqual(result.exactActions, ['s3:ListAllMyBuckets']);
    assert.deepEqual(result.wildcardActions, ['s3:Get*']);
  });

  it('returns empty results for an empty payload', () => {
    const result = extractPermissions({ ingestionSourcesConfig: [] });
    assert.deepEqual(result.exactActions, []);
    assert.deepEqual(result.wildcardActions, []);
    assert.deepEqual(result.resourcePermissions, []);
    assert.deepEqual(result.wildcardResourcePermissions, []);
  });
});
