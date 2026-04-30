import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  POLICY_SIZE_LIMIT,
  partitionIntoPolicies,
  policyDocumentSize,
  rewriteArnPartition,
} from '../lib/policy';

const TEN_CHAR_ACTION = (i: number) =>
  `svc:Action${String(i).padStart(3, '0')}`; // 14 chars - keep small

describe('partitionIntoPolicies', () => {
  it('keeps every action in a single policy when under the limit', () => {
    const actions = Array.from({ length: 5 }, (_, i) => TEN_CHAR_ACTION(i));
    const policies = partitionIntoPolicies({ actions });
    assert.equal(policies.length, 1);
    const stmt = policies[0].Statement[0];
    assert.deepEqual(stmt.Action, actions);
    assert.ok(policyDocumentSize(policies[0]) <= POLICY_SIZE_LIMIT);
  });

  it('splits across multiple policies when the limit is exceeded', () => {
    // Construct enough actions to require splitting at a small limit.
    const actions = Array.from({ length: 200 }, (_, i) => TEN_CHAR_ACTION(i));
    const policies = partitionIntoPolicies({ actions, limit: 500 });
    assert.ok(policies.length >= 2);
    for (const p of policies) {
      assert.ok(
        policyDocumentSize(p) <= 500,
        `policy of size ${policyDocumentSize(p)} exceeds limit`,
      );
    }
    // No action should be lost or duplicated across policies.
    const flat = policies.flatMap((p) => {
      const a = p.Statement[p.Statement.length - 1].Action;
      return Array.isArray(a) ? a : [a];
    });
    assert.deepEqual(flat, actions);
  });

  it('preserves seed statements in the first policy only', () => {
    const seed = [
      {
        Effect: 'Allow' as const,
        Action: 'apigateway:GET',
        Resource: ['arn:aws:apigateway:*::/restapis'],
      },
    ];
    const actions = Array.from({ length: 50 }, (_, i) => TEN_CHAR_ACTION(i));
    const policies = partitionIntoPolicies({
      actions,
      seedStatements: seed,
      limit: 400,
    });
    assert.ok(policies.length >= 2);
    assert.equal(policies[0].Statement[0].Action, 'apigateway:GET');
    for (let i = 1; i < policies.length; i++) {
      assert.equal(policies[i].Statement.length, 1);
      assert.equal(policies[i].Statement[0].Resource, '*');
    }
  });

  it('throws when a single action plus seeds cannot fit', () => {
    const huge = 'svc:' + 'X'.repeat(500);
    assert.throws(() =>
      partitionIntoPolicies({ actions: [huge], limit: 100 }),
    );
  });

  it('returns an empty array when actions is empty and no seed statements', () => {
    assert.deepEqual(partitionIntoPolicies({ actions: [] }), []);
  });

  it('emits one policy with seed statements when actions is empty', () => {
    const seed = [
      {
        Effect: 'Allow' as const,
        Action: 'apigateway:GET',
        Resource: ['arn:aws:apigateway:*::/restapis'],
      },
    ];
    const policies = partitionIntoPolicies({
      actions: [],
      seedStatements: seed,
    });
    assert.equal(policies.length, 1);
    assert.equal(policies[0].Statement[0].Action, 'apigateway:GET');
  });
});

describe('rewriteArnPartition', () => {
  it('rewrites string Resource fields', () => {
    const out = rewriteArnPartition(
      [
        {
          Effect: 'Allow',
          Action: 'apigateway:GET',
          Resource: 'arn:aws:apigateway:*::/restapis',
        },
      ],
      'aws-us-gov',
    );
    assert.equal(out[0].Resource, 'arn:aws-us-gov:apigateway:*::/restapis');
  });

  it('rewrites array Resource fields', () => {
    const out = rewriteArnPartition(
      [
        {
          Effect: 'Allow',
          Action: 'apigateway:GET',
          Resource: ['arn:aws:apigateway:*::/restapis', '*'],
        },
      ],
      'aws-us-gov',
    );
    assert.deepEqual(out[0].Resource, [
      'arn:aws-us-gov:apigateway:*::/restapis',
      '*',
    ]);
  });
});
