import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { extractPermissions } from '../lib/source';
import {
  buildAdditionalTemplate,
  buildDetailedTemplate,
  buildGovCloudTemplate,
} from '../lib/templates';
import { policyDocumentSize, type PolicyDocument } from '../lib/policy';

const fixture = JSON.parse(
  readFileSync(
    join(__dirname, '__fixtures__', 'ingestion-sources.json'),
    'utf8',
  ),
);
const perms = extractPermissions(fixture);

function managedPolicies(template: ReturnType<typeof buildDetailedTemplate>) {
  return Object.entries(template.Resources).filter(
    ([, r]) => r.Type === 'AWS::IAM::ManagedPolicy',
  );
}

describe('buildDetailedTemplate', () => {
  it('produces the expected top-level shape', () => {
    const t = buildDetailedTemplate(perms);
    assert.equal(t.AWSTemplateFormatVersion, '2010-09-09');
    assert.ok(t.Parameters?.JupiterOneAwsAccountArns);
    assert.ok(t.Parameters?.JupiterOneExternalId);
    assert.ok(t.Outputs?.RoleARN);
    assert.equal(t.Resources.JupiterOneRole?.Type, 'AWS::IAM::Role');
  });

  it('includes resource-scoped apigateway:GET in the first policy', () => {
    const t = buildDetailedTemplate(perms);
    const [, first] = managedPolicies(t)[0];
    const doc = first.Properties?.PolicyDocument as PolicyDocument;
    const apigwStmt = doc.Statement.find(
      (s) =>
        (Array.isArray(s.Action) ? s.Action[0] : s.Action) === 'apigateway:GET',
    );
    assert.ok(apigwStmt, 'first policy must include apigateway:GET');
    const resources = Array.isArray(apigwStmt!.Resource)
      ? apigwStmt!.Resource
      : [apigwStmt!.Resource];
    assert.ok(resources.some((r) => r.includes('arn:aws:apigateway:')));
  });

  it('attaches every managed policy + AWS SecurityAudit to the role', () => {
    const t = buildDetailedTemplate(perms);
    const role = t.Resources.JupiterOneRole;
    const arns = role.Properties?.ManagedPolicyArns as unknown[];
    assert.ok(arns.includes('arn:aws:iam::aws:policy/SecurityAudit'));
    const policyCount = managedPolicies(t).length;
    // role.ManagedPolicyArns = SecurityAudit + each managed policy ref
    assert.equal(arns.length, policyCount + 1);
  });

  it('keeps every partitioned managed policy under the AWS limit', () => {
    const t = buildDetailedTemplate(perms);
    for (const [, r] of managedPolicies(t)) {
      const doc = r.Properties?.PolicyDocument as PolicyDocument;
      assert.ok(
        policyDocumentSize(doc) <= 6144,
        `policy exceeds 6144: ${policyDocumentSize(doc)}`,
      );
    }
  });

  it('partitions across multiple managed policies when forced under a small limit', () => {
    const big = {
      ingestionSourcesConfig: [
        {
          id: 'big',
          permissions: Array.from(
            { length: 200 },
            (_, i) => `svc:Action${String(i).padStart(3, '0')}`,
          ),
        },
      ],
    };
    const bigPerms = extractPermissions(big);
    const t = buildDetailedTemplate(bigPerms, { policySizeLimit: 800 });
    const policies = managedPolicies(t);
    assert.ok(policies.length >= 2);
    // Resource names follow the pattern of the existing template.
    const names = policies.map(([n]) => n);
    assert.deepEqual(names[0], 'JupiterOneSecurityAuditPolicy');
    assert.deepEqual(names[1], 'JupiterOneSecurityAuditPolicy2');
  });

  it('is deterministic: same input produces byte-identical output', () => {
    const a = JSON.stringify(buildDetailedTemplate(perms));
    const b = JSON.stringify(buildDetailedTemplate(perms));
    assert.equal(a, b);
  });
});

describe('buildAdditionalTemplate', () => {
  it('emits a single managed policy with wildcard actions + broad-ARN apigateway:GET', () => {
    const t = buildAdditionalTemplate(perms);
    const policies = managedPolicies(t);
    assert.equal(policies.length, 1);
    const doc = policies[0][1].Properties?.PolicyDocument as PolicyDocument;
    // wildcard statement
    assert.deepEqual(doc.Statement[0].Action, perms.wildcardActions);
    assert.equal(doc.Statement[0].Resource, '*');
    // apigateway:GET resource statement comes from `roles[]` (broad ARN form).
    // Both Action and Resource MUST be arrays (matches the historical contract).
    const apigwStmt = doc.Statement[1];
    assert.deepEqual(apigwStmt.Action, ['apigateway:GET']);
    assert.deepEqual(apigwStmt.Resource, ['arn:aws:apigateway:*::/*']);
  });

  it('omits the resource-scoped statement when the source has no wildcard resources', () => {
    const minimal = {
      ingestionSourcesConfig: [
        {
          id: 'minimal',
          permissions: ['ec2:DescribeVpcs'],
          roles: ['ec2:Describe*'],
        },
      ],
    };
    const minimalPerms = extractPermissions(minimal);
    const t = buildAdditionalTemplate(minimalPerms);
    const doc = managedPolicies(t)[0][1].Properties
      ?.PolicyDocument as PolicyDocument;
    assert.equal(doc.Statement.length, 1);
    assert.equal(doc.Statement[0].Resource, '*');
  });

  it('uses the same parameter/role contract as the existing template', () => {
    const t = buildAdditionalTemplate(perms);
    assert.ok(t.Parameters?.JupiterOneAwsAccountArns);
    assert.equal(t.Resources.JupiterOneRole?.Type, 'AWS::IAM::Role');
    const arns = t.Resources.JupiterOneRole?.Properties
      ?.ManagedPolicyArns as unknown[];
    assert.ok(arns.includes('arn:aws:iam::aws:policy/SecurityAudit'));
  });
});

describe('buildGovCloudTemplate', () => {
  it('attaches to an IAM User and uses the aws-us-gov partition', () => {
    const t = buildGovCloudTemplate(perms);
    const user = t.Resources.JupiterOneAccessUser;
    assert.equal(user.Type, 'AWS::IAM::User');
    const arns = user.Properties?.ManagedPolicyArns as unknown[];
    assert.ok(arns.includes('arn:aws-us-gov:iam::aws:policy/SecurityAudit'));
    assert.ok(t.Outputs?.UserARN);
    assert.equal(t.Parameters, undefined);
  });

  it('rewrites apigateway resource ARNs to the aws-us-gov partition', () => {
    const t = buildGovCloudTemplate(perms);
    const policies = managedPolicies(t);
    const doc = policies[0][1].Properties?.PolicyDocument as PolicyDocument;
    const apigwStmt = doc.Statement.find(
      (s) =>
        (Array.isArray(s.Action) ? s.Action[0] : s.Action) === 'apigateway:GET',
    );
    assert.ok(apigwStmt);
    const resources = Array.isArray(apigwStmt!.Resource)
      ? apigwStmt!.Resource
      : [apigwStmt!.Resource];
    for (const r of resources) {
      assert.ok(
        r.startsWith('arn:aws-us-gov:'),
        `expected aws-us-gov partition, got ${r}`,
      );
    }
  });
});
