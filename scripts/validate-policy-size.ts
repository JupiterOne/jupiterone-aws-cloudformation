#!/usr/bin/env npx tsx

/**
 * Validates CloudFormation templates against the AWS limits they can hit:
 *
 * - each IAM policy document: 6,144 non-whitespace characters
 * - managed policies attached to one role or user: 10 (default quota)
 * - the template itself: 1 MB when referenced by S3 URL, which is how every
 *   supported path (launch link, `--template-url`, StackSets) deploys it.
 *   Past 51,200 bytes a direct upload (`--template-body`, console file
 *   upload) is rejected, so that limit is reported as a warning.
 *
 * Usage:
 *   npx tsx scripts/validate-policy-size.ts [files...]
 *
 * If no files are provided, validates all cloudformation-template.json files.
 */

import * as fs from 'fs';
import * as path from 'path';

const POLICY_SIZE_LIMIT = 6144;
const MANAGED_POLICIES_PER_PRINCIPAL_LIMIT = 10;
const TEMPLATE_URL_BYTES_LIMIT = 1048576;
const TEMPLATE_BODY_BYTES_LIMIT = 51200;

interface PolicyDocument {
  Version: string;
  Statement: unknown[];
}

interface CloudFormationResource {
  Type: string;
  Properties?: {
    PolicyDocument?: PolicyDocument;
    ManagedPolicyArns?: unknown[];
    [key: string]: unknown;
  };
}

interface CloudFormationTemplate {
  Resources?: Record<string, CloudFormationResource>;
  [key: string]: unknown;
}

interface PolicyValidationResult {
  policyName: string;
  size: number;
  limit: number;
  remaining: number;
  valid: boolean;
}

export interface LimitCheck {
  name: string;
  value: number;
  limit: number;
  valid: boolean;
  /** Warnings are reported but don't fail the run. */
  severity: 'error' | 'warning';
}

export interface TemplateValidationResult {
  file: string;
  error: string | null;
  policies: PolicyValidationResult[];
  /** Template size and per-principal attachment counts. */
  limits: LimitCheck[];
}

function limitCheck(
  name: string,
  value: number,
  limit: number,
  severity: LimitCheck['severity'] = 'error'
): LimitCheck {
  return { name, value, limit, valid: value <= limit, severity };
}

/** True when the result has a policy or limit violation that fails the run. */
export function hasBlockingErrors(result: TemplateValidationResult): boolean {
  return (
    result.error !== null ||
    result.policies.some((p) => !p.valid) ||
    result.limits.some((l) => !l.valid && l.severity === 'error')
  );
}

function findCloudFormationTemplates(dir: string): string[] {
  const templates: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      templates.push(...findCloudFormationTemplates(fullPath));
    } else if (entry.name === 'cloudformation-template.json') {
      templates.push(fullPath);
    }
  }

  return templates;
}

function validatePolicySize(
  policyName: string,
  policyDocument: PolicyDocument
): PolicyValidationResult {
  const compactJson = JSON.stringify(policyDocument);
  const size = compactJson.length;
  const remaining = POLICY_SIZE_LIMIT - size;

  return {
    policyName,
    size,
    limit: POLICY_SIZE_LIMIT,
    remaining,
    valid: size <= POLICY_SIZE_LIMIT,
  };
}

export function validateTemplate(filePath: string): TemplateValidationResult {
  return validateTemplateContent(filePath, fs.readFileSync(filePath, 'utf8'));
}

export function validateTemplateContent(
  filePath: string,
  content: string
): TemplateValidationResult {
  let template: CloudFormationTemplate;

  try {
    template = JSON.parse(content) as CloudFormationTemplate;
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return {
      file: filePath,
      error: `Invalid JSON: ${error}`,
      policies: [],
      limits: [],
    };
  }

  const policies: PolicyValidationResult[] = [];
  const templateBytes = Buffer.byteLength(content, 'utf8');
  const limits: LimitCheck[] = [
    limitCheck('template size (bytes)', templateBytes, TEMPLATE_URL_BYTES_LIMIT),
    limitCheck(
      'template size for direct upload (bytes)',
      templateBytes,
      TEMPLATE_BODY_BYTES_LIMIT,
      'warning'
    ),
  ];
  const resources = template.Resources ?? {};

  for (const [resourceName, resource] of Object.entries(resources)) {
    if (resource.Type === 'AWS::IAM::ManagedPolicy') {
      const policyDocument = resource.Properties?.PolicyDocument;
      if (policyDocument) {
        policies.push(validatePolicySize(resourceName, policyDocument));
      }
    }
    const attached = resource.Properties?.ManagedPolicyArns;
    if (Array.isArray(attached)) {
      limits.push(
        limitCheck(
          `${resourceName} managed policies`,
          attached.length,
          MANAGED_POLICIES_PER_PRINCIPAL_LIMIT
        )
      );
    }
  }

  return {
    file: filePath,
    error: null,
    policies,
    limits,
  };
}

function main(): void {
  const args = process.argv.slice(2);
  let files: string[];

  if (args.length > 0) {
    // Filter to only cloudformation-template.json files
    files = args.filter((f) => f.endsWith('cloudformation-template.json'));
    if (files.length === 0) {
      console.log(
        'No cloudformation-template.json files in arguments, skipping validation.'
      );
      process.exit(0);
    }
  } else {
    // Find all templates
    const cloudformationDir = path.join(__dirname, '..', 'cloudformation');
    files = findCloudFormationTemplates(cloudformationDir);
  }

  console.log('Validating IAM policy sizes...\n');
  console.log(`Policy size limit: ${POLICY_SIZE_LIMIT} characters\n`);

  let hasErrors = false;
  const results: TemplateValidationResult[] = [];

  for (const file of files) {
    const result = validateTemplate(file);
    results.push(result);

    if (hasBlockingErrors(result)) {
      hasErrors = true;
    }
  }

  // Print results
  for (const result of results) {
    const relativePath = path.relative(process.cwd(), result.file);
    console.log(`File: ${relativePath}`);

    if (result.error) {
      console.log(`  ERROR: ${result.error}\n`);
      continue;
    }

    for (const check of result.limits) {
      const status = check.valid
        ? 'OK'
        : check.severity === 'warning'
          ? 'WARNING'
          : 'OVER LIMIT';
      console.log(
        `  ${check.name}: ${check.value} of ${check.limit} - ${status}`
      );
    }

    if (result.policies.length === 0) {
      console.log('  No IAM managed policies found\n');
      continue;
    }

    for (const policy of result.policies) {
      const status = policy.valid ? 'OK' : 'OVER LIMIT';
      const remaining =
        policy.remaining >= 0 ? `+${policy.remaining}` : policy.remaining;
      console.log(
        `  ${policy.policyName}: ${policy.size} chars (${remaining} from limit) - ${status}`
      );
    }
    console.log('');
  }

  // Summary
  const totalPolicies = results.reduce((sum, r) => sum + r.policies.length, 0);
  const invalidPolicies = results.reduce(
    (sum, r) => sum + r.policies.filter((p) => !p.valid).length,
    0
  );
  const invalidLimits = results.reduce(
    (sum, r) =>
      sum + r.limits.filter((l) => !l.valid && l.severity === 'error').length,
    0
  );

  if (hasErrors) {
    console.log(
      `\nFAILED: ${invalidPolicies} of ${totalPolicies} policies exceed the size limit; ${invalidLimits} template size or attachment limit(s) exceeded.`
    );
    process.exit(1);
  } else {
    console.log(
      `\nPASSED: All ${totalPolicies} policies, template sizes and attachment counts are within AWS limits.`
    );
    process.exit(0);
  }
}

if (require.main === module) {
  main();
}
