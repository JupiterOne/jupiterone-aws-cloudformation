/**
 * Renders the data structures from {@link buildDetailedTemplate} and friends
 * to the on-disk formats committed in this repo:
 *
 *  - `cloudformation-template.json` (CloudFormation)
 *  - `managed-policy.md` (human-readable JSON snippet)
 *  - `terraform.tf` (Terraform aws_iam_* resources)
 *
 * The renderers carefully preserve whitespace and ordering so that idempotent
 * runs against unchanged input produce byte-identical files (no spurious diffs).
 */
import { format, resolveConfig } from 'prettier';
import type { CloudFormationTemplate } from './templates';
import type { PolicyDocument, PolicyStatement } from './policy';

/**
 * Re-format a generated file with the project's prettier config so output
 * matches what `pnpm prettier` (and the lint-staged pre-commit hook) would
 * produce. Without this, our `JSON.stringify` always-expanded arrays differ
 * from prettier's "collapse if it fits" behavior.
 */
export async function formatWithPrettier(
  filepath: string,
  content: string,
): Promise<string> {
  const config = (await resolveConfig(filepath)) ?? {};
  return format(content, { ...config, filepath });
}

const JUPITERONE_ACCOUNT_ARNS = [
  'arn:aws:iam::612791702201:root',
  'arn:aws:iam::592277296164:root',
  'arn:aws:iam::543056157939:root',
  'arn:aws:iam::688694159727:root',
  'arn:aws:iam::248422699954:root',
  'arn:aws:iam::703115985002:root',
];

export function renderCloudFormationJson(
  template: CloudFormationTemplate,
): string {
  // Match prettier's default 2-space JSON output and end with a trailing newline
  // so our diffs stay clean against existing files committed via prettier.
  return JSON.stringify(template, null, 2) + '\n';
}

function policyToPrettyJson(doc: PolicyDocument): string {
  return JSON.stringify(doc, null, 2);
}

function extractPolicyDocuments(template: CloudFormationTemplate): {
  name: string;
  document: PolicyDocument;
}[] {
  const out: { name: string; document: PolicyDocument }[] = [];
  for (const [name, resource] of Object.entries(template.Resources)) {
    if (resource.Type === 'AWS::IAM::ManagedPolicy') {
      const doc = resource.Properties?.PolicyDocument as PolicyDocument;
      out.push({ name, document: doc });
    }
  }
  return out;
}

export interface MarkdownOptions {
  /**
   * `single` matches `iam-cloudformation/managed-policy.md` (one block, no
   * numbering). `multi` matches `iam-cloudformation-detailed/managed-policy.md`
   * with a top-level header and per-statement numbered blocks.
   */
  layout: 'single' | 'multi';
}

export function renderManagedPolicyMarkdown(
  template: CloudFormationTemplate,
  opts: MarkdownOptions,
): string {
  const policies = extractPolicyDocuments(template);
  const parts: string[] = [];

  if (opts.layout === 'multi') {
    parts.push('# Specific IAM Managed Policies\n');
    policies.forEach((p, idx) => {
      parts.push(`## Managed Policy Statement ${idx + 1}\n`);
      parts.push('```json\n' + policyToPrettyJson(p.document) + '\n```\n');
    });
  } else {
    if (policies.length !== 1) {
      throw new Error(
        `single-layout markdown expects 1 managed policy, got ${policies.length}`,
      );
    }
    parts.push('## Managed Policy Statement\n');
    parts.push(
      '```json\n' + policyToPrettyJson(policies[0].document) + '\n```\n',
    );
  }

  return parts.join('\n');
}

function policyToTerraformJson(doc: PolicyDocument): string {
  // Terraform's heredoc syntax requires the JSON to be embedded verbatim.
  return JSON.stringify(doc, null, 2);
}

function statementResourceListEqualsRoot(stmt: PolicyStatement): boolean {
  return (
    typeof stmt.Resource === 'string' && stmt.Resource === '*'
  );
}
// `statementResourceListEqualsRoot` is intentionally exported nowhere; it's
// retained as a structural helper for future renderer tweaks but unused right
// now — we render PolicyDocument with JSON.stringify directly.
void statementResourceListEqualsRoot;

interface TerraformRenderOptions {
  /** `role` ⇒ commercial IAM role; `user` ⇒ GovCloud IAM user. */
  principal: 'role' | 'user';
  /** AWS partition (`aws` or `aws-us-gov`). Drives the SecurityAudit ARN. */
  partition: 'aws' | 'aws-us-gov';
}

export function renderTerraform(
  template: CloudFormationTemplate,
  opts: TerraformRenderOptions,
): string {
  const policies = extractPolicyDocuments(template);
  const out: string[] = [];

  if (opts.principal === 'role') {
    const trustArns = JSON.stringify(JUPITERONE_ACCOUNT_ARNS).replace(
      /","/g,
      '","',
    );
    out.push(
      `resource "aws_iam_role" "jupiterone" {
  name = "JupiterOne"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": ${trustArns}
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "<External Id>"
        }
      }
    }
  ]
}
EOF
}

output "aws_iam_role_jupiterone_role_arn" {
  value = "\${aws_iam_role.jupiterone.arn}"
}
`,
    );
  } else {
    out.push(
      `output "aws_iam_user_jupiterone_access_user" {
  value = "\${aws_iam_role.jupiterone.arn}"
}
`,
    );
  }

  policies.forEach((p, idx) => {
    const tfName =
      idx === 0
        ? 'jupiterone_security_audit_policy'
        : `jupiterone_security_audit_policy_${idx + 1}`;
    const policyName = idx === 0 ? 'JupiterOneSecurityAudit' : `JupiterOneSecurityAudit${idx + 1}`;
    out.push(
      `resource "aws_iam_policy" "${tfName}" {
  name = "${policyName}"
  policy = <<EOF
${policyToTerraformJson(p.document)}
EOF
}
`,
    );

    if (opts.principal === 'role') {
      const attachmentSuffix = idx === 0 ? '' : `_${idx + 1}`;
      out.push(
        `resource "aws_iam_role_policy_attachment" "jupiterone_security_audit_policy_attachment${attachmentSuffix}" {
  role       = "\${ aws_iam_role.jupiterone.name }"
  policy_arn = "\${ aws_iam_policy.${tfName}.arn }"
}
`,
      );
    } else {
      const attachmentSuffix = idx === 0 ? '' : `_${idx + 1}`;
      out.push(
        `resource "aws_iam_user_policy_attachment" "jupiterone_security_audit_policy_attachment${attachmentSuffix}" {
  user       = "\${ aws_iam_user.jupiterone_access_user.name }"
  policy_arn = "\${ aws_iam_policy.${tfName}.arn }"
}
`,
      );
    }
  });

  if (opts.principal === 'role') {
    out.push(
      `resource "aws_iam_role_policy_attachment" "aws_security_audit_policy_attachment" {
  role       = "\${ aws_iam_role.jupiterone.name }"
  policy_arn = "arn:${opts.partition}:iam::aws:policy/SecurityAudit"
}
`,
    );
  } else {
    out.push(
      `resource "aws_iam_user" "jupiterone_access_user" {
  name = "jupiterone-access-user"
}

resource "aws_iam_user_policy_attachment" "aws_security_audit_policy_attachment" {
  user       = "\${ aws_iam_user.jupiterone_access_user.name }"
  policy_arn = "arn:${opts.partition}:iam::aws:policy/SecurityAudit"
}
`,
    );
  }

  return out.join('\n');
}
