/**
 * Top-level "sync" routine: takes the raw ingestion-sources JSON, regenerates
 * every committed template/markdown/terraform file, and returns the writes as
 * { path, content } pairs so the caller can either persist them or diff them
 * (used by the validation mode).
 */
import { join } from 'node:path';
import { extractPermissions, type RawIngestionSourcesPayload } from './source';
import {
  buildAdditionalTemplate,
  buildDetailedTemplate,
  buildGovCloudTemplate,
  type CloudFormationTemplate,
} from './templates';
import {
  formatWithPrettier,
  renderCloudFormationJson,
  renderManagedPolicyMarkdown,
  renderTerraform,
} from './render';

export interface FileWrite {
  path: string;
  content: string;
}

export interface SyncOptions {
  /** Repo root absolute path. */
  repoRoot: string;
  /** Override the AWS-imposed 6144-char policy size limit (used in tests). */
  policySizeLimit?: number;
}

interface VariantSpec {
  dir: string;
  template: CloudFormationTemplate;
  markdown: 'multi' | 'single';
  terraform: { principal: 'role' | 'user'; partition: 'aws' | 'aws-us-gov' };
}

export async function syncTemplates(
  payload: RawIngestionSourcesPayload,
  opts: SyncOptions,
): Promise<FileWrite[]> {
  const perms = extractPermissions(payload);

  if (perms.exactActions.length === 0) {
    throw new Error(
      'Source payload contained no exact IAM permissions. Refusing to ' +
        'overwrite templates with an empty action list.',
    );
  }

  const variants: VariantSpec[] = [
    {
      dir: 'cloudformation/iam-cloudformation-detailed',
      template: buildDetailedTemplate(perms, {
        policySizeLimit: opts.policySizeLimit,
      }),
      markdown: 'multi',
      terraform: { principal: 'role', partition: 'aws' },
    },
    {
      dir: 'cloudformation/iam-cloudformation',
      template: buildAdditionalTemplate(perms),
      markdown: 'single',
      terraform: { principal: 'role', partition: 'aws' },
    },
    {
      dir: 'cloudformation/iam-cloudformation-govcloud',
      template: buildGovCloudTemplate(perms),
      markdown: 'single',
      terraform: { principal: 'user', partition: 'aws-us-gov' },
    },
  ];

  const writes: FileWrite[] = [];
  for (const variant of variants) {
    const jsonPath = join(
      opts.repoRoot,
      variant.dir,
      'cloudformation-template.json',
    );
    const mdPath = join(opts.repoRoot, variant.dir, 'managed-policy.md');
    const tfPath = join(opts.repoRoot, variant.dir, 'terraform.tf');

    writes.push({
      path: jsonPath,
      content: await formatWithPrettier(
        jsonPath,
        renderCloudFormationJson(variant.template),
      ),
    });
    writes.push({
      path: mdPath,
      content: await formatWithPrettier(
        mdPath,
        renderManagedPolicyMarkdown(variant.template, {
          layout: variant.markdown,
        }),
      ),
    });
    // Terraform files aren't formatted by the project's prettier config; we
    // emit them as-is.
    writes.push({
      path: tfPath,
      content: renderTerraform(variant.template, variant.terraform),
    });
  }

  return writes;
}
