/**
 * Types and helpers for IAM policy documents and the AWS-imposed 6,144
 * non-whitespace character size limit on managed policies.
 *
 * Statements are kept as data so renderers (CloudFormation JSON, Markdown,
 * Terraform) can serialize them without round-tripping through string parsing.
 */
import type { ResourcePermission } from './source';

export const POLICY_SIZE_LIMIT = 6144;

export interface PolicyStatement {
  Effect: 'Allow';
  Action: string | string[];
  Resource: string | string[];
}

export interface PolicyDocument {
  Version: '2012-10-17';
  Statement: PolicyStatement[];
}

export function policyDocumentSize(doc: PolicyDocument): number {
  // AWS measures non-whitespace; JSON.stringify with no spaces produces
  // exactly that.
  return JSON.stringify(doc).length;
}

function statementWithActions(actions: string[]): PolicyStatement {
  return {
    Effect: 'Allow',
    Resource: '*',
    Action: actions,
  };
}

/**
 * Resource-scoped statement used by the *detailed* template:
 *   { Effect, Resource: [...specific ARNs], Action: "apigateway:GET" }
 * Field order and Action-as-string for single-action statements match the
 * historical hand-maintained file shape so diffs stay clean.
 */
function detailedResourceStatement(perm: ResourcePermission): PolicyStatement {
  return {
    Effect: 'Allow',
    Resource: perm.resources,
    Action: perm.action,
  };
}

/**
 * Resource-scoped statement used by the *wildcard* templates
 * (`iam-cloudformation`, `iam-cloudformation-govcloud`):
 *   { Effect, Action: ["apigateway:GET"], Resource: ["arn:..."] }
 * Note both fields are arrays even when they have a single element, matching
 * the historical shape.
 */
function wildcardResourceStatement(perm: ResourcePermission): PolicyStatement {
  return {
    Effect: 'Allow',
    Action: [perm.action],
    Resource: perm.resources,
  };
}

/**
 * Splits actions across one or more managed policy documents so each
 * serialized document stays under {@link POLICY_SIZE_LIMIT} characters.
 *
 * The first document includes the `seedStatements` (e.g. resource-specific
 * apigateway permissions); subsequent documents only contain action lists.
 *
 * @throws if any single action plus the seed statements would exceed the limit.
 */
export function partitionIntoPolicies(opts: {
  actions: string[];
  seedStatements?: PolicyStatement[];
  /** Hard cap (defaults to AWS limit). Lower it in tests to validate behavior. */
  limit?: number;
}): PolicyDocument[] {
  const limit = opts.limit ?? POLICY_SIZE_LIMIT;
  const seedStatements = opts.seedStatements ?? [];
  const policies: PolicyDocument[] = [];

  let current: PolicyDocument = {
    Version: '2012-10-17',
    Statement: [...seedStatements, statementWithActions([])],
  };

  const flushIfNeeded = (next: PolicyDocument): PolicyDocument => {
    if (policyDocumentSize(next) > limit) {
      // Pop the most recently added action and finalize this policy.
      const actionStmt = next.Statement[next.Statement.length - 1];
      const actions = Array.isArray(actionStmt.Action)
        ? actionStmt.Action
        : [actionStmt.Action];
      const popped = actions.pop()!;
      actionStmt.Action = actions;
      policies.push(next);
      const fresh: PolicyDocument = {
        Version: '2012-10-17',
        Statement: [statementWithActions([popped])],
      };
      if (policyDocumentSize(fresh) > limit) {
        throw new Error(
          `Single action "${popped}" exceeds policy size limit (${limit}). ` +
            `Reduce the seed statements or raise the limit.`,
        );
      }
      return fresh;
    }
    return next;
  };

  for (const action of opts.actions) {
    const stmt = current.Statement[current.Statement.length - 1];
    const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
    actions.push(action);
    stmt.Action = actions;
    current = flushIfNeeded(current);
  }

  // Drop the trailing policy if it ended up with no actions.
  const lastStmt = current.Statement[current.Statement.length - 1];
  const lastActions = Array.isArray(lastStmt.Action)
    ? lastStmt.Action
    : [lastStmt.Action];
  if (lastActions.length === 0 && current.Statement.length === 1) {
    return policies;
  }
  policies.push(current);

  return policies;
}

export function buildDetailedResourceStatements(
  resourcePermissions: ResourcePermission[],
): PolicyStatement[] {
  return resourcePermissions.map(detailedResourceStatement);
}

export function buildWildcardResourceStatements(
  resourcePermissions: ResourcePermission[],
): PolicyStatement[] {
  return resourcePermissions.map(wildcardResourceStatement);
}

/**
 * Adjusts ARN partitions in resource statements (e.g. `arn:aws:` → `arn:aws-us-gov:`).
 */
export function rewriteArnPartition(
  statements: PolicyStatement[],
  partition: 'aws' | 'aws-us-gov',
): PolicyStatement[] {
  const swap = (value: string): string =>
    value.startsWith('arn:aws:')
      ? `arn:${partition}:` + value.slice('arn:aws:'.length)
      : value;
  return statements.map((s) => ({
    ...s,
    Resource: Array.isArray(s.Resource) ? s.Resource.map(swap) : swap(s.Resource),
  }));
}
