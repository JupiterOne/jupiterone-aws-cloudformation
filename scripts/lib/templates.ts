/**
 * Builds the four CloudFormation templates this repository ships:
 *
 * - `iam-cloudformation-detailed`: exact action list, partitioned across
 *   multiple `AWS::IAM::ManagedPolicy` resources to fit the 6,144-char limit.
 *   Attached (with `arn:aws:iam::aws:policy/SecurityAudit`) to a single role.
 * - `iam-cloudformation`: a single managed policy of *wildcard* actions plus
 *   one resource-specific statement for `apigateway:GET`. Same role shape.
 * - `iam-cloudformation-organization`: same policy as `iam-cloudformation`,
 *   with a fixed, parameterised role name for AWS Organizations (StackSet +
 *   management account stack).
 * - `iam-cloudformation-govcloud`: same as `iam-cloudformation` but with the
 *   `aws-us-gov` ARN partition and an IAM User (GovCloud lacks the same
 *   cross-account role trust capabilities used in commercial AWS).
 *
 * The structures (parameters, outputs, metadata) intentionally mirror the
 * hand-maintained templates so the contract toward consumers does not change.
 */
import {
  actionsNotCoveredByWildcards,
  type PolicyDocument,
  type PolicyStatement,
  buildDetailedResourceStatements,
  buildWildcardResourceStatements,
  partitionIntoPolicies,
  rewriteArnPartition,
} from './policy';
import type { ExtractedPermissions } from './source';

export interface CloudFormationResource {
  Type: string;
  Properties?: Record<string, unknown>;
}

export interface CloudFormationTemplate {
  AWSTemplateFormatVersion: '2010-09-09';
  Description: string;
  Metadata?: Record<string, unknown>;
  Parameters?: Record<string, unknown>;
  Resources: Record<string, CloudFormationResource>;
  Outputs?: Record<string, unknown>;
}

const DETAILED_DESCRIPTION =
  'CloudFormation Template for JupiterOne AWS Integration IAM';
const ADDITIONAL_DESCRIPTION = DETAILED_DESCRIPTION;
const GOVCLOUD_DESCRIPTION =
  'CloudFormation Template for JupiterOne AWS GovCloud Integration IAM';

const J1_AUTH_PARAMETERS = {
  JupiterOneAwsAccountArns: {
    Description:
      "The JupiterOne AWS account ARN(s), in the format 'arn:aws:iam::<aws-account-id>:root'. If multiple, comma-delimited",
    Type: 'CommaDelimitedList',
    Default: 'arn:aws:iam::612791702201:root',
  },
  JupiterOneExternalId: {
    Description: 'The JupiterOne external Id',
    Type: 'String',
  },
} as const;

const J1_AUTH_METADATA = {
  'AWS::CloudFormation::Interface': {
    ParameterGroups: [
      {
        Label: { default: 'JupiterOne Authentication Parameters' },
        Parameters: ['JupiterOneAwsAccountArns', 'JupiterOneExternalId'],
      },
    ],
    ParameterLabels: {
      JupiterOneAwsAccountArns: {
        default: 'What are the JupiterOne AWS account ARNs?',
      },
      JupiterOneExternalId: {
        default: 'What is the JupiterOne external Id you were provided?',
      },
    },
  },
} as const;

function managedPolicyResource(
  name: string,
  document: PolicyDocument,
): CloudFormationResource {
  return {
    Type: 'AWS::IAM::ManagedPolicy',
    Properties: {
      ManagedPolicyName: name,
      Description: 'JupiterOne SecurityAudit policy',
      Path: '/',
      PolicyDocument: document,
    },
  };
}

function roleResource(
  managedPolicyArns: unknown[],
): CloudFormationResource {
  return {
    Type: 'AWS::IAM::Role',
    Properties: {
      ManagedPolicyArns: managedPolicyArns,
      AssumeRolePolicyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'sts:AssumeRole',
            Effect: 'Allow',
            Principal: { AWS: { Ref: 'JupiterOneAwsAccountArns' } },
            Condition: {
              StringEquals: {
                'sts:ExternalId': { Ref: 'JupiterOneExternalId' },
              },
            },
          },
        ],
      },
    },
  };
}

export interface BuildOptions {
  /** Override the AWS-imposed 6144-char limit (tests). */
  policySizeLimit?: number;
}

/**
 * Detailed template: every exact action explicitly listed.
 *
 * The first managed policy seeds the resource-scoped `apigateway:GET`
 * statement(s); remaining policies only carry chunks of the exact action list.
 */
export function buildDetailedTemplate(
  perms: ExtractedPermissions,
  opts: BuildOptions = {},
): CloudFormationTemplate {
  const seedStatements: PolicyStatement[] = buildDetailedResourceStatements(
    perms.resourcePermissions,
  );

  const policies = partitionIntoPolicies({
    actions: perms.exactActions,
    seedStatements,
    limit: opts.policySizeLimit,
  });

  if (policies.length === 0) {
    throw new Error(
      'Detailed template requires at least one exact action; got none.',
    );
  }

  const resources: Record<string, CloudFormationResource> = {};
  const policyRefs: unknown[] = ['arn:aws:iam::aws:policy/SecurityAudit'];

  policies.forEach((doc, idx) => {
    const suffix = idx === 0 ? '' : String(idx + 1);
    const resourceName = `JupiterOneSecurityAuditPolicy${suffix}`;
    const policyName = `JupiterOneSecurityAudit${suffix}`;
    resources[resourceName] = managedPolicyResource(policyName, doc);
    policyRefs.push({ Ref: resourceName });
  });

  resources.JupiterOneRole = roleResource(policyRefs);

  return {
    AWSTemplateFormatVersion: '2010-09-09',
    Description: DETAILED_DESCRIPTION,
    Metadata: J1_AUTH_METADATA,
    Parameters: J1_AUTH_PARAMETERS,
    Resources: resources,
    Outputs: {
      RoleARN: {
        Description: 'ARN of the JupiterOne role',
        Value: { 'Fn::GetAtt': ['JupiterOneRole', 'Arn'] },
      },
    },
  };
}

function buildWildcardPolicyDocument(
  perms: ExtractedPermissions,
  partition: 'aws' | 'aws-us-gov',
): PolicyDocument {
  const statements: PolicyStatement[] = [];

  // Steps that only declare exact `permissions[]` (no `roles[]` wildcard)
  // would otherwise be missing here and work only with the detailed template.
  const actions = [
    ...perms.wildcardActions,
    ...actionsNotCoveredByWildcards(perms.exactActions, perms.wildcardActions),
  ].sort((a, b) => a.localeCompare(b));

  if (actions.length > 0) {
    statements.push({
      Effect: 'Allow',
      Resource: '*',
      Action: actions,
    });
  }

  // The wildcard templates carry the broad-ARN form of resource-scoped
  // permissions (declared via per-step `roles[]`). The detailed template uses
  // `resourcePermissions` instead.
  if (perms.wildcardResourcePermissions.length > 0) {
    statements.push(
      ...rewriteArnPartition(
        buildWildcardResourceStatements(perms.wildcardResourcePermissions),
        partition,
      ),
    );
  }

  return { Version: '2012-10-17', Statement: statements };
}

/**
 * Additional template: wildcard actions + AWS-managed `SecurityAudit`.
 */
export function buildAdditionalTemplate(
  perms: ExtractedPermissions,
): CloudFormationTemplate {
  const document = buildWildcardPolicyDocument(perms, 'aws');
  const resources: Record<string, CloudFormationResource> = {
    JupiterOneSecurityAuditPolicy: managedPolicyResource(
      'JupiterOneSecurityAudit',
      document,
    ),
    JupiterOneRole: roleResource([
      'arn:aws:iam::aws:policy/SecurityAudit',
      { Ref: 'JupiterOneSecurityAuditPolicy' },
    ]),
  };
  return {
    AWSTemplateFormatVersion: '2010-09-09',
    Description: ADDITIONAL_DESCRIPTION,
    Metadata: J1_AUTH_METADATA,
    Parameters: J1_AUTH_PARAMETERS,
    Resources: resources,
    Outputs: {
      RoleARN: {
        Description: 'ARN of the JupiterOne role',
        Value: { 'Fn::GetAtt': ['JupiterOneRole', 'Arn'] },
      },
    },
  };
}

const ORGANIZATION_DESCRIPTION =
  'CloudFormation Template for JupiterOne AWS Integration IAM (AWS Organizations). ' +
  'Deploy it as a service-managed StackSet for member accounts and as a regular stack in the management account, ' +
  'using the same role name and External ID in both. Deploy to a single Region: IAM is global.';

const ORGANIZATION_ROLE_NAME_PARAMETER = {
  Description:
    'Name of the IAM role to create. Every account in the organization, including the management account, must use the same name.',
  Type: 'String',
  Default: 'JupiterOne',
  AllowedPattern: '[\\w+=,.@-]{1,64}',
  ConstraintDescription:
    'Use 1-64 letters, numbers or +=,.@_- characters (no spaces).',
} as const;

/**
 * Organization template: same permissions as the additional template, but
 * the role and policy get fixed names. Configure Organization Accounts
 * derives each member account's role ARN from the management account's role
 * name, so a CloudFormation-generated name (`<stack>-JupiterOneRole-<random>`)
 * can never match across accounts. The policy name is derived from the role
 * name so it does not collide with a `JupiterOneSecurityAudit` policy left by
 * an earlier single-account stack.
 */
export function buildOrganizationTemplate(
  perms: ExtractedPermissions,
): CloudFormationTemplate {
  const document = buildWildcardPolicyDocument(perms, 'aws');
  const policy = managedPolicyResource(
    'JupiterOneSecurityAudit',
    document,
  );
  const role = roleResource([
    'arn:aws:iam::aws:policy/SecurityAudit',
    { Ref: 'JupiterOneSecurityAuditPolicy' },
  ]);
  return {
    AWSTemplateFormatVersion: '2010-09-09',
    Description: ORGANIZATION_DESCRIPTION,
    Metadata: {
      'AWS::CloudFormation::Interface': {
        ParameterGroups: [
          {
            Label: { default: 'JupiterOne Authentication Parameters' },
            Parameters: [
              'JupiterOneAwsAccountArns',
              'JupiterOneExternalId',
              'JupiterOneRoleName',
            ],
          },
        ],
        ParameterLabels: {
          ...J1_AUTH_METADATA['AWS::CloudFormation::Interface'].ParameterLabels,
          JupiterOneRoleName: {
            default:
              'IAM role name (must be identical in every account of the organization)',
          },
        },
      },
    },
    Parameters: {
      ...J1_AUTH_PARAMETERS,
      // A StackSet puts this stack in every member account; NoEcho keeps the
      // External ID out of DescribeStacks there, and an empty value would
      // create a role no AssumeRole call can satisfy.
      JupiterOneExternalId: {
        ...J1_AUTH_PARAMETERS.JupiterOneExternalId,
        NoEcho: true,
        MinLength: 1,
      },
      JupiterOneRoleName: ORGANIZATION_ROLE_NAME_PARAMETER,
    },
    Resources: {
      JupiterOneSecurityAuditPolicy: {
        ...policy,
        Properties: {
          ...policy.Properties,
          ManagedPolicyName: {
            'Fn::Sub': '${JupiterOneRoleName}-SecurityAudit',
          },
        },
      },
      JupiterOneRole: {
        ...role,
        Properties: {
          ...role.Properties,
          RoleName: { Ref: 'JupiterOneRoleName' },
        },
      },
    },
    Outputs: {
      RoleARN: {
        Description: 'ARN of the JupiterOne role',
        Value: { 'Fn::GetAtt': ['JupiterOneRole', 'Arn'] },
      },
    },
  };
}

/**
 * GovCloud template: wildcard actions attached to an IAM User (no cross-account
 * trust available in GovCloud), plus the GovCloud-managed `SecurityAudit`.
 */
export function buildGovCloudTemplate(
  perms: ExtractedPermissions,
): CloudFormationTemplate {
  const document = buildWildcardPolicyDocument(perms, 'aws-us-gov');
  const resources: Record<string, CloudFormationResource> = {
    JupiterOneSecurityAuditPolicy: managedPolicyResource(
      'JupiterOneSecurityAudit',
      document,
    ),
    JupiterOneAccessUser: {
      Type: 'AWS::IAM::User',
      Properties: {
        ManagedPolicyArns: [
          'arn:aws-us-gov:iam::aws:policy/SecurityAudit',
          { Ref: 'JupiterOneSecurityAuditPolicy' },
        ],
        UserName: 'JupiterOneAccessUser',
      },
    },
  };
  return {
    AWSTemplateFormatVersion: '2010-09-09',
    Description: GOVCLOUD_DESCRIPTION,
    Resources: resources,
    Outputs: {
      UserARN: {
        Description: 'ARN of the JupiterOne user',
        Value: { 'Fn::GetAtt': ['JupiterOneAccessUser', 'Arn'] },
      },
    },
  };
}
