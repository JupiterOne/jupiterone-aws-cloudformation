# jupiterone-aws-cloudformation

This project provides instructions to configure the
[JupiterOne](https://jupiterone.com/) AWS integration. JupiterOne assumes an IAM
Role in the target account that has been granted permission to read information
from AWS services supported by JupiterOne. Configuring the IAM Role can be
accomplished using one of the following methods:

1. [![Launch JupiterOne CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=jupiterone-integration&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-jupiter-aws-integration%2Fjupiterone-cloudformation.json)
1. [Launch Cloudformation with AWS CLI](#cloudformation-with-aws-cli)
1. [Create a Role using the AWS Management Console](#manual-creation-with-aws-management-console)

## Supported Services

Currently supported services and relevant access requirements:

- ACM
  - describeCertificate
  - listCertificates
  - listTagsForCertificate
- API Gateway
  - getIntegration
  - getResources
  - getRestApis
- Autoscaling
  - describeAutoScalingGroups
- Cloudfront
  - listDistributions
  - listTagsForResource
- CloudWatch Events
  - listRules
  - listTargetsByRule
- Config Service
  - describeComplianceByConfigRule
  - describeConfigRules
  - getComplianceByResource
  - getComplianceDetailsByConfigRule
- DynamoDB
  - describeContinuousBackups
  - describeTable
  - listBackups
  - listTables
  - listTagsOfResource
- EC2
  - describeAddresses
  - describeImages
  - describeInstances
  - describeInternetGateways
  - describeKeyPairs
  - describeNetworkAcls
  - describeNetworkInterfaces
  - describeRouteTables
  - describeSecurityGroups
  - describeSubnets
  - describeVolumes
  - describeVpcs
- ELB
  - describeLoadBalancers
  - describeTags
- GuardDuty
  - getDetector
  - getFindings
  - listDetectors
  - listFindings
- IAM
  - getAccountPasswordPolicy
  - getAccountSummary
  - getGroup
  - getGroupPolicy
  - getPolicyVersion
  - getRolePolicy
  - getUserPolicy
  - listAccessKeys
  - listAccountAliases
  - listEntitiesForPolicy
  - listGroupPolicies
  - listGroups
  - listInstanceProfiles
  - listMFADevices
  - listPolicies
  - listRolePolicies
  - listRoles
  - listUserPolicies
  - listUsers
- Inspector
  - describeAssessmentRuns
  - describeFindings
  - listAssessmentRuns
  - listFindings
- KMS
  - describeKey
  - listAliases
  - listKeys
- Lambda
  - listFunctions
- RDS
  - describeDBClusters
  - describeDBInstances
  - listTagsForResource
- Redshift
  - describeClusters
- Route53
  - getDomainDetail
  - listDomains
  - listResourceRecordSets
  - listTagsForDomain
- S3
  - getBucketAcl
  - getBucketEncryption
  - getBucketLocation
  - getBucketLogging
  - getBucketReplication
  - getBucketTagging
  - getBucketVersioning
  - getPublicAccessBlock
  - listBuckets
- Transfer
  - listServers
  - listTagsForResource
  - listUsers
- WAF
  - getWebACL
  - listWebACLs

Planned services and anticipated relevant access requirements:

- CloudWatch Alarms
  - describeAlarms
  - describeAlarmHistory
- ECR
  - describeImages
  - describeRepositories
  - getRepositoryPolicy
  - listImages
  - listTagsForResource
- ECS
  - describeClusters
  - describeContainerInstances
  - describeServices
  - describeTaskDefinition
  - describeTasks
  - describeTaskSets
  - listClusters
  - listContainerInstances
  - listServices
  - listTagsForResource
  - listTaskDefinitions
  - listTasks
- EKS
  - describeCluster
  - listClusters
- ElastiCache
  - describeCacheClusters
  - describeCacheEngineVersions
  - describeCacheParameterGroups
  - describeCacheParameters
  - describeCacheSecurityGroups
  - describeCacheSubnetGroups
  - describeEngineDefaultParameters
  - listAllowedNodeTypeModifications
  - listTagsForResource
- S3 bucket policy
  - getBucketCORS
  - getBucketObjectLockConfiguration
  - getBucketPolicy
  - getBucketPublicAccessBlock
  - getBucketPolicyStatus
  - getObjectLegalHold
  - getObjectRetention
- VPC Peering
  - describeVpcPeeringConnections
- WAF (Regional)
  - getWebACL
  - listWebACLs
- Workspaces
  - describeClientProperties
  - describeIpGroups
  - describeTags
  - describeWorkspaceBundles
  - describeWorkspaceDirectories
  - describeWorkspaceImages
  - describeWorkspaces
  - listAvailableManagementCidrRanges

## IAM Role Permissions

The [SecurityAudit][1] AWS-managed IAM policy covers many permissions used by
JupiterOne and simplifies administration as support for more services is added.
However, there are [additional permissions](#additional-permissions), not
covered by `SecurityAudit`, necessary to allow JupiterOne to ingest more
information, enabling the platform to provide even more value.

Each of the configuration methods recommends and assumes the use of the
`SecurityAudit` managed policy, though you may decide to build out a single
policy based on the information provided here.

In case you don't mind the maintenance work and would prefer to update a
hand-crafted policy, an exact policy that includes
[specific permissions](#specific-permissions-policy) is also provided.

### Additional Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "batch:Describe*",
        "batch:List*",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "ecr:Describe*",
        "ecr:List*",
        "elasticache:List*",
        "elasticmapreduce:List*",
        "es:List*",
        "kinesis:Describe*",
        "kinesis:List*",
        "s3:GetObjectRetention",
        "s3:GetObjectLegalHold",
        "waf:List*",
        "waf:Get*",
        "waf-regional:List*",
        "waf-regional:Get*",
        "workspaces:List*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["apigateway:GET"],
      "Resource": ["arn:aws:apigateway:*::/*"]
    }
  ]
}
```

### Specific Permissions Policy

This policy may be used to provide only exactly the specific permissions
currently used by JupiterOne. Using this policy will most certainly require you
to update the policy in the future as more APIs are called by JupiterOne.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "acm:DescribeCertificate",
        "acm:ListTagsForCertificate",
        "acm:ListCertificates",
        "autoscaling:DescribeAutoScalingGroups",
        "cloudfront:ListDistributions",
        "cloudfront:ListTagsForResource",
        "cloudwatch:ListRules",
        "cloudwatch:ListTargetsByRule",
        "cloudwatch:ListTagsForResource",
        "config:DescribeComplianceByConfigRule",
        "config:DescribeConfigRules",
        "config:GetComplianceByResource",
        "config:GetComplianceDetailsByConfigRule",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeTable",
        "dynamodb:ListBackups",
        "dynamodb:ListTables",
        "dynamodb:ListTagsOfResource",
        "ec2:DescribeAddresses",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTags",
        "events:ListRules",
        "events:ListTargetsByRule",
        "guardduty:GetDetector",
        "guardduty:GetFindings",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetGroup",
        "iam:GetGroupPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRolePolicy",
        "iam:GetUserPolicy",
        "iam:ListAccessKeys",
        "iam:ListAccountAliases",
        "iam:ListEntitiesForPolicy",
        "iam:ListGroupPolicies",
        "iam:ListGroups",
        "iam:ListInstanceProfiles",
        "iam:ListMFADevices",
        "iam:ListPolicies",
        "iam:ListRolePolicies",
        "iam:ListRoles",
        "iam:ListUserPolicies",
        "iam:ListUsers",
        "inspector:DescribeAssessmentRuns",
        "inspector:DescribeFindings",
        "inspector:ListAssessmentRuns",
        "inspector:ListFindings",
        "kms:DescribeKey",
        "kms:ListAliases",
        "kms:ListKeys",
        "lambda:ListFunctions",
        "lambda:ListTags",
        "redshift:DescribeClusters",
        "rds:DescribeDBClusters",
        "rds:DescribeDBClusterSnapshots",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "rds:ListTagsForResource",
        "route53domains:GetDomainDetail",
        "route53domains:ListDomains",
        "route53domains:ListTagsForDomain",
        "route53:ListResourceRecordSets",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketReplication",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetPublicAccessBlock",
        "s3:ListBuckets",
        "transfer:ListServers",
        "transfer:ListTagsForResource",
        "transfer:ListUsers",
        "waf:GetWebACL",
        "waf:ListWebACLs"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["apigateway:HEAD", "apigateway:GET", "apigateway:OPTIONS"],
      "Resource": [
        "arn:aws:apigateway:*::/restapis",
        "arn:aws:apigateway:*::/restapis/*/authorizers",
        "arn:aws:apigateway:*::/restapis/*/authorizers/*",
        "arn:aws:apigateway:*::/restapis/*/resources",
        "arn:aws:apigateway:*::/restapis/*/resources/*",
        "arn:aws:apigateway:*::/restapis/*/resources/*/methods/*",
        "arn:aws:apigateway:*::/vpclinks"
      ]
    }
  ]
}
```

## Cloudformation with AWS CLI

```bash
aws cloudformation create-stack --stack-name JupiterOneIntegration --capabilities CAPABILITY_NAMED_IAM --template-url https://s3.amazonaws.com/jupiterone-prod-us-jupiter-aws-integration/jupiterone-cloudformation.json
```

## Manual Creation with AWS Management Console

From your AWS Management Console, perform the following steps:

1.  Go to **IAM**, select **Roles** and then **Create Role**.

1.  Select **Another AWS account** under **Select type of trusted entity**.

1.  Enter the following **Account ID**: `<jupiterone_account_id>`

1.  Select **Require external ID** and enter the following **External ID**:
    `<jupiterone_external_id>`

1.  Leave **Require MFA** unchecked and click **Next: Permissions**.

1.  Click **Create Policy**, select the **JSON** tab, and enter the following
    document content:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "batch:Describe*",
        "batch:List*",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "ecr:Describe*",
        "ecr:List*",
        "elasticache:List*",
        "elasticmapreduce:List*",
        "es:List*",
        "kinesis:Describe*",
        "kinesis:List*",
        "s3:GetObjectRetention",
        "s3:GetObjectLegalHold",
        "waf:List*",
        "waf:Get*",
        "waf-regional:List*",
        "waf-regional:Get*",
        "workspaces:List*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["apigateway:GET"],
      "Resource": ["arn:aws:apigateway:*::/*"]
    }
  ]
}
```

1.  Click **Review Policy** and verify the permissions.

1.  Enter `JupiterOneSecurityAudit` as the **Name** and click **Create Policy**.

1.  Return to the **Create Role** tab in your browser. Click the Policy table's
    **Refresh Icon**.

1.  In the Policy search box, search for `SecurityAudit`. Select both
    `SecurityAudit` and `JupiterOneSecurityAudit` policies. [SecurityAudit][1]
    is an AWS-managed IAM policy.

1.  With both policies selected, click **Next: Review**.

1.  Enter `JupiterOne` as the **Role Name**, and optionally, enter a description
    for the Role.

1.  Click **Create Role**.

1.  In the list of Roles, search for and select the newly created `JupiterOne`
    role, and copy the **Role ARN**. It should be in a format that looks like
    `arn:aws:iam::<your_aws_account_id>:role/JupiterOne`.

[1]:
  https://console.aws.amazon.com/iam/home#policies/arn:aws:iam::aws:policy/SecurityAudit
