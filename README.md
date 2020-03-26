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

- AccessAnalyzer
  - listAnalyzers
  - listFindings
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
- Batch
  - describeComputeEnvironments
  - describeJobDefinitions
  - describeJobQueues
  - describeJobs
  - listJobs
- CloudFormation
  - describeStacks
- CloudFront
  - listDistributions
  - listTagsForResource
- CloudTrail
  - describeTrails
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
  - describeFlowLogs
  - describeImages
  - describeInstances
  - describeInternetGateways
  - describeKeyPairs
  - describeNetworkAcls
  - describeNetworkInterfaces
  - describeRouteTables
  - describeSecurityGroups
  - describeSnapshots
  - describeSubnets
  - describeVolumes
  - describeVpcs
- ECR
  - describeImages
  - describeImageScanFindings
  - describeRepositories
  - getLifecyclePolicy
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
- ELB
  - describeLoadBalancers
  - describeTags
- ElastiCache
  - describeCacheClusters
  - describeCacheParameterGroups
  - describeCacheParameters
  - describeCacheSubnetGroups
  - listTagsForResource
- ES
  - describeElasticsearchDomains
  - listDomainNames
  - listTags
- GuardDuty
  - getDetector
  - getFindings
  - listDetectors
  - listFindings
- IAM
  - generateCredentialReport
  - getAccessKeyLastUsed
  - getAccountPasswordPolicy
  - getAccountSummary
  - getCredentialReport
  - getGroup
  - getGroupPolicy
  - getPolicyVersion
  - getRolePolicy
  - getSAMLProvider
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
  - listRoleTags
  - listSAMLProviders
  - listUserPolicies
  - listUsers
  - listUserTags
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
  - listTags
- Organizations
  - listAccounts
  - listTagsForResource
- RDS
  - describeDBClusters
  - describeDBClusterSnapshots
  - describeDBInstances
  - describeDBSnapshots
  - describeDBClusterParameterGroups
  - describeDBClusterParameters
  - describeDBParameterGroups
  - describeDBParameters
  - listTagsForResource
- Redshift
  - describeClusters
- Route53
  - listHostedZones
  - listResourceRecordSets
  - listTagsForResource
- Route53Domains
  - getDomainDetail
  - listDomains
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
  - listBucketInventoryConfigurations
- S3 bucket policy
  - getBucketCORS
  - getBucketLifecycleConfiguration
  - getBucketObjectLockConfiguration
  - getBucketPolicy
  - getBucketPublicAccessBlock
  - getBucketPolicyStatus
  - getBucketObjectLockConfiguration
- SNS
  - getTopicAttributes
  - getSubscriptionAttributes
  - listTopics
  - listSubscriptions
  - listTagsForResource
- SQS
  - getQueueAttributes
  - listQueues
  - listQueueTags
- Transfer
  - listServers
  - listTagsForResource
  - listUsers
- WAF
  - getWebACL
  - listWebACLs
- Workspaces
  - describeTags
  - describeWorkspaceBundles
  - describeWorkspaces

Planned services and anticipated relevant access requirements:

- CloudWatch Alarms
  - describeAlarms
  - describeAlarmHistory
- VPC Peering
  - describeVpcPeeringConnections
- WAF (Regional)
  - getWebACL
  - listWebACLs
- Workspaces
  - describeClientProperties
  - describeIpGroups
  - describeWorkspaceDirectories
  - describeWorkspaceImages
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
        "access-analyzer:List*",
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
        "s3:Get*Configuration",
        "sns:GetTopicAttributes",
        "sns:GetSubscriptionAttributes",
        "sns:ListTopics",
        "sns:ListSubscriptions",
        "sns:ListTagsForResource",
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
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",
        "acm:DescribeCertificate",
        "acm:ListTagsForCertificate",
        "acm:ListCertificates",
        "autoscaling:DescribeAutoScalingGroups",
        "batch:DescribeComputeEnvironments",
        "batch:DescribeJobDefinitions",
        "batch:DescribeJobQueues",
        "batch:DescribeJobs",
        "batch:ListJobs",
        "cloudformation:DescribeStacks",
        "cloudfront:ListDistributions",
        "cloudfront:ListTagsForResource",
        "cloudtrail:DescribeTrails",
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
        "ec2:DescribeFlowLogs",
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
        "ecr:GetLifecyclePolicy",
        "ecr:GetRepositoryPolicy",
        "ecr:DescribeImages",
        "ecr:DescribeImageScanFindings",
        "ecr:DescribeRepositories",
        "ecr:ListTagsForResource",
        "ecs:DescribeClusters",
        "ecs:DescribeContainerInstances",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "ecs:DescribeTasks",
        "ecs:DescribeTaskSets",
        "ecs:ListClusters",
        "ecs:ListContainerInstances",
        "ecs:ListServices",
        "ecs:ListTagsForResource",
        "ecs:ListTaskDefinitions",
        "ecs:ListTasks",
        "eks:DescribeCluster",
        "eks:ListClusters",
        "elasticloadbalancing:DescribeCacheClusters",
        "elasticloadbalancing:DescribeCacheParameterGroups",
        "elasticloadbalancing:DescribeCacheParameters",
        "elasticloadbalancing:DescribeCacheSubnetGroups",
        "elasticloadbalancing:ListTagsForResource",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTags",
        "es:DescribeElasticsearchDomains",
        "es:ListDomainNames",
        "es:ListTags",
        "events:ListRules",
        "events:ListTargetsByRule",
        "guardduty:GetDetector",
        "guardduty:GetFindings",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "iam:GenerateCredentialReport",
        "iam:GetAccessKeyLastUsed",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:GetGroup",
        "iam:GetGroupPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRolePolicy",
        "iam:GetSAMLProvider",
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
        "iam:ListRoleTags",
        "iam:ListSAMLProviders",
        "iam:ListUserPolicies",
        "iam:ListUsers",
        "iam:ListUserTags",
        "inspector:DescribeAssessmentRuns",
        "inspector:DescribeFindings",
        "inspector:ListAssessmentRuns",
        "inspector:ListFindings",
        "kms:DescribeKey",
        "kms:ListAliases",
        "kms:ListKeys",
        "lambda:ListFunctions",
        "lambda:ListTags",
        "organizations:ListAccounts",
        "organizations:ListTagsForResource",
        "redshift:DescribeClusters",
        "rds:DescribeDBClusters",
        "rds:DescribeDBClusterSnapshots",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBClusterParameterGroups",
        "rds:DescribeDBClusterParameters",
        "rds:DescribeDBParameterGroups",
        "rds:DescribeDBParameters",
        "rds:ListTagsForResource",
        "route53domains:GetDomainDetail",
        "route53domains:ListDomains",
        "route53domains:ListTagsForDomain",
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets",
        "route53:ListTagsForResource",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketLifecycleConfiguration",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketReplication",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetPublicAccessBlock",
        "s3:ListBuckets",
        "s3:ListBucketInventoryConfigurations",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "sns:GetTopicAttributes",
        "sns:GetSubscriptionAttributes",
        "sns:ListTopics",
        "sns:ListSubscriptions",
        "sns:ListTagsForResource",
        "sqs:GetQueueAttributes",
        "sqs:ListQueues",
        "sqs:ListQueueTags",
        "transfer:ListServers",
        "transfer:ListTagsForResource",
        "transfer:ListUsers",
        "waf:GetWebACL",
        "waf:ListWebACLs",
        "workspaces:describeTags",
        "workspaces:describeWorkspaceBundles",
        "workspaces:describeWorkspaces"
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
        "s3:Get*Configuration",
        "sns:GetTopicAttributes",
        "sns:GetSubscriptionAttributes",
        "sns:ListTopics",
        "sns:ListSubscriptions",
        "sns:ListTagsForResource",
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
