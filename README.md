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
  - describeKey
  - listAliases
  - listKeys
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
  - describeImages
  - describeInstances
  - describeInternetGateways
  - describeKeyPairs
  - describeNetworkAcls
  - describeRouteTables
  - describeSecurityGroups
  - describeSubnets
  - describeVpcs
  - describeVolumes
- ELB
  - describeTags
  - describeLoadBalancers
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

## IAM Role Permissions

The AWS [`SecurityAudit` Managed Policy](#securityaudit-managed-policy) covers
many permissions used by JupiterOne and simplifies administration as support for
more services is added. However, there are
[additional permissions](#additional-permissions), not covered by
`SecurityAudit`, necessary to allow JupiterOne to ingest more information,
enabling the platform to provide even more value.

Each of the configuration methods recommends and assumes the use of the
`SecurityAudit` Managed Policy, though you may decide to build out a single
policy based on the information provided here.

### `SecurityAudit` Managed Policy

It is recommended that this policy is attached to the role assumed by JupiterOne
to minimize maintenance efforts. A copy of the policy is provided here for
convenient review.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "acm:Describe*",
        "acm:List*",
        "application-autoscaling:Describe*",
        "appmesh:Describe*",
        "appmesh:List*",
        "appsync:List*",
        "athena:List*",
        "autoscaling:Describe*",
        "batch:DescribeComputeEnvironments",
        "batch:DescribeJobDefinitions",
        "chime:List*",
        "cloud9:Describe*",
        "cloud9:ListEnvironments",
        "clouddirectory:ListDirectories",
        "cloudformation:DescribeStack*",
        "cloudformation:GetTemplate",
        "cloudformation:ListStack*",
        "cloudformation:GetStackPolicy",
        "cloudfront:Get*",
        "cloudfront:List*",
        "cloudhsm:ListHapgs",
        "cloudhsm:ListHsms",
        "cloudhsm:ListLunaClients",
        "cloudsearch:DescribeDomains",
        "cloudsearch:DescribeServiceAccessPolicies",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListTags",
        "cloudtrail:LookupEvents",
        "cloudwatch:Describe*",
        "codebuild:ListProjects",
        "codecommit:BatchGetRepositories",
        "codecommit:GetBranch",
        "codecommit:GetObjectIdentifier",
        "codecommit:GetRepository",
        "codecommit:List*",
        "codedeploy:Batch*",
        "codedeploy:Get*",
        "codedeploy:List*",
        "codepipeline:ListPipelines",
        "codestar:Describe*",
        "codestar:List*",
        "cognito-identity:ListIdentityPools",
        "cognito-idp:ListUserPools",
        "cognito-sync:Describe*",
        "cognito-sync:List*",
        "comprehend:Describe*",
        "comprehend:List*",
        "config:BatchGetAggregateResourceConfig",
        "config:BatchGetResourceConfig",
        "config:Deliver*",
        "config:Describe*",
        "config:Get*",
        "config:List*",
        "datapipeline:DescribeObjects",
        "datapipeline:DescribePipelines",
        "datapipeline:EvaluateExpression",
        "datapipeline:GetPipelineDefinition",
        "datapipeline:ListPipelines",
        "datapipeline:QueryObjects",
        "datapipeline:ValidatePipelineDefinition",
        "datasync:Describe*",
        "datasync:List*",
        "dax:Describe*",
        "dax:ListTags",
        "directconnect:Describe*",
        "dms:Describe*",
        "dms:ListTagsForResource",
        "ds:DescribeDirectories",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeGlobalTable",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeTimeToLive",
        "dynamodb:ListBackups",
        "dynamodb:ListGlobalTables",
        "dynamodb:ListStreams",
        "dynamodb:ListTables",
        "ec2:Describe*",
        "ecr:DescribeRepositories",
        "ecr:GetRepositoryPolicy",
        "ecs:Describe*",
        "ecs:List*",
        "eks:DescribeCluster",
        "eks:ListClusters",
        "elasticache:Describe*",
        "elasticbeanstalk:Describe*",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargetSecurityGroups",
        "elasticfilesystem:DescribeMountTargets",
        "elasticloadbalancing:Describe*",
        "elasticmapreduce:Describe*",
        "elasticmapreduce:ListClusters",
        "elasticmapreduce:ListInstances",
        "es:Describe*",
        "es:ListDomainNames",
        "events:Describe*",
        "events:List*",
        "firehose:Describe*",
        "firehose:List*",
        "fms:ListComplianceStatus",
        "fms:ListPolicies",
        "fsx:Describe*",
        "fsx:List*",
        "gamelift:ListBuilds",
        "gamelift:ListFleets",
        "glacier:DescribeVault",
        "glacier:GetVaultAccessPolicy",
        "glacier:ListVaults",
        "globalaccelerator:Describe*",
        "globalaccelerator:List*",
        "greengrass:List*",
        "guardduty:Get*",
        "guardduty:List*",
        "iam:GenerateCredentialReport",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:Get*",
        "iam:List*",
        "iam:SimulateCustomPolicy",
        "iam:SimulatePrincipalPolicy",
        "inspector:Describe*",
        "inspector:Get*",
        "inspector:List*",
        "inspector:Preview*",
        "iot:Describe*",
        "iot:GetPolicy",
        "iot:GetPolicyVersion",
        "iot:List*",
        "kinesis:DescribeStream",
        "kinesis:ListStreams",
        "kinesis:ListTagsForStream",
        "kinesisanalytics:ListApplications",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "lambda:GetAccountSettings",
        "lambda:GetFunctionConfiguration",
        "lambda:GetLayerVersionPolicy",
        "lambda:GetPolicy",
        "lambda:List*",
        "license-manager:List*",
        "lightsail:GetInstances",
        "logs:Describe*",
        "logs:ListTagsLogGroup",
        "machinelearning:DescribeMLModels",
        "mediaconnect:Describe*",
        "mediaconnect:List*",
        "mediastore:GetContainerPolicy",
        "mediastore:ListContainers",
        "opsworks:DescribeStacks",
        "opsworks-cm:DescribeServers",
        "organizations:List*",
        "organizations:Describe*",
        "quicksight:Describe*",
        "quicksight:List*",
        "ram:List*",
        "rds:Describe*",
        "rds:DownloadDBLogFilePortion",
        "rds:ListTagsForResource",
        "redshift:Describe*",
        "rekognition:Describe*",
        "rekognition:List*",
        "robomaker:Describe*",
        "robomaker:List*",
        "route53:Get*",
        "route53:List*",
        "route53domains:GetDomainDetail",
        "route53domains:GetOperationDetail",
        "route53domains:ListDomains",
        "route53domains:ListOperations",
        "route53domains:ListTagsForDomain",
        "route53resolver:List*",
        "s3:GetAccelerateConfiguration",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetAnalyticsConfiguration",
        "s3:GetBucket*",
        "s3:GetEncryptionConfiguration",
        "s3:GetInventoryConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetMetricsConfiguration",
        "s3:GetObjectAcl",
        "s3:GetObjectVersionAcl",
        "s3:GetPublicAccessBlock",
        "s3:GetReplicationConfiguration",
        "s3:ListAllMyBuckets",
        "sagemaker:Describe*",
        "sagemaker:List*",
        "sdb:DomainMetadata",
        "sdb:ListDomains",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:ListSecrets",
        "secretsmanager:ListSecretVersionIds",
        "securityhub:Get*",
        "securityhub:List*",
        "serverlessrepo:GetApplicationPolicy",
        "serverlessrepo:List*",
        "ses:GetIdentityDkimAttributes",
        "ses:GetIdentityVerificationAttributes",
        "ses:ListIdentities",
        "ses:ListVerifiedEmailAddresses",
        "shield:Describe*",
        "shield:List*",
        "snowball:ListClusters",
        "snowball:ListJobs",
        "sns:GetTopicAttributes",
        "sns:ListSubscriptionsByTopic",
        "sns:ListTopics",
        "sqs:GetQueueAttributes",
        "sqs:ListDeadLetterSourceQueues",
        "sqs:ListQueues",
        "sqs:ListQueueTags",
        "ssm:Describe*",
        "ssm:ListDocuments",
        "sso:DescribePermissionsPolicies",
        "sso:List*",
        "states:ListStateMachines",
        "storagegateway:DescribeBandwidthRateLimit",
        "storagegateway:DescribeCache",
        "storagegateway:DescribeCachediSCSIVolumes",
        "storagegateway:DescribeGatewayInformation",
        "storagegateway:DescribeMaintenanceStartTime",
        "storagegateway:DescribeNFSFileShares",
        "storagegateway:DescribeSnapshotSchedule",
        "storagegateway:DescribeStorediSCSIVolumes",
        "storagegateway:DescribeTapeArchives",
        "storagegateway:DescribeTapeRecoveryPoints",
        "storagegateway:DescribeTapes",
        "storagegateway:DescribeUploadBuffer",
        "storagegateway:DescribeVTLDevices",
        "storagegateway:DescribeWorkingStorage",
        "storagegateway:List*",
        "tag:GetResources",
        "tag:GetTagKeys",
        "transfer:Describe*",
        "transfer:List*",
        "translate:List*",
        "trustedadvisor:Describe*",
        "waf:ListWebACLs",
        "waf-regional:ListWebACLs",
        "workspaces:Describe*"
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

### Additional Permissions

These permissions extend those included in the `SecurityAudit` Managed Policy.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "athena:BatchGet*",
        "athena:Get*",
        "athena:List*",
        "batch:Describe*",
        "batch:List*",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "ecs:List*",
        "eks:DescribeCluster",
        "eks:ListClusters",
        "elasticache:Describe*",
        "elasticache:List*",
        "elasticmapreduce:Describe*",
        "elasticmapreduce:List*",
        "es:Describe*",
        "es:List*",
        "glue:Get*",
        "inspector:Describe*",
        "inspector:Get*",
        "inspector:List*",
        "kinesis:Describe*",
        "kinesis:List*",
        "waf:List*",
        "waf:Get*"
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
        "athena:BatchGet*",
        "athena:Get*",
        "athena:List*",
        "batch:Describe*",
        "batch:List*",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "ecs:List*",
        "eks:DescribeCluster",
        "eks:ListClusters",
        "elasticache:Describe*",
        "elasticache:List*",
        "elasticmapreduce:Describe*",
        "elasticmapreduce:List*",
        "es:Describe*",
        "es:List*",
        "glue:Get*",
        "inspector:Describe*",
        "inspector:Get*",
        "inspector:List*",
        "kinesis:Describe*",
        "kinesis:List*",
        "waf:List*",
        "waf:Get*"
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
    `SecurityAudit` and `JupiterOneSecurityAudit` policies. `SecurityAudit` is
    an AWS-managed IAM policy.

1.  With both policies selected, click **Next: Review**.

1.  Enter `JupiterOne` as the **Role Name**, and optionally, enter a description
    for the Role.

1.  Click **Create Role**.

1.  In the list of Roles, search for and select the newly created `JupiterOne`
    role, and copy the **Role ARN**. It should be in a format that looks like
    `arn:aws:iam::<your_aws_account_id>:role/JupiterOne`.
