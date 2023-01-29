# jupiterone-aws-cloudformation

This project provides instructions to configure the
[JupiterOne](https://jupiterone.com/) AWS integration. JupiterOne assumes an IAM
Role in the target account that has been granted permission to read information
from AWS services supported by JupiterOne. Configuring the IAM Role can be
accomplished using one of the following methods:

1.  [![Launch JupiterOne IAM CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=jupiterone-integration&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-jupiter-aws-integration%2Fiam-cloudformation.json)
1.  [Launch JupiterOne IAM CloudFormation Stack using the AWS CLI](#iam-cloudformation-with-aws-cli)
1.  [Create a Role using the AWS Management Console](#manual-iam-role-creation-with-aws-management-console)

JupiterOne is also capable of processing CloudTrail events. Sending them to
JupiterOne's AWS account requires an EventBridge event rule, which can be
configured using one of the following methods:

1.  [![Launch JupiterOne EventBridge CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=jupiterone-integration-events&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-jupiter-aws-integration%2Fevents-cloudformation.json)
1.  [Launch JupiterOne EventBridge CloudFormation Stack using the AWS CLI](#events-cloudformation-with-aws-cli)
1.  [Create an EventBridge Rule using the AWS Management Console](#manual-eventbridge-rule-creation-with-aws-management-console)

## IAM

### Supported Services

JupiterOne currently supports the following services:

- AccessAnalyzer
- ACM
- API Gateway
- Autoscaling
- Batch
- CloudFormation
- CloudFront
- CloudHSM
- CloudTrail
- CloudWatch
  - CloudWatch Alarms
  - CloudWatch Events
  - CloudWatch Logs
- CodeCommit
- CodePipeline
- Config
- DynamoDB
- EC2
- ECR
- ECS
- EFS
- EKS
- ELB
- ElastiCache
- ES
- Firewall Manager
- Glue
- Direct Connect
- GuardDuty
- IAM (including IAM Policy analysis)
- Inspector
- Inspector2
- KMS
- Lambda
- Macie
- Organizations
- RDS
- Redshift
  - Redshift Serverless
- Route53
- Route53Domains
- S3 (including Bucket Policy analysis)
- Shield
- SNS
- SQS
- SSM
- Transfer
- VPC (including VPC Peering)
- WAF
- Workspaces

For detailed and specific permissions, see **"Specific Permissions Policy"**
section below.

### IAM Role Permissions

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

#### Additional Permissions

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
        "cloudhsm:DescribeBackups",
        "cloudhsm:DescribeClusters",
        "cloudhsm:ListTags",
        "cloudwatch:GetMetricData",
        "cloudwatch:List*",
        "codecommit:ListRepositories",
        "codecommit:GetRepository",
        "codecommit:ListTagsForResource",
        "codepipeline:List*",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "ec2:GetEbsDefaultKmsKeyId",
        "ec2:GetEbsEncryptionByDefault",
        "ecr:Describe*",
        "ecr:GetLifecyclePolicy",
        "ecr:GetRepositoryPolicy",
        "ecr:List*",
        "elasticache:List*",
        "elasticfilesystem:Describe*",
        "elasticmapreduce:List*",
        "es:List*",
        "directconnect:Describe*",
        "inspector2:ListCoverage",
        "inspector2:ListFindings",
        "kinesis:Describe*",
        "kinesis:List*",
        "lambda:GetFunction",
        "macie2:GetFindings",
        "macie2:ListFindings",
        "s3:GetObjectRetention",
        "s3:GetObjectLegalHold",
        "s3:Get*Configuration",
        "shield:GetSubscriptionState",
        "sns:GetTopicAttributes",
        "sns:GetSubscriptionAttributes",
        "sns:ListTopics",
        "sns:ListSubscriptions",
        "sns:ListTagsForResource",
        "ssm:GetDocument",
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

#### Specific Permissions Policy

This policy may be used to provide only exactly the specific permissions
currently used by JupiterOne. Using this policy will most certainly require you
to update the policy in the future as more APIs are called by JupiterOne.

NOTE: By default, AWS enforces a policy size limit of 6,144 non-whitespace characters. The policy below includes more than 6,144 non-whitespace characters. We recommend you split this document across two different AWS policies in order to stay under the 6,144 non-whitespace character limit. Alternatively, you could request a quota increase from AWS.

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
        "autoscaling:DescribeLaunchConfigurations",
        "autoscaling:DescribePolicies",
        "batch:DescribeComputeEnvironments",
        "batch:DescribeJobDefinitions",
        "batch:DescribeJobQueues",
        "batch:ListJobs",
        "cloudformation:DescribeStacks",
        "cloudfront:ListDistributions",
        "cloudfront:ListTagsForResource",
        "cloudhsm:DescribeBackups",
        "cloudhsm:DescribeClusters",
        "cloudhsm:ListTags",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:GetMetricData",
        "cloudwatch:ListTagsForResource",
        "codecommit:ListRepositories",
        "codecommit:GetRepository",
        "codecommit:ListTagsForResource",
        "codepipeline:ListPipelines",
        "config:DescribeComplianceByConfigRule",
        "config:DescribeConfigRules",
        "config:GetComplianceDetailsByConfigRule",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeTable",
        "dynamodb:ListBackups",
        "dynamodb:ListTables",
        "dynamodb:ListTagsOfResource",
        "ec2:DescribeAddresses",
        "ec2:DescribeCustomerGateways",
        "ec2:DescribeImages",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeLaunchTemplates", 
        "ec2:DescribeNatGateways",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRegions",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshotAttribute",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpnConnections",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpnGateways",
        "ec2:GetEbsDefaultKmsKeyId",
        "ec2:GetEbsEncryptionByDefault",
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
        "ecs:ListClusters",
        "ecs:ListContainerInstances",
        "ecs:ListServices",
        "ecs:ListTagsForResource",
        "ecs:ListTaskDefinitionFamilies",
        "ecs:ListTasks",
        "eks:DescribeCluster",
        "eks:DescribeNodegroup",
        "eks:ListClusters",
        "eks:ListNodegroups",
        "elasticache:DescribeCacheClusters",
        "elasticache:DescribeReplicationGroups",
        "elasticache:DescribeSnapshots",
        "elasticache:ListTagsForResource",
        "elasticfilesystem:DescribeFileSystemPolicy",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargetSecurityGroups",
        "elasticfilesystem:DescribeMountTargets",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTags",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeRules",
        "es:DescribeElasticsearchDomains",
        "es:ListDomainNames",
        "es:ListTags",
        "fms:ListPolicies",
        "fms:ListTagsForResource",
        "fms:ListResourceSets",
        "fms:ListResourceSetResources",
        "fms:ListAppsLists",
        "fms:ListProtocolsLists",
        "glue:ListJobs",
        "glue:GetJob",
        "glue:GetTags",
        "glue:GetDatabases",
        "glue:GetDatabases",
        "glue:GetSecurityConfigurations",
        "directconnect:DescribeConnections",
        "directconnect:DescribeVirtualInterfaces",
        "directconnect:DescribeLags",
        "directconnect:DescribeDirectConnectGateways",
        "directconnect:DescribeVirtualGateways",
        "events:ListRules",
        "events:ListTargetsByRule",
        "events:ListTagsForResource",
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
        "iam:GetOpenIDConnectProvider",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:GetSAMLProvider",
        "iam:GetUser",
        "iam:GetUserPolicy",
        "iam:ListAccessKeys",
        "iam:ListAccountAliases",
        "iam:ListEntitiesForPolicy",
        "iam:ListGroupPolicies",
        "iam:ListGroups",
        "iam:ListInstanceProfiles",
        "iam:ListMFADevices",
        "iam:ListOpenIDConnectProviders",
        "iam:ListOpenIDConnectProviderTags", 
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
        "inspector:DescribeRulesPackages",
        "inspector:ListAssessmentRuns",
        "inspector:ListFindings",
        "inspector2:ListCoverage",
        "inspector2:ListFindings",
        "kinesis:DescribeStreamSummary",
        "kinesis:ListStreamConsumers", 
        "kinesis:ListStreams", 
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListKeys",
        "lambda:GetFunction",
        "lambda:ListFunctions",
        "lambda:ListTags",
        "logs:DescribeLogGroups",
        "logs:ListTagsLogGroup",
        "macie2:GetFindings",
        "macie2:ListFindings",
        "organizations:DescribeOrganization",
        "organizations:ListAccounts",
        "organizations:ListTagsForResource",
        "redshift:DescribeClusters",
        "redshift:DescribeClusterParameters", 
        "redshift:DescribeClusterParameterGroups", 
        "redshift:DescribeLoggingStatus", 
        "redshift-serverless:ListUsageLimits",
        "redshift-serverless:ListNamespaces",
        "redshift-serverless:ListWorkgroups",
        "redshift-serverless:ListTagsForResource",
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
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketOwnershipControls",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetInventoryConfiguration",
        "s3:GetReplicationConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketNotification",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:ListAllMyBuckets", 
        "shield:DescribeSubscription",
        "shield:GetSubscriptionState",
        "shield:ListResourcesInProtectionGroup",
        "shield:ListProtectionGroups",
        "shield:ListProtections",
        "shield:ListTagsForResource",
        "sns:GetTopicAttributes",
        "sns:GetSubscriptionAttributes",
        "sns:ListTopics",
        "sns:ListSubscriptions",
        "sns:ListTagsForResource",
        "sqs:GetQueueAttributes",
        "sqs:ListQueues",
        "sqs:ListQueueTags",
        "ssm:DescribePatchGroupState", 
        "ssm:DescribeParameters", 
        "ssm:DescribePatchBaselines", 
        "ssm:DescribePatchGroups", 
        "ssm:DescribeInstancePatchStates", 
        "ssm:DescribeInstanceInformation", 
        "ssm:ListInventoryEntries",
        "ssm:GetDocument",
        "tag:GetResources",
        "transfer:ListServers",
        "transfer:ListTagsForResource",
        "transfer:ListUsers",
        "waf:GetWebACL",
        "waf:ListWebACLs",
        "wafv2:GetWebACL",
        "wafv2:ListWebACLs",
        "wafv2:ListResourcesForWebACL",
        "workspaces:DescribeWorkspaces",
        "workspaces:DescribeWorkspaceBundles"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "apigateway:GET",
      "Resource": [
        "arn:aws:apigateway:*::/apis",
        "arn:aws:apigateway:*::/apis/*/integrations",
        "arn:aws:apigateway:*::/apis/*/authorizers",
        "arn:aws:apigateway:*::/apis/*/routes",
        "arn:aws:apigateway:*::/domainnames",
        "arn:aws:apigateway:*::/restapis",
        "arn:aws:apigateway:*::/restapis/*/authorizers",
        "arn:aws:apigateway:*::/restapis/*/authorizers/*",
        "arn:aws:apigateway:*::/restapis/*/resources",
        "arn:aws:apigateway:*::/restapis/*/resources/*"
      ]
    }
  ]
}
```

> Notes:
>
> - `cloudwatch:GetMetricData` permission is only used to obtain
>   `BucketSizeBytes` and `NumberOfObjects` metrics data for S3 buckets.

### IAM CloudFormation with AWS CLI

```bash
aws cloudformation create-stack --stack-name JupiterOneIntegration --capabilities CAPABILITY_NAMED_IAM --template-url https://s3.amazonaws.com/jupiterone-prod-us-jupiter-aws-integration/iam-cloudformation.json
```

### Manual IAM Role Creation with AWS Management Console

From your AWS Management Console, perform the following steps:

1.  Go to **IAM** > **Roles** and click **Create Role**.

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
            "access-analyzer:List*",
            "batch:Describe*",
            "batch:List*",
            "cloudhsm:DescribeBackups",
            "cloudhsm:DescribeClusters",
            "cloudhsm:ListTags",
            "cloudwatch:GetMetricData",
            "cloudwatch:List*",
            "dynamodb:Describe*",
            "dynamodb:List*",
            "ecr:Describe*",
            "ecr:GetLifecyclePolicy",
            "ecr:GetRepositoryPolicy",
            "ecr:List*",
            "elasticache:List*",
            "elasticfilesystem:Describe*",
            "elasticmapreduce:List*",
            "es:List*",
            "kinesis:Describe*",
            "kinesis:List*",
            "lambda:GetFunction",
            "macie2:GetMacieSession",
            "macie2:GetFindings",
            "macie2:ListFindings",
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

## Events

### Supported Events

JupiterOne currently supports the following events:

### S3

| Event Name                      | Modified Entities `_type` | Modified Relationships `_type`             |
| ------------------------------- | ------------------------- | ------------------------------------------ |
| CreateBucket                    | `aws_s3_bucket`           |                                            |
| PutBucketAcl                    | `aws_s3_bucket`           | `aws_s3_bucket_grant`                      |
| PutBucketEncryption             | `aws_s3_bucket`           |                                            |
| DeleteBucketEncryption          | `aws_s3_bucket`           |                                            |
| PutBucketInventoryConfiguration | `aws_s3_bucket`           | `aws_s3_bucket_publishes_inventory_report` |
| PutBucketLifecycle              | `aws_s3_bucket`           |                                            |
| PutBucketLogging                | `aws_s3_bucket`           |                                            |
| PutBucketPolicy                 | `aws_s3_bucket_policy`    | `aws_s3_bucket_has_policy`                 |
| PutBucketReplication            | `aws_s3_bucket`           |                                            |
| PutBucketTagging                | `aws_s3_bucket`           |                                            |
| PutBucketVersioning             | `aws_s3_bucket`           |                                            |
| PutObjectLockConfiguration      | `aws_s3_bucket`           |                                            |
| PutPublicAccessBlock            | `aws_s3_bucket`           |                                            |

### IAM

| Event Name      | Modified Entities `_type` | Modified Relationships `_type` |
| --------------- | ------------------------- | ------------------------------ |
| CreateAccessKey | `aws_iam_access_key`      |                                |
| CreateGroup     | `aws_iam_group`           |                                |
| CreatePolicy    | `aws_iam_policy`          |                                |
| CreateRole      | `aws_iam_role`            |                                |
| CreateUser      | `aws_iam_user`            |                                |

### EC2

| Event Name         | Modified Entities `_type` | Modified Relationships `_type` |
| ------------------ | ------------------------- | ------------------------------ |
| RunInstances       | `aws_instance`            |                                |
| StartInstances     | `aws_instance`            |                                |
| StopInstances      | `aws_instance`            |                                |
| TerminateInstances | `aws_instance`            |                                |

### AutoScaling

| Event Name             | Modified Entities `_type` | Modified Relationships `_type`                                                                                                                                                                               |
| ---------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CreateAutoScalingGroup | `aws_autoscaling_group`   | `aws_autoscaling_has_aws_autoscaling_group` `aws_autoscaling_group_uses_launch_template` `aws_autoscaling_group_has_instance` `aws_autoscaling_group_uses_launch_config` `aws_autoscaling_group_uses_policy` |
| UpdateAutoScalingGroup | `aws_autoscaling_group`   |                                                                                                                                                                                                              |
| DeleteAutoScalingGroup | `aws_autoscaling_group`   |                                                                                                                                                                                                              |

The following events are next on our roadmap:

- S3
  - DeleteBucket
  - DeleteBucketLifecycle
  - DeleteBucketPolicy
  - DeleteBucketReplication
  - DeleteBucketTagging
- IAM
  - AddRoleToInstanceProfile
  - AddUserToGroup
  - AttachGroupPolicy
  - AttachRolePolicy
  - AttachUserPolicy
  - ChangePassword
  - CreateInstanceProfile
  - CreateLoginProfile
  - CreatePolicyVersion
  - CreateSAMLProvider
  - CreateServiceLinkedRole
  - CreateVirtualMFADevice
  - DeactivateMFADevice
  - DeleteAccessKey
  - DeleteAccountPasswordPolicy
  - DeleteGroup
  - DeleteGroupPolicy
  - DeleteInstanceProfile
  - DeleteLoginProfile
  - DeletePolicy
  - DeletePolicyVersion
  - DeleteRole
  - DeleteRolePolicy
  - DeleteSAMLProvider
  - DeleteServiceLinkedRole
  - DeleteUser
  - DeleteUserPolicy
  - DeleteVirtualMFADevice
  - DetachGroupPolicy
  - DetachRolePolicy
  - DetachUserPolicy
  - EnableMFADevice
  - PutGroupPolicy
  - PutRolePolicy
  - PutUserPolicy
  - RemoveRoleFromInstanceProfile
  - RemoveUserFromGroup
  - SetDefaultPolicyVersion
  - TagRole
  - TagUser
  - UntagRole
  - UntagUser
  - UpdateAccessKey
  - UpdateAccountPasswordPolicy
  - UpdateAssumeRolePolicy
  - UpdateGroup
  - UpdateLoginProfile
  - UpdateRole
  - UpdateRoleDescription
  - UpdateSAMLProvider
  - UpdateUser

### Events CloudFormation with AWS CLI

```bash
aws cloudformation create-stack --stack-name JupiterOneIntegrationEvents --template-url https://s3.amazonaws.com/jupiterone-prod-us-jupiter-aws-integration/events-cloudformation.json
```

### Manual EventBridge Rule Creation with AWS Management Console

From your AWS Management Console, perform the following steps:

1.  Go to **Amazon EventBridge** > **Rules** and, with the default event bus
    selected, click **Create rule**.

1.  Enter the following values:

    - Name: `jupiterone-cloudtrail-events`
    - Description: `Send CloudTrail Events to JupiterOne`

1.  In the **Define pattern** section, select **Event pattern** and then
    **Custom pattern**. Copy the
    `Resources.JupiterOneCloudTrailEventsRule.Properties.EventPattern` object
    from `cloudformation/events-cloudformation.json` into the text field. It
    should look something like this:

    ```json
    {
      "source": ["aws.s3", "aws.iam", "aws.ec2", "...more sources..."],
      "detail-type": ["AWS API Call via CloudTrail"],
      "detail": {
        "eventSource": [
          "s3.amazonaws.com",
          "iam.amazonaws.com",
          "ec2.amazonaws.com",
          "...more sources..."
        ],
        "eventName": ["...event names here..."]
      }
    }
    ```

1.  In the **Select targets** section, select **Event bus in another AWS
    account**. For the **Event Bus** field, enter
    `arn:aws:events:us-east-1:612791702201:event-bus/jupiter-integration-aws`.
    For the role, select **Use existing role** but do not select a role.

1.  Click **Create**.

[1]: https://console.aws.amazon.com/iam/home#policies/arn:aws:iam::aws:policy/SecurityAudit
