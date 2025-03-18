resource "aws_iam_role" "jupiterone" {
  name = "JupiterOne"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::612791702201:root","arn:aws:iam::592277296164:root","arn:aws:iam::543056157939:root","arn:aws:iam::688694159727:root","arn:aws:iam::248422699954:root","arn:aws:iam::703115985002:root"]
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
  value = "${aws_iam_role.jupiterone.arn}"
}

resource "aws_iam_policy" "jupiterone_security_audit_policy" {
  name = "JupiterOneSecurityAudit"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": [
        "arn:aws:apigateway:*::/restapis",
        "arn:aws:apigateway:*::/restapis/*/authorizers",
        "arn:aws:apigateway:*::/restapis/*/authorizers/*",
        "arn:aws:apigateway:*::/restapis/*/resources",
        "arn:aws:apigateway:*::/restapis/*/resources/*",
        "arn:aws:apigateway:*::/domainnames",
        "arn:aws:apigateway:*::/restapis/*/resources/*/methods/*",
        "arn:aws:apigateway:*::/restapis/*/stages",
        "arn:aws:apigateway:*::/restapis/*/stages/*",
        "arn:aws:apigateway:*::/apis",
        "arn:aws:apigateway:*::/apis/*/integrations",
        "arn:aws:apigateway:*::/apis/*/authorizers",
        "arn:aws:apigateway:*::/apis/*/routes"
      ],
      "Action": "apigateway:GET"
    },
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",
        "account:GetAlternateContact",
        "acm-pca:ListCertificateAuthorities",
        "acm-pca:ListTags",
        "acm:DescribeCertificate",
        "acm:ListCertificates",
        "acm:ListTagsForCertificate",
        "airflow:GetEnvironment",
        "airflow:ListEnvironments",
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeLaunchConfigurations",
        "autoscaling:DescribePolicies",
        "backup:GetBackupVaultAccessPolicy",
        "backup:ListBackupJobs",
        "backup:ListBackupPlans",
        "backup:ListBackupVaults",
        "backup:ListCopyJobs",
        "backup:ListRecoveryPointsByBackupVault",
        "backup:ListRestoreJobs",
        "backup:ListRestoreTestingPlans",
        "batch:DescribeComputeEnvironments",
        "batch:DescribeJobDefinitions",
        "batch:DescribeJobQueues",
        "batch:ListJobs",
        "cloudformation:DescribeStacks",
        "cloudformation:ListStacks",
        "cloudfront:GetDistributionConfig",
        "cloudfront:ListDistributions",
        "cloudfront:ListKeyGroups",
        "cloudfront:ListPublicKeys",
        "cloudfront:ListTagsForResource",
        "cloudhsm:DescribeBackups",
        "cloudhsm:DescribeClusters",
        "cloudhsm:ListTags",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:GetMetricData",
        "cloudwatch:ListTagsForResource",
        "codebuild:BatchGetProjects",
        "codebuild:BatchGetReportGroups",
        "codebuild:GetResourcePolicy",
        "codebuild:ListProjects",
        "codebuild:ListReportGroups",
        "codecommit:GetRepository",
        "codecommit:ListRepositories",
        "codecommit:ListTagsForResource",
        "codepipeline:ListPipelines",
        "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUserPools",
        "config:DescribeComplianceByConfigRule",
        "config:DescribeConfigRules",
        "config:GetComplianceDetailsByConfigRule",
        "dax:DescribeClusters",
        "directconnect:DescribeConnections",
        "directconnect:DescribeDirectConnectGateways",
        "directconnect:DescribeLags",
        "directconnect:DescribeVirtualInterfaces",
        "dms:DescribeEndpoints",
        "dms:DescribeReplicationInstances",
        "dms:ListTagsForResource",
        "ds:DescribeDirectories",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeGlobalTable",
        "dynamodb:DescribeTable",
        "dynamodb:ListBackups",
        "dynamodb:ListGlobalTables",
        "dynamodb:ListTables",
        "dynamodb:ListTagsOfResource",
        "ec2:DescribeAddresses",
        "ec2:DescribeCustomerGateways",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeIamInstanceProfileAssociations",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeInstances",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions",
        "ec2:DescribeManagedPrefixLists",
        "ec2:DescribeNatGateways",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRegions",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshotAttribute",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeTransitGatewayVpcAttachments",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcEndpointConnections",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcEndpointServiceConfigurations",
        "ec2:DescribeVpcEndpointServicePermissions",
        "ec2:DescribeVpcEndpointServices",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpnConnections",
        "ec2:DescribeVpnGateways",
        "ec2:GetEbsDefaultKmsKeyId",
        "ec2:GetEbsEncryptionByDefault",
        "ec2:GetManagedPrefixListEntries",
        "ecr:DescribeImages",
        "ecr:DescribeImageScanFindings",
        "ecr:DescribeRepositories",
        "ecr:GetLifecyclePolicy",
        "ecr:GetRepositoryPolicy",
        "ecr:ListTagsForResource",
        "ecs:DescribeClusters",
        "ecs:DescribeContainerInstances",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "ecs:DescribeTasks",
        "ecs:ListClusters",
        "ecs:ListContainerInstances",
        "ecs:ListServices",
        "ecs:ListTaskDefinitionFamilies",
        "ecs:ListTasks",
        "eks:DescribeCluster",
        "eks:DescribeNodegroup",
        "eks:ListClusters",
        "eks:ListNodegroups",
        "elasticache:DescribeCacheClusters",
        "elasticache:DescribeCacheSubnetGroups",
        "elasticache:DescribeReplicationGroups",
        "elasticache:DescribeSnapshots",
        "elasticache:ListTagsForResource",
        "elasticfilesystem:DescribeFileSystemPolicy",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:DescribeMountTargetSecurityGroups",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeRules",
        "elasticloadbalancing:DescribeTags",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticmapreduce:DescribeCluster",
        "elasticmapreduce:ListClusters",
        "elasticmapreduce:ListInstances",
        "es:DescribeElasticsearchDomains",
        "es:ListDomainNames",
        "es:ListTags",
        "events:ListRules",
        "events:ListTagsForResource",
        "events:ListTargetsByRule",
        "firehose:DescribeDeliveryStream",
        "firehose:ListDeliveryStreams",
        "firehose:ListTagsForDeliveryStream",
        "fms:ListAppsLists",
        "fms:ListPolicies",
        "fms:ListProtocolsLists",
        "fms:ListResourceSetResources",
        "fms:ListResourceSets",
        "fms:ListTagsForResource",
        "glacier:GetVaultAccessPolicy",
        "glacier:GetVaultLock",
        "glacier:ListTagsForVault",
        "glacier:ListVaults",
        "globalaccelerator:ListAccelerators",
        "globalaccelerator:ListCustomRoutingAccelerators",
        "globalaccelerator:ListCustomRoutingEndpointGroups",
        "globalaccelerator:ListCustomRoutingListeners",
        "globalaccelerator:ListEndpointGroups",
        "globalaccelerator:ListListeners",
        "globalaccelerator:ListTagsForResource",
        "glue:GetConnection",
        "glue:GetConnections",
        "glue:GetDatabase",
        "glue:GetDatabases",
        "glue:GetDataCatalogEncryptionSettings",
        "glue:GetDevEndpoint",
        "glue:GetDevEndpoints",
        "glue:GetJob"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "jupiterone_security_audit_policy_attachment" {
  role       = "${ aws_iam_role.jupiterone.name }"
  policy_arn = "${ aws_iam_policy.jupiterone_security_audit_policy.arn }"
}
resource "aws_iam_policy" "jupiterone_security_audit_policy_2" {
  name = "JupiterOneSecurityAudit2"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "glue:GetResourcePolicy",
        "glue:GetSecurityConfigurations",
        "glue:GetTags",
        "glue:ListJobs",
        "glue:ListSessions",
        "guardduty:GetDetector",
        "guardduty:GetFindings",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "health:DescribeEventDetails",
        "health:DescribeEvents",
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
        "iam:GetServerCertificate",
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
        "iam:ListServerCertificates",
        "iam:ListUserPolicies",
        "iam:ListUsers",
        "iam:ListUserTags",
        "identitystore:ListGroupMemberships",
        "identitystore:ListGroups",
        "identitystore:ListUsers",
        "inspector:DescribeAssessmentRuns",
        "inspector:DescribeFindings",
        "inspector:DescribeRulesPackages",
        "inspector:ListAssessmentRuns",
        "inspector:ListFindings",
        "inspector2:ListCoverage",
        "inspector2:ListFindings",
        "kafka:GetBootstrapBrokers",
        "kafka:ListClustersV2",
        "kafka:ListTagsForResource",
        "kinesis:DescribeStreamSummary",
        "kinesis:ListStreamConsumers",
        "kinesis:ListStreams",
        "kinesis:ListTagsForStream",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListKeys",
        "lambda:GetFunction",
        "lambda:GetFunctionUrlConfig",
        "lambda:GetPolicy",
        "lambda:ListFunctions",
        "lambda:ListTags",
        "lex:DescribeResourcePolicy",
        "lex:ListBotAliases",
        "lex:ListBots",
        "logs:DescribeDestinations",
        "logs:DescribeLogGroups",
        "logs:DescribeSubscriptionFilters",
        "logs:ListTagsLogGroup",
        "macie2:GetFindings",
        "macie2:ListFindings",
        "mq:DescribeBroker",
        "mq:ListBrokers",
        "network-firewall:DescribeFirewall",
        "network-firewall:DescribeFirewallPolicy",
        "network-firewall:DescribeRuleGroup",
        "network-firewall:ListFirewallPolicies",
        "network-firewall:ListFirewalls",
        "network-firewall:ListRuleGroups",
        "organizations:DescribeAccount",
        "organizations:DescribeOrganization",
        "organizations:DescribeOrganizationalUnit",
        "organizations:DescribePolicy",
        "organizations:ListAccounts",
        "organizations:ListChildren",
        "organizations:ListPolicies",
        "organizations:ListRoots",
        "organizations:ListTagsForResource",
        "organizations:ListTargetsForPolicy",
        "quicksight:DescribeDashboard",
        "quicksight:DescribeDataSet",
        "quicksight:DescribeDataSource",
        "quicksight:DescribeVpcConnection",
        "quicksight:ListDashboards",
        "quicksight:ListDataSets",
        "quicksight:ListDataSources",
        "quicksight:ListVpcConnections",
        "rds:DescribeDBClusterParameterGroups",
        "rds:DescribeDBClusterParameters",
        "rds:DescribeDBClusters",
        "rds:DescribeDBClusterSnapshots",
        "rds:DescribeDBInstances",
        "rds:DescribeDBParameterGroups",
        "rds:DescribeDBParameters",
        "rds:DescribeDBProxies",
        "rds:DescribeDBProxyTargetGroups",
        "rds:DescribeDBProxyTargets",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBSubnetGroups",
        "rds:DescribeOptionGroups",
        "redshift-serverless:ListEndpointAccess",
        "redshift-serverless:ListNamespaces",
        "redshift-serverless:ListRecoveryPoints",
        "redshift-serverless:ListSnapshots",
        "redshift-serverless:ListTagsForResource",
        "redshift-serverless:ListUsageLimits",
        "redshift-serverless:ListWorkgroups",
        "redshift:DescribeClusterParameterGroups",
        "redshift:DescribeClusterParameters",
        "redshift:DescribeClusters",
        "redshift:DescribeLoggingStatus",
        "route53:GetHostedZone",
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets",
        "route53domains:GetDomainDetail",
        "route53domains:ListDomains",
        "route53domains:ListTagsForDomain",
        "route53resolver:ListResolverRuleAssociations",
        "route53resolver:ListResolverRules",
        "route53resolver:ListTagsForResource",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketNotification",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketOwnershipControls",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetBucketWebsite",
        "s3:GetEncryptionConfiguration",
        "s3:GetInventoryConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetReplicationConfiguration",
        "s3:ListAccessPoints",
        "s3:ListAllMyBuckets",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:ListNotebookInstances",
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:ListSecrets",
        "securityhub:DescribeStandards",
        "securityhub:DescribeStandardsControls",
        "securityhub:GetEnabledStandards",
        "securityhub:GetFindings",
        "ses:GetConfigurationSet",
        "ses:GetEmailIdentity",
        "ses:ListConfigurationSets",
        "ses:ListEmailIdentities",
        "ses:ListReceiptFilters",
        "shield:DescribeSubscription",
        "shield:GetSubscriptionState",
        "shield:ListProtectionGroups",
        "shield:ListProtections",
        "shield:ListResourcesInProtectionGroup",
        "shield:ListTagsForResource",
        "signer:ListSigningProfiles",
        "sns:GetSubscriptionAttributes",
        "sns:GetTopicAttributes",
        "sns:ListSubscriptions",
        "sns:ListTagsForResource",
        "sns:ListTopics",
        "sqs:GetQueueAttributes",
        "sqs:ListQueues",
        "sqs:ListQueueTags",
        "ssm:DescribeDocumentPermission",
        "ssm:DescribeInstanceInformation",
        "ssm:DescribeInstancePatchStates",
        "ssm:DescribeParameters",
        "ssm:DescribePatchBaselines",
        "ssm:DescribePatchGroups",
        "ssm:DescribePatchGroupState",
        "ssm:GetDocument",
        "ssm:GetServiceSetting",
        "ssm:ListAssociations",
        "ssm:ListComplianceItems",
        "ssm:ListComplianceSummaries",
        "ssm:ListDocuments",
        "ssm:ListInventoryEntries",
        "ssm:ListTagsForResource",
        "sso:DescribePermissionSet",
        "sso:ListApplications",
        "sso:ListInstances",
        "sso:ListAccountAssignments",
        "sso:ListAccountAssignmentsForPrincipal",
        "sso:ListPermissionSets",
        "tag:GetResources",
        "transfer:DescribeServer",
        "transfer:ListServers",
        "transfer:ListTagsForResource",
        "transfer:ListUsers",
        "waf:GetWebACL",
        "waf:ListWebACLs",
        "wafv2:GetLoggingConfiguration",
        "wafv2:GetWebACL",
        "wafv2:ListResourcesForWebACL"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "jupiterone_security_audit_policy_attachment_3" {
  role       = "${ aws_iam_role.jupiterone.name }"
  policy_arn = "${ aws_iam_policy.jupiterone_security_audit_policy_3.arn }"
}
resource "aws_iam_policy" "jupiterone_security_audit_policy_3" {
  name = "JupiterOneSecurityAudit3"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "wafv2:ListWebACLs",
        "workspaces:DescribeTags",
        "workspaces:DescribeWorkspaceBundles",
        "workspaces:DescribeWorkspaces"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "jupiterone_security_audit_policy_attachment_3" {
  role       = "${ aws_iam_role.jupiterone.name }"
  policy_arn = "${ aws_iam_policy.jupiterone_security_audit_policy_3.arn }"
}