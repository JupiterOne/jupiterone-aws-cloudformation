# jupiterone-aws-cloudformation

This project provides instructions to configure the
[JupiterOne](https://jupiterone.com/) AWS integration. JupiterOne assumes an IAM
Role in the target account that has been granted permission to read information
from AWS services supported by JupiterOne. Configuring the IAM Role can be
accomplished using one of the following methods:

1.  [![Launch JupiterOne IAM CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?stackName=JupiterOneIntegration&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-aws-cloudformation-templates%2Fcloudformation.json)
2.  [Launch JupiterOne IAM CloudFormation Stack using the AWS CLI](#iam-cloudformation-with-aws-cli)
3.  [Create a Role using the AWS Management Console](#manual-iam-role-creation-with-aws-management-console)

Connecting a whole AWS Organization (the **Configure Organization Accounts**
option in JupiterOne)? Use the [AWS Organizations](#aws-organizations) setup
instead: it creates the role with the same name in every account, including the
management account.

JupiterOne is also capable of processing CloudTrail events. Sending them to
JupiterOne's AWS account requires an EventBridge event rule, which can be
configured using one of the following methods:

1.  [![Launch JupiterOne EventBridge CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?stackName=jupiterone-integration-events&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-aws-cloudformation-templates%2Fevents-cloudformation.json)
2.  [Launch JupiterOne EventBridge CloudFormation Stack using the AWS CLI](#events-cloudformation-with-aws-cli)
3.  [Create an EventBridge Rule using the AWS Management Console](#manual-eventbridge-rule-creation-with-aws-management-console)

## IAM

### Supported Services

JupiterOne currently supports the following services:

- AccessAnalyzer
- ACM
- API Gateway
  - API Gateway v1
  - API Gateway v2
- Autoscaling
- Backup
- Batch
- CloudFormation
- CloudFront
- CloudHSM
- CloudTrail
- CloudWatch
  - CloudWatch Alarms
  - CloudWatch Events
  - CloudWatch Logs
- CodeBuild
- CodeCommit
- CodePipeline
- Config
- DirectConnect
- DynamoDB
- EC2
- ECR
- ECS
- EFS
- EKS
- ElastiCache
- ELB
- EMR
- ES
- Firehose
- Firewall Manager
- Global Accelerator
- Glue
- GuardDuty
- IAM (including IAM Policy analysis)
- Inspector
- Inspector2
- Kinesis
- KMS
- Lambda
- Lex v2
- Macie 2
- Network Firewall
- Organizations
- RDS
- Redshift
  - Redshift Serverless
- Route53
  - Route53 Domains
- S3 (including Bucket Policy analysis)
  - S3 Glacier
- Secrets Manager
- SES
- Shield
- SNS
- SQS
- SSM
- Transfer
- VPC (including VPC Peering)
- WAF
- WAF v2
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

[Link to Additional Permissions Policy](cloudformation/iam-cloudformation/managed-policy.md)

[![Launch JupiterOne IAM CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?stackName=JupiterOneIntegration&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-aws-cloudformation-templates%2Fcloudformation.json)

#### Specific Permissions Policy

This policy may be used to provide only exactly the specific permissions
currently used by JupiterOne. Using this policy will most certainly require you
to update the policy in the future as more APIs are called by JupiterOne.

NOTE: By default, AWS enforces a policy size limit of 6,144 non-whitespace characters. The policy below has been split into multiple statements to
stay under the 6,144 non-whitespace character limit. If you have requested a quote increase from AWS, you may be able to consolidate these policies.

[Link to Specific Permissions Policy](cloudformation/iam-cloudformation-detailed/managed-policy.md)

[![Launch JupiterOne IAM CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?stackName=JupiterOneIntegration&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-aws-cloudformation-templates%2Fcloudformation-detailed.json)

### AWS Organizations

When **Configure Organization Accounts** is enabled, JupiterOne creates an
integration for every member account and assumes the role **with the same name
and External ID** as the management account's role. The role therefore has to
exist, with an identical name, in the management account _and_ in every member
account.

Use the [organization template](cloudformation/iam-cloudformation-organization/cloudformation-template.json)
for both steps below. Unlike the single-account template, it names the role
from the `JupiterOneRoleName` parameter (default `JupiterOne`) instead of
letting CloudFormation generate a name such as
`JupiterOneIntegration-JupiterOneRole-A1B2C3D4E5F6`, which can never match
across accounts.

Template URL:
`https://jupiterone-prod-us-aws-cloudformation-templates.s3.amazonaws.com/iam-cloudformation-organization.json`

Use the External ID and JupiterOne AWS account ARNs shown in JupiterOne when
you create the integration. They differ by region (for example, EU accounts
must trust `arn:aws:iam::043196788006:root`), so don't rely on the template
defaults.

#### 1. Member accounts: StackSet

Create a StackSet with **service-managed permissions** from the management
account (or a delegated administrator), targeting your organization root or
the OUs you want to monitor. Service-managed StackSets require
[trusted access with AWS Organizations](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-activate-trusted-access.html)
to be activated.

```bash
aws cloudformation create-stack-set \
  --stack-set-name JupiterOneIntegration \
  --template-url https://jupiterone-prod-us-aws-cloudformation-templates.s3.amazonaws.com/iam-cloudformation-organization.json \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=JupiterOneExternalId,ParameterValue=<external-id> \
    ParameterKey=JupiterOneAwsAccountArns,ParameterValue='"<jupiterone-account-arns>"' \
    ParameterKey=JupiterOneRoleName,ParameterValue=JupiterOne

aws cloudformation create-stack-instances \
  --stack-set-name JupiterOneIntegration \
  --deployment-targets OrganizationalUnitIds=<root-or-ou-id> \
  --regions us-east-1
```

From a delegated administrator account, add `--call-as DELEGATED_ADMIN` to
both commands.

Deploy to **one region only**. IAM roles and policies are global, so a second
region fails with "already exists".

#### 2. Management account: regular stack

AWS never deploys service-managed StackSet instances to the management
account, even when you target the organization root
([AWS docs](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-associate-stackset-with-org.html)).
Create the role there with a regular stack named `JupiterOneOrganization`,
using **the same template and the same parameter values**. Don't name it
`JupiterOneIntegration`: that's the single-account stack name, and creating a
stack with a name that already exists fails.

```bash
aws cloudformation create-stack \
  --stack-name JupiterOneOrganization \
  --template-url https://jupiterone-prod-us-aws-cloudformation-templates.s3.amazonaws.com/iam-cloudformation-organization.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=JupiterOneExternalId,ParameterValue=<external-id> \
    ParameterKey=JupiterOneAwsAccountArns,ParameterValue='"<jupiterone-account-arns>"' \
    ParameterKey=JupiterOneRoleName,ParameterValue=JupiterOne
```

#### 3. In JupiterOne

Configure the AWS integration with the management account's role ARN (the
stack's `RoleARN` output, for example
`arn:aws:iam::<management-account-id>:role/JupiterOne`) and enable
**Configure Organization Accounts**.

If an account already has an IAM role named `JupiterOne` (for example, created
manually), the stack fails with "already exists". Either delete that role or
set `JupiterOneRoleName` to another name, the same in every account.

If the management account already has the single-account stack (usually named
`JupiterOneIntegration`), keep it while you set up the organization: its role
name ends in random characters, so it doesn't conflict with the `JupiterOne`
role, and the `JupiterOneOrganization` stack has a different name. Once the
integration uses the new role ARN, delete the old stack.

### IAM CloudFormation with AWS CLI

```bash
aws cloudformation create-stack --stack-name JupiterOneIntegration --capabilities CAPABILITY_NAMED_IAM --template-url https://s3.amazonaws.com/jupiterone-prod-us-aws-cloudformation-templates/cloudformation.json
```

### Manual IAM Role Creation with AWS Management Console

From your AWS Management Console, perform the following steps:

1.  Go to **IAM** > **Roles** and click **Create Role**.

2.  Select **Another AWS account** under **Select type of trusted entity**.

3.  Enter the following **Account ID**: `<jupiterone_account_id>`

4.  Select **Require external ID** and enter the following **External ID**:
    `<jupiterone_external_id>`

5.  Leave **Require MFA** unchecked and click **Next: Permissions**.

6.  Click **Create Policy**, select the **JSON** tab, and enter the document content found here: [Link to Additional Permissions Policy](cloudformation/iam-cloudformation/managed-policy.md)

7.  Click **Review Policy** and verify the permissions.

8.  Enter `JupiterOneSecurityAudit` as the **Name** and click **Create Policy**.

9.  Return to the **Create Role** tab in your browser. Click the Policy table's
    **Refresh Icon**.

10. In the Policy search box, search for `SecurityAudit`. Select both
    `SecurityAudit` and `JupiterOneSecurityAudit` policies. [SecurityAudit][1]
    is an AWS-managed IAM policy.

11. With both policies selected, click **Next: Review**.

12. Enter `JupiterOne` as the **Role Name**, and optionally, enter a description
    for the Role.

13. Click **Create Role**.

14. In the list of Roles, search for and select the newly created `JupiterOne`
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

| Event Name                    | Modified Entities `_type` | Modified Relationships `_type`                                                                                                                                                                             |
| ----------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RunInstances                  | `aws_instance`            | `aws_ec2_has_aws_instance` `aws_instance_uses_ami` `aws_instance_uses_key_pair` `aws_instance_uses_eni` `aws_resource_has_security_group` `aws_security_group_protects_resource` `aws_subnet_has_instance` |
| StartInstances                | `aws_instance`            |                                                                                                                                                                                                            |
| StopInstances                 | `aws_instance`            |                                                                                                                                                                                                            |
| TerminateInstances            | `aws_instance`            |                                                                                                                                                                                                            |
| ModifyInstanceAttribute       | `aws_instance`            | `aws_resource_has_security_group` `aws_security_group_protects_resource`                                                                                                                                   |
| CreateFleet                   | `aws_instance`            | `aws_ec2_has_aws_instance` `aws_instance_uses_ami` `aws_instance_uses_key_pair` `aws_instance_uses_eni` `aws_resource_has_security_group` `aws_security_group_protects_resource` `aws_subnet_has_instance` |
| CreateSecurityGroup           | `aws_security_group`      | `aws_ec2_has_aws_security_group`                                                                                                                                                                           |
| DeleteSecurityGroup           | `aws_security_group`      |                                                                                                                                                                                                            |
| AuthorizeSecurityGroupIngress |                           | `aws_security_group_rule`                                                                                                                                                                                  |
| RevokeSecurityGroupIngress    |                           | `aws_security_group_rule`                                                                                                                                                                                  |
| AuthorizeSecurityGroupEgress  |                           | `aws_security_group_rule`                                                                                                                                                                                  |
| RevokeSecurityGroupEgress     |                           | `aws_security_group_rule`                                                                                                                                                                                  |
| CreateImage                   | `aws_ami`                 | `aws_ami_contains_snapshot`                                                                                                                                                                                |
| RegisterImage                 | `aws_ami`                 | `aws_ami_contains_snapshot`                                                                                                                                                                                |
| ModifyImageAttribute          | `aws_ami`                 |                                                                                                                                                                                                            |
| DeregisterImage               | `aws_ami`                 |                                                                                                                                                                                                            |
| CreateSnapshot                | `aws_ebs_snapshot`        | `aws_ebs_volume_snapshot`                                                                                                                                                                                  |
| CreateSnapshots               | `aws_ebs_snapshot`        | `aws_ebs_volume_snapshot`                                                                                                                                                                                  |
| ModifySnapshotAttribute       | `aws_ebs_snapshot`        |                                                                                                                                                                                                            |
| DeleteSnapshot                | `aws_ebs_snapshot`        |                                                                                                                                                                                                            |

### Elastic Load Balancing (ELB)

| Event Name         | Modified Entities `_type`     | Modified Relationships `_type`                                                                                                                                                                                            |
| ------------------ | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CreateLoadBalancer | `aws_alb` `aws_elb` `aws_nlb` | `aws_elasticloadbalancing_has_aws_alb` `aws_elasticloadbalancing_has_aws_elb` `aws_elasticloadbalancing_has_aws_nlb` `aws_vpc_has_load_balancer` `aws_resource_has_security_group` `aws_security_group_protects_resource` |
| CreateListener     | `aws_lb_listener`             | `aws_load_balancer_has_listener` `aws_lb_listener_uses_acm_certificate` `aws_lb_listener_uses_iam_server_certificate`                                                                                                     |
| CreateTargetGroup  | `aws_lb_target_group`         | `aws_load_balancer_connects_target_group`                                                                                                                                                                                 |
| CreateRule         | `aws_lb_listener_rule`        | `aws_lb_listener_has_rule`                                                                                                                                                                                                |
| SetSecurityGroups  |                               | `aws_resource_has_security_group` `aws_security_group_protects_resource`                                                                                                                                                  |
| RegisterTargets    |                               | `aws_load_balancer_connects_target_group`                                                                                                                                                                                 |

### AutoScaling

| Event Name             | Modified Entities `_type` | Modified Relationships `_type`                                                                                                                                                                               |
| ---------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CreateAutoScalingGroup | `aws_autoscaling_group`   | `aws_autoscaling_has_aws_autoscaling_group` `aws_autoscaling_group_uses_launch_template` `aws_autoscaling_group_has_instance` `aws_autoscaling_group_uses_launch_config` `aws_autoscaling_group_uses_policy` |
| UpdateAutoScalingGroup | `aws_autoscaling_group`   |                                                                                                                                                                                                              |
| DeleteAutoScalingGroup | `aws_autoscaling_group`   |                                                                                                                                                                                                              |

### RDS

| Event Name              | Modified Entities `_type` | Modified Relationships                                                                                                                                                                                                                                                                              |
| ----------------------- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CreateDBInstance        | `aws_db_instance`         | `aws_rds_has_aws_db_instance` `aws_rds_cluster_contains_instance` `aws_rds_parameter_group_in_use` `aws_security_group_protects_resource` `aws_resource_has_security_group` `aws_resource_uses_kms_key` `aws_vpc_has_db_instance` `aws_db_instance_uses_secret` `aws_db_instance_uses_option_group` |
| ModifyDBInstance        | `aws_db_instance`         | `aws_rds_has_aws_db_instance` `aws_rds_cluster_contains_instance` `aws_rds_parameter_group_in_use` `aws_security_group_protects_resource` `aws_resource_has_security_group` `aws_resource_uses_kms_key` `aws_vpc_has_db_instance` `aws_db_instance_uses_secret` `aws_db_instance_uses_option_group` |
| StartDBInstance         | `aws_db_instance`         |                                                                                                                                                                                                                                                                                                     |
| StopDBInstance          | `aws_db_instance`         |                                                                                                                                                                                                                                                                                                     |
| DeleteDBInstance        | `aws_db_instance`         |                                                                                                                                                                                                                                                                                                     |
| CreateDBCluster         | `aws_rds_cluster`         | `aws_rds_has_aws_rds_cluster` `aws_rds_parameter_group_in_use` `aws_security_group_protects_resource` `aws_resource_has_security_group` `aws_resource_uses_kms_key`                                                                                                                                 |
| ModifyDBCluster         | `aws_rds_cluster`         | `aws_rds_has_aws_rds_cluster` `aws_rds_parameter_group_in_use` `aws_security_group_protects_resource` `aws_resource_has_security_group` `aws_resource_uses_kms_key`                                                                                                                                 |
| StartDBCluster          | `aws_rds_cluster`         |                                                                                                                                                                                                                                                                                                     |
| StopDBCluster           | `aws_rds_cluster`         |                                                                                                                                                                                                                                                                                                     |
| DeleteDBCluster         | `aws_rds_cluster`         |                                                                                                                                                                                                                                                                                                     |
| CreateDBSnapshot        | `aws_db_snapshot`         | `aws_db_instance_has_snapshot` `aws_db_snapshot_uses_kms_key`                                                                                                                                                                                                                                       |
| DeleteDBSnapshot        | `aws_db_snapshot`         |                                                                                                                                                                                                                                                                                                     |
| CreateDBClusterSnapshot | `aws_db_cluster_snapshot` | `aws_db_cluster_has_snapshot` `aws_db_cluster_snapshot_uses_kms_key`                                                                                                                                                                                                                                |
| DeleteDBClusterSnapshot | `aws_db_cluster_snapshot` |                                                                                                                                                                                                                                                                                                     |

### Redshift

| Event Name    | Modified Entities `_type` | Modified Relationships `_type`                                                                                                                                                                                          |
| ------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CreateCluster | `aws_redshift_cluster`    | `aws_redshift_has_aws_redshift_cluster` `aws_redshift_cluster_uses_parameter_group` `aws_security_group_protects_resource` `aws_resource_has_security_group` `aws_resource_uses_kms_key` `aws_vpc_has_redshift_cluster` |
| ModifyCluster | `aws_redshift_cluster`    | `aws_redshift_has_aws_redshift_cluster` `aws_redshift_cluster_uses_parameter_group` `aws_security_group_protects_resource` `aws_resource_has_security_group` `aws_resource_uses_kms_key` `aws_vpc_has_redshift_cluster` |
| DeleteCluster | `aws_redshift_cluster`    |                                                                                                                                                                                                                         |

### Events CloudFormation with AWS CLI

```bash
aws cloudformation create-stack --stack-name JupiterOneIntegrationEvents --template-url https://s3.amazonaws.com/jupiterone-prod-us-aws-cloudformation-templates/events-cloudformation.json
```

### Events CloudFormation with AWS Management Console

[![Launch JupiterOne EventBridge CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?stackName=jupiterone-integration-events&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-aws-cloudformation-templates%2Fevents-cloudformation.json)

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
    from `cloudformation/events/cloudformation-template.json` ([Link to EventBridge CloudFormation](cloudformation/events/cloudformation-template.json)) into the text field. It should look something like this:

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
    For the role, select **Create a new role for this specific resource**.

    The role should have be created with a policy which looks like:

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": ["events:PutEvents"],
          "Resource": [
            "arn:aws:events:<TARGET AWS REGION>:<JUPITERONE ACCOUNT ID>:event-bus/jupiter-integration-aws"
          ]
        }
      ]
    }
    ```

    and a trust relationship which looks like:

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "events.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
    ```

1.  Click **Create**.

[1]: https://console.aws.amazon.com/iam/home#policies/arn:aws:iam::aws:policy/SecurityAudit
