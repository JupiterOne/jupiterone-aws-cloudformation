# jupiterone-aws-cloudformation

This project provides instructions to configure the
[JupiterOne](https://jupiterone.com/) AWS integration. JupiterOne assumes an IAM
Role in the target account that has been granted permission to read information
from AWS services supported by JupiterOne. Configuring the IAM Role can be
accomplished using one of the following methods:

1.  [![Launch JupiterOne IAM CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?stackName=JupiterOneIntegration&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-aws-cloudformation-templates%2Fcloudformation.json)
2.  [Launch JupiterOne IAM CloudFormation Stack using the AWS CLI](#iam-cloudformation-with-aws-cli)
3.  [Create a Role using the AWS Management Console](#manual-iam-role-creation-with-aws-management-console)

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

[Link to Additional Permissions Policy](cloudformation/iam-cloudformation/managed-policy.md)

[![Launch JupiterOne IAM CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?stackName=JupiterOneIntegration&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-aws-cloudformation-templates%2Fcloudformation.json)

#### Specific Permissions Policy

This policy may be used to provide only exactly the specific permissions
currently used by JupiterOne. Using this policy will most certainly require you
to update the policy in the future as more APIs are called by JupiterOne.

NOTE: By default, AWS enforces a policy size limit of 6,144 non-whitespace characters. The policy below has been split into multiple statements to 
stay under the 6,144 non-whitespace character limit. If you have requested a quote increase from AWS, you may be able to consolidate these policies.

[Link to Specific Permissions Policy](cloudformation/iam-cloudformation-detailed/managed-policy-statements.md)

[![Launch JupiterOne IAM CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?stackName=JupiterOneIntegration&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-aws-cloudformation-templates%2Fcloudformation-detailed.json)

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

2.  In the **Select targets** section, select **Event bus in another AWS
    account**. For the **Event Bus** field, enter
    `arn:aws:events:us-east-1:612791702201:event-bus/jupiter-integration-aws`.
    For the role, select **Use existing role** but do not select a role.

3.  Click **Create**.

[1]: https://console.aws.amazon.com/iam/home#policies/arn:aws:iam::aws:policy/SecurityAudit
