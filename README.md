# jupiterone-aws-integration

Contains scripts and instructions to configure your [JupiterOne](https://jupiterone.io/)
AWS integration.

## Setup

You can set up the necessary AWS IAM role for JupiterOne using one of the
following methods:

## Launch a stack now!

Just click this button to launch a CloudFormation stack for provisioning your
JupiterOne AWS integration:

[![Launch JupiterOne CloudFormation Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=jupiterone-integration&templateURL=https%3A%2F%2Fs3.amazonaws.com%2Fjupiterone-prod-us-jupiter-aws-integration%2Fjupiterone-cloudformation.json)

## Using AWS CLI

```bash
aws cloudformation create-stack --stack-name JupiterOneIntegration --template-url https://s3.amazonaws.com/jupiterone-prod-us-jupiter-aws-integration/jupiterone-cloudformation.json
```

## Manual creation via AWS Management Console

From your AWS Management Console, perform the following steps:

1.  Go to **IAM**, select **Roles** and then **Create Role**.

1.  Select **Another AWS account** under **Select type of trusted entity**.

1.  Enter the following **Account ID**: `<jupiterone_account_id>`

1.  Select **Require external ID** and enter the following **External ID**:
    `<jupiterone_external_id>`

1.  Leave **Require MFA** unchecked and click **Next: Permissions**.

1.  In the Policy search box, search for and select `SecurityAudit` policy. This
    is an AWS-managed IAM policy that grants access to read security
    configurations of the AWS resources.

1.  With the `SecurityAudit` policy select, click **Next: Review**.

1.  Enter `JupiterOne` as the **Role Name**, and optionally, enter a description
    for the Role.

1.  Click **Create Role**.

1.  In the list of Roles, search for and select the newly created `JupiterOne`
    role, and copy the **Role ARN**. It should be in a format that looks like
    `arn:aws:iam::<your_aws_account_id>:role/JupiterOne`.
