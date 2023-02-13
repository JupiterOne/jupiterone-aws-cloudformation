## Managed Policy Statement

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "backup:GetBackupVaultAccessPolicy",
        "batch:Describe*",
        "batch:List*",
        "cloudhsm:Describe*",
        "cloudhsm:List*",
        "cloudwatch:GetMetricData",
        "ec2:GetEbsDefaultKmsKeyId",
        "eks:Describe*",
        "eks:List*",
        "elasticfilesystem:Describe*",
        "fms:List*",
        "glue:GetJob",
        "glue:GetSecurityConfigurations",
        "glue:GetTags",
        "glue:List*",
        "lambda:GetFunction",
        "lex:Describe*",
        "lex:List*",
        "macie2:GetFindings",
        "macie2:List*",
        "network-firewall:Describe*",
        "network-firewall:List*",
        "redshift-serverless:List*",
        "shield:GetSubscriptionState",
        "sns:GetSubscriptionAttributes",
        "ssm:GetDocument"
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