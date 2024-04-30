## Managed Policy Statement

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "airflow:GetEnvironment",
        "batch:Describe*",
        "batch:List*",
        "cloudhsm:Describe*",
        "cloudhsm:List*",
        "cloudwatch:GetMetricData",
        "codebuild:BatchGetReportGroups",
        "codebuild:GetResourcePolicy",
        "codebuild:List*",
        "ec2:GetEbsDefaultKmsKeyId",
        "eks:Describe*",
        "eks:List*",
        "fms:List*",
        "glacier:List*",
        "glue:GetJob",
        "glue:GetTags",
        "glue:List*",
        "identitystore:List*",
        "lambda:GetFunction",
        "lex:List*",
        "macie2:GetFindings",
        "macie2:List*",
        "redshift-serverless:List*",
        "ses:GetConfigurationSet",
        "ses:GetEmailIdentity",
        "ses:List*",
        "signer:List*",
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
