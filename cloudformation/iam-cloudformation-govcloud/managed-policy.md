## Managed Policy Statement

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
        "lambda:GetFunction",
        "lex:List*",
        "ses:GetConfigurationSet",
        "ses:GetEmailIdentity",
        "ses:List*",
        "sns:GetSubscriptionAttributes",
        "ssm:GetDocument"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["apigateway:GET"],
      "Resource": ["arn:aws-us-gov:apigateway:*::/*"]
    }
  ]
}
```
