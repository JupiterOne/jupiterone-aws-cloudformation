## Managed Policy Statement

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "backup:List*",
        "batch:Describe*",
        "batch:List*",
        "cloudhsm:Describe*",
        "cloudhsm:List*",
        "cloudwatch:Get*",
        "codebuild:BatchGet*",
        "codebuild:List*",
        "ec2:GetEbsDefaultKmsKeyId",
        "fms:List*",
        "glacier:List*",
        "glue:Get*",
        "glue:List*",
        "lambda:Get*",
        "lex:ListBotAliases",
        "macie2:GetFindings",
        "redshift-serverless:List*",
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
