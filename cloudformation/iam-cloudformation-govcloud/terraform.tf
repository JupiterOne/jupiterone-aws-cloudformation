output "aws_iam_user_jupiterone_access_user" {
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
EOF
}

resource "aws_iam_user" "jupiterone_access_user" {
  name = "jupiterone-access-user"
}

resource "aws_iam_user_policy_attachment" "jupiterone_security_audit_policy_attachment" {
  user       = "${ aws_iam_user.jupiterone_access_user.name }"
  policy_arn = "${ aws_iam_policy.jupiterone_security_audit_policy.arn }"
}
resource "aws_iam_user_policy_attachment" "aws_security_audit_policy_attachment" {
  user       = "${ aws_iam_user.jupiterone_access_user.name }"
  policy_arn = "arn:aws-us-gov:iam::aws:policy/SecurityAudit"
}
