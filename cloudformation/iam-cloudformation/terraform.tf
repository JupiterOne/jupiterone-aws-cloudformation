resource "aws_iam_role" "jupiterone" {
  name = "JupiterOne"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::612791702201:root"
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
      "Resource": "*",
      "Action": [
        "backup:GetBackupVaultAccessPolicy",
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
        "elasticfilesystem:Describe*",
        "fms:List*",
        "glacier:List*",
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
      "Action": [
        "apigateway:GET"
      ],
      "Resource": [
        "arn:aws:apigateway:*::/*"
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
resource "aws_iam_role_policy_attachment" "aws_security_audit_policy_attachment" {
  role       = "${ aws_iam_role.jupiterone.name }"
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}
