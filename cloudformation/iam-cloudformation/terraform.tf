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
      "Resource": "*",
      "Action": [
        "backup:List*",
        "batch:Describe*",
        "batch:List*",
        "cloudhsm:Describe*",
        "cloudhsm:List*",
        "cloudwatch:GetMetricData",
        "codebuild:BatchGetReportGroups",
        "codebuild:List*",
        "ec2:GetEbsDefaultKmsKeyId",
        "eks:Describe*",
        "eks:List*",
        "fms:List*",
        "glacier:List*",
        "glue:GetJob",
        "glue:List*",
        "lambda:GetFunction",
        "lex:List*",
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
