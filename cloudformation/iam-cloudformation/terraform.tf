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
        "access-analyzer:List*",
        "auditmanager:Get*",
        "backup:List*",
        "batch:List*",
        "cloudfront:List*",
        "cloudhsm:Describe*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudwatch:Get*",
        "codedeploy:BatchGet*",
        "codedeploy:List*",
        "cognito-idp:Describe*",
        "cognito-idp:List*",
        "datasync:Describe*",
        "datasync:List*",
        "detective:Get*",
        "detective:List*",
        "devops-guru:List*",
        "ec2:Describe*",
        "ecr:Describe*",
        "ecs:Describe*",
        "ecs:List*",
        "eks:Describe*",
        "eks:List*",
        "elasticache:Describe*",
        "elasticache:List*",
        "elasticfilesystem:Describe*",
        "elasticloadbalancing:Describe*",
        "elasticmapreduce:List*",
        "fms:List*",
        "globalaccelerator:List*",
        "guardduty:Get*",
        "guardduty:List*",
        "iam:Get*",
        "iam:List*",
        "identitystore:List*",
        "inspector:Describe*",
        "inspector:List*",
        "inspector2:List*",
        "lex:Describe*",
        "lex:List*",
        "logs:Describe*",
        "organizations:Describe*",
        "organizations:List*",
        "quicksight:Describe*",
        "quicksight:List*",
        "ram:Get*",
        "rds:Describe*",
        "route53:List*",
        "route53resolver:List*",
        "s3:Get*",
        "s3:List*",
        "secretsmanager:Describe*",
        "secretsmanager:Get*",
        "secretsmanager:List*",
        "servicediscovery:Get*",
        "servicediscovery:List*",
        "ssm:Describe*",
        "ssm:List*",
        "sso:Describe*",
        "sso:Get*",
        "sso:List*",
        "storagegateway:Describe*",
        "storagegateway:List*",
        "tag:Get*",
        "transfer:List*",
        "vpc-lattice:List*",
        "wafv2:Get*",
        "wafv2:List*"
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
