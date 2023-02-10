{
"AWSTemplateFormatVersion": "2010-09-09",
"Description": "CloudFormation Template for JupiterOne AWS Integration IAM",
"Metadata": {
"AWS::CloudFormation::Interface": {
"ParameterGroups": [
{
"Label": {
"default": "JupiterOne Authentication Parameters"
},
"Parameters": [
"JupiterOneAwsAccountId",
"JupiterOneExternalId"
]
}
],
"ParameterLabels": {
"JupiterOneAwsAccountId": {
"default": "What is the JupiterOne AWS account Id?"
},
"JupiterOneExternalId": {
"default": "What is the JupiterOne external Id you were provided?"
}
}
}
},
"Parameters": {
"JupiterOneAwsAccountId": {
"Description": "The JupiterOne AWS account Id",
"Type": "String",
"Default": "612791702201"
},
"JupiterOneExternalId": {
"Description": "The JupiterOne external Id",
"Type": "String"
}
},
"Resources": {
"JupiterOneSecurityAuditPolicy": {
"Type": "AWS::IAM::ManagedPolicy",
"Properties": {
"ManagedPolicyName": "JupiterOneSecurityAudit",
"Description": "JupiterOne SecurityAudit policy",
"Path": "/",
"PolicyDocument": {
"Version": "2012-10-17",
"Statement": [
{
"Effect": "Allow",
"Resource": "_",
"Action": [
"backup:GetBackupVaultAccessPolicy",
"batch:Describe_",
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
"Action": [
"apigateway:GET"
],
"Resource": [
"arn:aws:apigateway:*::/*"
]
}
]
}
}
},
"JupiterOneRole": {
"Type": "AWS::IAM::Role",
"Properties": {
"ManagedPolicyArns": [
"arn:aws:iam::aws:policy/SecurityAudit",
{
"Ref": "JupiterOneSecurityAuditPolicy"
}
],
"AssumeRolePolicyDocument": {
"Version": "2012-10-17",
"Statement": [
{
"Action": "sts:AssumeRole",
"Effect": "Allow",
"Principal": {
"AWS": {
"Fn::Join": [
"",
[
"arn:aws:iam::",
{
"Ref": "JupiterOneAwsAccountId"
},
":root"
]
]
}
},
"Condition": {
"StringEquals": {
"sts:ExternalId": {
"Ref": "JupiterOneExternalId"
}
}
}
}
]
}
}
}
},
"Outputs": {
"RoleARN": {
"Description": "ARN of the JupiterOne role",
"Value": {
"Fn::GetAtt": [
"JupiterOneRole",
"Arn"
]
}
}
}
}
