# IAM role for scheduled assessments

Creates an [AWS Identity and Access Management (IAM) role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html) using AWS CloudFormation for AWS Resilience Hub to use when running scheduled (daily) assessments of an application.

## Deployment

Using this template, you can create an IAM role in a single AWS account by creating a [CloudFormation stack](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacks.html), or deploy it to multiple accounts using [CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html). The role only needs to be created once per AWS account and will be used by Resilience Hub for all application assessments where scheduled assessments have been configured.

* [AwsResilienceHubPeriodicAssessmentRole.yaml](./AwsResilienceHubPeriodicAssessmentRole.yaml)

## Resources

The templates create a single resource of type [AWS::IAM::Role](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html). The role has a specific naming convention required by Resilience Hub - **AwsResilienceHubPeriodicAssessmentRole**. The trust policy of this role is minimally scoped so that Resilience Hub is the only principal that can assume it. For more information on the permissions associated with this role, please refer to [this documentation](https://docs.aws.amazon.com/resilience-hub/latest/userguide/security-iam-resilience-hub-permissions.html#security-iam-resilience-hub-primary-account).
