# IAM role template for AWS Resilience Hub applications

Creates [AWS Identity and Access Management (IAM) roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html) using AWS CloudFormation.

These roles can be passed to AWS Resilience Hub as part of creating an application, and will be used by AWS Resilience Hub when assessing your AWS resources.
For further documentation on how to create AWS Resilience Hub applications using custom IAM roles, see [Setup IAM roles and permissions](https://docs.aws.amazon.com/resilience-hub/latest/userguide/security_iam_service-with-iam.html#setting-up-permissions).

## Deployment

Using this template, you can create an IAM role in a single AWS account by creating a [CloudFormation stack](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacks.html), or deploy it to multiple accounts using [CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html).

* The [AWSResilienceHubPrimaryAccountAssessmentRole.yaml](AWSResilienceHubPrimaryAccountAssessmentRole.yaml) role needs to be created once per primary AWS account (the account used for creating Resilience Hub applications).

* (Optional) If your AWS Resilience Hub application, is composed of resources across multiple accounts (cross accounts) the [AWSResilienceHubCrossAccountAssessmentRole.yaml](AWSResilienceHubCrossAccountAssessmentRole.yaml) role needs to be deployed on every cross account (application infrastructure accounts which contain resources that are part of the AWS Resilience Hub application).


## Resources

Each of the provided templates create a single resource of type [AWS::IAM::Role](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html).

1) **AWSResilienceHubPrimaryAccountAssessmentRole**: The trust policy of this role is minimally scoped so that Resilience Hub is the only principal that can assume it. For more information on the permissions associated with this role, please refer to [this documentation](https://docs.aws.amazon.com/resilience-hub/latest/userguide/security-iam-resilience-hub-permissions.html#security-iam-resilience-hub-primary-account). 
   The following policies are attached to this role:
   * **AWSResilienceHubAsssessmentExecutionPolicy**. This policy contains all read-only permissions required by AWS Resilience Hub to assess the resiliency of your application.
   * (Optional) **AWSResilienceHubCrossAccountAssumeRolePolicy**. This IAM policy contains sts:AssumeRole permissions for all cross account IAM roles. If your application is composed of cross account resources, AWS Resilience Hub uses the primary role 
     to assume any cross account IAM roles, to access resources in cross accounts. If created, this policy will be applied to the created IAM role.

   The AWSResilienceHubPrimaryAccountAssessmentRole.yaml accepts the following parameters:
   1) RoleName (required) - The name of the IAM role which will be created in your primary account, and can be passed when creating AWS Resilience Hub applications.
   2) CrossAccountIAMRoleARNs (optional) - A comma seperated list of cross account IAM roles which will be used by AWS Resilience Hub to access cross account resources.
   3) AWSResilienceHubCrossAccountAssumeRolePolicyName (optional) - The name of the policy which will be created to allow the primary IAM role to assume any cross account IAM roles.

1) **AWSResilienceHubCrossAccountAssessmentRole**: The trust policy of this role is minimally scoped so that only the primary IAM role created is allowed to assume the role. For more information on the permissions associated with this role, please refer to [this documentation](https://docs.aws.amazon.com/resilience-hub/latest/userguide/security-iam-resilience-hub-permissions.html#security-iam-resilience-hub-primary-account).
   The following policies are attached to this role:
    * **AWSResilienceHubAsssessmentExecutionPolicy**. This policy contains all read-only permissions required by AWS Resilience Hub to assess the resiliency of your application.
   
   The AWSResilienceHubPrimaryAccountAssessmentRole.yaml accepts the following parameters:
    1) RoleName (required) - The name of the IAM role which will be created in your cross account, and can be passed when creating AWS Resilience Hub applications.
    2) AWSResilienceHubPrimaryAccountAssessmentRoleARN (required) - The primary account IAM role ARN. The trust policy of the created role, will allow the primary IAM role previously created, to assume this cross account role. 