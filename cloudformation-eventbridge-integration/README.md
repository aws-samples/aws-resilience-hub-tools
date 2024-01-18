# Automate resilience assessments of your AWS CloudFormation stacks using AWS Resilience Hub and Amazon EventBridge
This AWS CloudFormation template deploys a solution to automatically assess the resilience posture of new or updated CloudFormation stacks, and Terraform state files stored in AWS S3 bucket. The solution automatically creates an application in Resilience Hub and assesses it against the provided resiliency policies. The application owner receives a notification with their resilience assessment. 

This solution uses Amazon EventBridge to launch an AWS Step Functions workflow to orchestrate AWS Resilience Hub (ARH). Notification of detected drift and assessment failures are published to Amazon Simple Notification Service (SNS).

The solution deploys five resiliency policies in ARH to check applications against: `MissionCritical | Critical | Important | CoreServices | NonCritical` 
![Resiliency Policies](res-policies.png)

## Prerequisites
1. AWS account
2. IAM admin privileges (or sufficient to deploy this solution)
3. SNS topic with permission to receive resilience assessment notifications (see https://docs.aws.amazon.com/resilience-hub/latest/userguide/enabling-sns-in-arh.html)

## Setup
1. Navigate to the CloudFormation console in AWS
2. Deploy `arh_cfn_eb_template.yaml`

## How to use Solution
### Using CloudFormation stacks
When deploying or updating applications to AWS using CloudFormation, add the two following tags to the CloudFormation. This will result in automatic creation or update to existing applications in ARH which notifies the application owner of any detected drift or assessment failures.

Steps:
1. Deploy a CloudFormation template
2. During the CloudFormation deployment, add the following tags: 
    1. **(Required)**`app_criticality`, value: STRING from a pre-formatted list from ARH tiers: Valid Values: `MissionCritical | Critical | Important | CoreServices | NonCritical`
    2. **(Optional)** `app_owner`, value: ARN of valid SNS Topic that will receive the resilience assessment notifications
   
![Add Tags Image](add-tag.png)

3. Once the template is deployed, the solution will automatically handle the create/update/delete process for resources in ARH.

### Using Terraform state files store in S3 bucket
When uploading Terraform state file to AWS S3 bucket, add the two following tags to the CloudFormation. This will result in automatic creation or update to existing applications in ARH which notifies the application owner of any detected drift or assessment failures.

Steps:
1. Upload Terraform state file to AWS S3 bucket
2. During the object upload, add the following tags: 
    1. **(Required)**`app_criticality`, value: STRING from a pre-formatted list from ARH tiers: Valid Values: `MissionCritical | Critical | Important | CoreServices | NonCritical`
    2. **(Optional)** `app_owner`, value: ARN of valid SNS Topic that will receive the resilience assessment notifications
   
![Add Tags Image](add-tag-s3.png)

3. Once the object is uploaded, the solution will automatically handle the create/update/delete process for resources in ARH.


## Reference Architecture
#### AWS Architecture
![Architecture Image](architecture.png)
#### AWS Step Functions Workflow
![Step Functions Workflow](step-functions-workflow(simple).png)
The above Step Function branches based off of the status of the CloudFormation stack:
>CREATE_COMPLETE --> Create a new application in ARH
>DELETE_COMPLETE --> Delete the application in ARH
>UPDATE_COMPLETE --> Create a new version for the application in ARH and re-import input sources. If application does not exist in ARH then create a new application.

## Important Notes
- Deleting a template that was deployed with the tag will also result in the application created in ARH being deleted as well.
- To import existing stacks into ARH, update the stack and add the `app_criticality` tag.
