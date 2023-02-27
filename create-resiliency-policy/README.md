# Create resiliency policy

Create a [resiliency policy](https://docs.aws.amazon.com/resilience-hub/latest/userguide/create-policy.html) using AWS CloudFormation to associate with applications defined in AWS Resilience Hub. Depending on the use case, you can create a resiliency policy that uses the same Recovery Time Objective (RTO) and Recovery Point Objective (RPO) values for each [disruption type](https://docs.aws.amazon.com/resilience-hub/latest/userguide/concepts-terms.html#disruption), or create a granular policy with different RTO and RPO values for different disruption types.

## Deployment

Using these templates, you can create resiliency policies in a single AWS account and region by creating a [CloudFormation stack](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacks.html), or deploy it to multiple accounts and regions using [CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html).

* **Single RTO/RPO** - [resiliency_policy.yaml](./resiliency_policy.yaml)
* **Granular RTO/RPO** - [resiliency_policy_granular.yaml](./resiliency_policy_granular.yaml)

## Parameters

When using these templates, you will need to provide values for the parameters required by each use case.

### Single RTO/RPO

* **PolicyName** - A name for the policy
* **PolicyDescription** - A description for the policy
* **RPOInSecs** - The Recovery Point Objective (RPO) in seconds
* **RTOInSecs** - The Recovery Time Objective (RTO) in seconds
* **PolicyTier** - A tier for the policy that represents the criticality. Supported values are MissionCritical, Critical, Important, CoreServices, and NonCritical

### Granular RTO/RPO

* **PolicyName** - A name for the policy
* **PolicyDescription** - A description for the policy
* **AvailabilityZoneRPOInSecs** - The Recovery Point Objective (RPO) for Availability Zone disruptions in seconds
* **AvailabilityZoneRTOInSecs** - The Recovery Time Objective (RTO) for Availability Zone disruptions in seconds
* **HardwareRPOInSecs** - The Recovery Point Objective (RPO) for Hardware disruptions in seconds
* **HardwareRTOInSecs** - The Recovery Time Objective (RTO) for Hardware disruptions in seconds
* **SoftwareRPOInSecs** - The Recovery Point Objective (RPO) for Software disruptions in seconds
* **SoftwareRTOInSecs** - The Recovery Time Objective (RTO) for Software disruptions in seconds
* **RegionRPOInSecs** - The Recovery Point Objective (RPO) for Regional disruptions in seconds
* **RegionRTOInSecs** - The Recovery Time Objective (RTO) for Regional disruptions in seconds
* **PolicyTier** - A tier for the policy that represents the criticality. Supported values are MissionCritical, Critical, Important, CoreServices, and NonCritical

## Resources

The templates create a single resource of type [AWS::ResilienceHub::ResiliencyPolicy](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-resiliencehub-resiliencypolicy.html).

## Outputs

The [Outputs](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html) returns the ARN of the Resiliency policy that was created.
