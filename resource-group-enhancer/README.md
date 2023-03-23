# Add resources that are not supported by Resource Groups

There are 4 resource types that are supported by AWS Resilience Hub but not supported by AWS Resource Groups. If you are using Resource Groups as the input for applications on Resilience Hub, and your application consists of one of the following resource types, you can use this solution to add these resource types directly to the application on Resilience Hub in an automated way.

AWS::AutoScaling::AutoScalingGroup
AWS::ApiGatewayV2::Api
AWS::RDS::GlobalCluster
AAWS::Route53::RecordSet

## Pre-requisites

* Execution environment needs to have the [AWS SDK for Python (Boto3)](https://aws.amazon.com/sdk-for-python/) installed
* You need the following IAM permissions for the script to work:
    * Permissions to describe AutoScaling groups and AWS Regions ([DescribeRegions](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html), [DescribeAutoScalingGroups](https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_DescribeAutoScalingGroups.html))
    * API Gateway permissions to get API Gateway V2 APIs ([GetApis](https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis.html#GetApis))
    * Resilience Hub permissions ([ResolveAppVersionResources](https://docs.aws.amazon.com/resilience-hub/latest/APIReference/API_ResolveAppVersionResources.html), [DescribeAppVersionResourcesResolutionStatus](https://docs.aws.amazon.com/resilience-hub/latest/APIReference/API_DescribeAppVersionResourcesResolutionStatus.html), [ListAppVersionResources](https://docs.aws.amazon.com/resilience-hub/latest/APIReference/API_ListAppVersionResources.html), [PublishAppVersion](https://docs.aws.amazon.com/resilience-hub/latest/APIReference/API_PublishAppVersion.html), [CreateAppVersionAppComponent](https://docs.aws.amazon.com/resilience-hub/latest/APIReference/API_CreateAppVersionAppComponent.html), [CreateAppVersionResource](https://docs.aws.amazon.com/resilience-hub/latest/APIReference/API_CreateAppVersionResource.html))

## Execution

Run [resource-group-enhancer.py](./resource-group-enhancer.py) in an environment that meets the pre-requisites.

```
python resource-group-enhancer.py
```

The script prompts for the following inputs:

* ARN of the application on Resilience Hub (this is REQUIRED)
* Tags associated with AutoScaling groups and API Gateways V2. This accepts a list of key:value pairs. For example, if you have two tags associated with your resources, you would enter them as - app:myapp, environment:prod (this is optional, only use this if you want to add AutoScaling groups or API Gateways V2)
* List of global database names. You can enter a comma-separated list of global database names (this is optional, only use this if you want to add RDS global databases to your application)
* List of Route 53 RecordSets. You can enter a comma-separated list of Route 53 RecordSets (this is optional, only use this if you want to add Route 53 RecordSets to your application)

## Output

The script adds resources to the application on Resilience Hub based on inputs provided during execution. After adding the resources, a new version of the application will be published on Resilience Hub.
