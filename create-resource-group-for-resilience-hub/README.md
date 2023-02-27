# Create an AWS Resource Group to define an application for AWS Resilience Hub

Creates an AWS Resource Group that describes an application that can be used for running assessments using AWS Resilience Hub. This is useful in situations where you might have your infrastruscture provisioned without using any of the infrastrucure-as-code tools supported by Resilience Hub, such as AWS CloudFormation and Terraform.

This solution creates a new Resource Group and applies appropriate filters to only include resource types that are supported by Resilience Hub and will help mitigate quota exhaustion. The Resource Group created will contain the following resource types:

* AWS::ApiGateway::RestApi
* AWS::DynamoDB::Table
* AWS::EC2::Instance
* AWS::EC2::NatGateway
* AWS::EC2::Volume
* AWS::ECS::Service
* AWS::EFS::FileSystem
* AWS::Lambda::Function
* AWS::RDS::DBCluster
* AWS::RDS::DBInstance
* AWS::S3::Bucket
* AWS::SQS::Queue
* AWS::ElasticLoadBalancingV2::LoadBalancer
* AWS::ElasticLoadBalancing::LoadBalancer

**NOTE: There are additional resource types supported by Resilience Hub (such as Amazon EC2 AutoScaling groups) that are currently not supported by Resource Groups. You will need to add these resources manually to the application on Resilience Hub.**

## Deployment

Use the [resource-group.yaml](./resource-group.yaml) template to create a CloudFormation stack.

## Parameters

When using this template, you will need to provide values for the following parameters:

* **ApplicationName** - the name of the application which will be used to name the resource group
* **TagKey** - the tag key used to identify resources
* **TagValue** - the tag value used to identify resources

## Resources

The templates create a single resource of type [AWS::ResourceGroups::Group](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-resourcegroups-group.html).

## Outputs

The [Outputs](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html) returns the name and ARN of the Resource Group that was created.
