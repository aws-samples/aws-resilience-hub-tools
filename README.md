# AWS Resilience Hub tools

Collection of solutions and tools to customize and enhance your usage of [AWS Resilience Hub](https://aws.amazon.com/resilience-hub/). 

## List of assets

* [create-resiliency-policy](./create-resiliency-policy) - Creates a resiliency policy within Resilience Hub using AWS CloudFormation
* [create-resource-group-for-resilience-hub](./create-resource-group-for-resilience-hub) - Creates an AWS Resource Group that only contains resources supported by Resilience Hub
* [aws-codepipeline-integration](./aws-codepipeline-integration) - Example of how Resilience Hub can be integrated with AWS CodePipeline for continuous resilience
* [github-actions-integration](./github-actions-integration) - Example of how Resilience Hub can be integrated into Github Actions for continuous resilience
* [jenkins-pipeline-integration](./jenkins-pipeline-integration) - Example of how Resilience Hub can be integrated into Jenkins Pipeline for continuous resilience
* [resilience-hub-csv-export](./resilience-hub-csv-export) - Export data from Resilience Hub for all applications in a CSV file that can be used for reporting and analytics
* [resilience-reporter](./resilience-reporter) - Creates an Amazon QuickSight dashboard that contains data from Resilience Hub for all applications
* [resource-group-enhancer](./resource-group-enhancer) - Add resources not supported by AWS Resource Group to an application in Resilience Hub
* [scheduled-assessment-role](./scheduled-assessment-role) - Creates an Identity and Access Management (IAM) role to be used by Resilience Hub for running scheduled (daily) assessments

## License

This library is licensed under the MIT-0 License.
