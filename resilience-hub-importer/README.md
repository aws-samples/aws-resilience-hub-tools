# AWS Resilience Hub Importer

This CDK stack automates the process of creating an AWS Resilience Hub application and importing resources from an existing CloudFormation stack.

## Features

- Creates a new AWS Resilience Hub application
- Retrieves the ARN of a specified source CloudFormation stack
- Imports resources from the source stack into the Resilience Hub application
- Provides status updates on the import process

## Prerequisites

- [AWS CDK](https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html) installed and configured
- [Node.js](https://nodejs.org/) (v14.x or later) and npm installed
- AWS CLI configured with appropriate credentials
- Existing CloudFormation stack to import resources from
- AWS Resilience Hub policy created

## Installation

1. Clone this repository: git clone https://github.com/your-username/resilience-hub-importer.git cd resilience-hub-importer
2. Install dependencies:
npm install


## Usage

1. Synthesize the CloudFormation template:
cdk synth

2. Deploy the stack:
cdk deploy --context resiliencyPolicyArn=arn:aws:resiliencehub:region:account-id:resiliency-policy/policy-id --context sourceStackName=YourSourceStackName --context appName=YourAppName


Replace the following with your actual values:
- `region`: The AWS region where your Resilience Hub policy is located
- `account-id`: Your AWS account ID
- `policy-id`: The ID of your Resilience Hub policy
- `YourSourceStackName`: The name of the CloudFormation stack you want to import resources from
- `YourAppName`: The desired name for your new Resilience Hub application (optional)

## Stack Outputs

After successful deployment, the stack will output:

- **ApplicationArn**: ARN of the created Resilience Hub Application
- **StackArn**: ARN of the source stack
- **ImportStatus**: Status of the import operation

## Cleanup

To remove all resources created by this stack, run:

cdk destroy


## Architecture

This stack uses AWS CDK to define the following resources:

1. A new AWS Resilience Hub application
2. An IAM role for AWS Custom Resources with necessary permissions
3. A Custom Resource to retrieve the source stack's ARN
4. A Custom Resource to import resources from the source stack to the Resilience Hub application

## Troubleshooting

- If the import fails, check the CloudWatch logs for the Lambda functions created by the Custom Resources.
- Ensure that the provided Resilience Hub policy ARN and source stack name are correct.
- Verify that your AWS account has the necessary permissions to create and modify Resilience Hub applications and to read the source CloudFormation stack.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file for details.

## Additional Resources

- [AWS Resilience Hub Documentation](https://docs.aws.amazon.com/resilience-hub/)
- [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/latest/guide/home.html)
- [CloudFormation Documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html)
This README provides a comprehensive guide for users to understand, install, and use your Resilience Hub Importer. It includes sections on prerequisites, installation, usage, outputs, cleanup, architecture, troubleshooting, contributing, licensing, and additional resources.

Feel free to adjust any details to better match your specific implementation or to add any other information you think would be valuable for users of your tool.