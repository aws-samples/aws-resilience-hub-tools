import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as resiliencehub from 'aws-cdk-lib/aws-resiliencehub';
import * as cr from 'aws-cdk-lib/custom-resources';
import * as iam from 'aws-cdk-lib/aws-iam';

/**
 * A CDK stack that creates an AWS Resilience Hub application and imports resources
 * from an existing CloudFormation stack for resilience assessment.
 * 
 * Required context parameters:
 * - resiliencyPolicyArn: ARN of the Resilience Hub policy to apply
 * - sourceStackName: Name of the CloudFormation stack to import
 * 
 * Optional context parameters:
 * - appName: Name for the Resilience Hub application (defaults to 'MyResilienceApp')
 */
export class ResilienceHubImporterStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Retrieve context values for stack configuration
    const resiliencyPolicyArn = this.node.tryGetContext('resiliencyPolicyArn');
    const sourceStackName = this.node.tryGetContext('sourceStackName');
    const appName = this.node.tryGetContext('appName') || 'MyResilienceApp';

    // Validate required context parameters
    if (!resiliencyPolicyArn || !sourceStackName) {
      console.warn(
        'Missing context: "resiliencyPolicyArn" or "sourceStackName". Destroy may proceed since these are not critical for resource deletion.'
      ); 
    }

    /**
     * Create the AWS Resilience Hub application with daily assessment schedule
     * and production environment tag
     */
    const arhApp = new resiliencehub.CfnApp(this, 'ResilienceHubApplication', {
      name: appName,
      description: 'Resilience configuration for my application',
      appAssessmentSchedule: 'Daily',
      resiliencyPolicyArn: resiliencyPolicyArn,
      appTemplateBody: '{"Resources":{}}',
      resourceMappings: [],
      tags: {
        Environment: 'Production',
      },
    });

    // Set the removal policy for created resileince app to RETAIN
    arhApp.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);

    /**
     * Create IAM role for custom resources with permissions to:
     * - Import resources to Resilience Hub
     * - Access CloudFormation stack information
     */
    const customResourceRole = new iam.Role(this, 'CustomResourceRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Role for AWS Resilience Hub import resource',
      inlinePolicies: {
        ResilienceHubImportPolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: ['resiliencehub:ImportResourcesToDraftAppVersion'],
              resources: [arhApp.attrAppArn],
            }),
            new iam.PolicyStatement({
              actions: ['cloudformation:DescribeStacks'],
              resources: [`arn:aws:cloudformation:${this.region}:${this.account}:stack/${sourceStackName}/*`],
            }),
          ],
        }),
      },
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AWSResilienceHubAsssessmentExecutionPolicy'),
      ],
    });

    /**
     * Custom resource to retrieve the source stack's ARN
     * Uses CloudFormation's DescribeStacks API
     */
    const getStackArn = new cr.AwsCustomResource(this, 'GetStackArn', {
      onCreate: {
        service: 'CloudFormation',
        action: 'describeStacks',
        parameters: { StackName: sourceStackName },
        physicalResourceId: cr.PhysicalResourceId.of(`GetStackArn-${sourceStackName}`),
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ['cloudformation:DescribeStacks'],
          resources: [`arn:aws:cloudformation:${this.region}:${this.account}:stack/${sourceStackName}/*`],
        }),
      ]),
      role: customResourceRole,
    });

    const stackArn = getStackArn.getResponseField('Stacks.0.StackId');

    /**
     * Custom resource to import resources from the source stack
     * into the Resilience Hub application
     */
    const importResources = new cr.AwsCustomResource(this, 'ImportResources', {
      onCreate: {
        service: 'ResilienceHub',
        action: 'importResourcesToDraftAppVersion',
        parameters: {
          appArn: arhApp.attrAppArn,
          sourceArns: [stackArn],
        },
        physicalResourceId: cr.PhysicalResourceId.of(`ImportResources-${appName}`),
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ['resiliencehub:ImportResourcesToDraftAppVersion'],
          resources: [arhApp.attrAppArn],
        }),
      ]),
      role: customResourceRole,
    });

    // Ensure proper resource creation order
    importResources.node.addDependency(arhApp);
    importResources.node.addDependency(getStackArn);

    /**
     * Stack outputs for reference and monitoring
     */
    new cdk.CfnOutput(this, 'ApplicationArn', {
      value: arhApp.attrAppArn,
      description: 'ARN of the created Resilience Hub Application',
    });

    new cdk.CfnOutput(this, 'StackArn', {
      value: stackArn,
      description: 'ARN of the source stack',
    });

    new cdk.CfnOutput(this, 'ImportStatus', {
      value: importResources.getResponseField('status'),
      description: 'Status of the import operation',
    });
  }
}
