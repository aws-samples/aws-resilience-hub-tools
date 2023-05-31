# This is the same script as described in the Readme, but this script allows execution in a lambda.
# Set the following keys in the lambda input json: "arn", "tags", "global_dbs_list", "recordsets_list"
# The purpose of these keys can be found in the Readme. For empty, leave the values as empty strings. 

import json
import boto3
import time

def lambda_handler(event, context):
    global arh
    global app_ARN
    # Get resource metadata
    app_ARN = event["arn"]
    tag_list = event["tags"]
    global_dbs_list = event["global_dbs_list"]
    recordsets_list = event["recordsets_list"]

    # Create Resilience Hub client
    arh_region = app_ARN.split(':')[3]
    arh = boto3.client('resiliencehub', region_name=arh_region)

    # Get list of current resources in the application
    initial_resolve = arh.resolve_app_version_resources(
        appArn=app_ARN,
        appVersion='draft'
    )

    initial_resolve_status = arh.describe_app_version_resources_resolution_status(
        appArn=app_ARN,
        appVersion='draft',
        resolutionId=initial_resolve['resolutionId']
    )['status']

    while initial_resolve_status in {'Pending', 'InProgress'}:
        print('Waiting for resolution to complete. Current status - ' + initial_resolve_status)
        time.sleep(2)
        initial_resolve_status = arh.describe_app_version_resources_resolution_status(
            appArn=app_ARN,
            appVersion='draft',
            resolutionId=initial_resolve['resolutionId']
        )['status']

    current_resources = []

    get_current_resources = arh.list_app_version_resources(
        appArn=app_ARN,
        appVersion='draft'
    )

    current_resources.append(get_current_resources)

    while 'NextToken' in get_current_resources:
        get_current_resources = arh.list_app_version_resources(
            appArn=app_ARN,
            appVersion='draft'
        )
        current_resources.append(get_current_resources)

    # Add resources based on user selections
    if tag_list != '':
        tags = {i.split(':')[0]: i.split(':')[1] for i in tag_list.replace(' ', '').split(',')}
        autoscaling_regions = boto3.Session().get_available_regions('autoscaling')
        apigateway_regions = boto3.Session().get_available_regions('apigateway')

        ec2 = boto3.client('ec2')
        available_regions = [region['RegionName'] for region in ec2.describe_regions(Filters=[
            {
                'Name': 'opt-in-status',
                'Values': [
                    'opt-in-not-required', 'opted-in'
                ]
            },
        ])['Regions']]

        # Filter region list to only include available regions
        autoscaling_regions = [x for x in autoscaling_regions if x in available_regions]
        apigateway_regions = [x for x in apigateway_regions if x in available_regions]

        print('Adding AutoScaling groups')
        get_asgs(tags, autoscaling_regions, current_resources)
        print('Adding API Gateway v2')
        get_apigwv2(tags, autoscaling_regions, current_resources)

    if global_dbs_list != '':
        global_dbs = global_dbs_list.replace(' ', '').split(",")
        print('Adding RDS Global databases')
        get_global_dbs(global_dbs, current_resources)

    if recordsets_list != '':
        recordsets = recordsets_list.replace(' ', '').split(",")
        print('Adding Route53 RecordSets')
        get_recordsets(recordsets, current_resources)

    # Publish new app version
    arh.publish_app_version(
        appArn=app_ARN
    )
    print('New version of the application has been published.')

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }


# Add AutoScaling groups
def get_asgs(tags, autoscaling_regions, current_resources):
    asg_filter = []

    # Create AutoScaling groups filter based on tags
    for i in tags:
        tag = {
            'Name': 'tag:' + i,
            'Values': [tags[i]]
        }
        asg_filter.append(tag)

    # Find AutoScaling groups with matching tags and add them to Resilience Hub
    for region in autoscaling_regions:
        try:
            autoscaling = boto3.client('autoscaling', region_name=region)
            asg_list = autoscaling.describe_auto_scaling_groups(Filters=asg_filter)['AutoScalingGroups']
            for asg in asg_list:
                asg_resource_exists = check_resource_exists(asg['AutoScalingGroupName'], current_resources)
                if asg_resource_exists:
                    print('Resource already exists in the application - ' + asg['AutoScalingGroupName'])
                else:
                    print('Adding resource - ' + asg['AutoScalingGroupName'])
                    add_resource(asg['AutoScalingGroupName'], 'AWS::ResilienceHub::ComputeAppComponent',
                                 'AWS::AutoScaling::AutoScalingGroup', region)
        except Exception as error:
            print(error)


# Add API gateways v2
def get_apigwv2(tags, apigateway_regions, current_resources):
    for region in apigateway_regions:
        try:
            api_list = []
            apigwv2 = boto3.client('apigatewayv2', region_name=region)
            apis = apigwv2.get_apis()
            for api in apis['Items']:
                if tags.items() <= api['Tags'].items():
                    api_list.append(api['ApiId'])
            for api in api_list:
                api_resource_exists = check_resource_exists(api, current_resources)
                if api_resource_exists:
                    print('Resource already exists in the application - ' + api)
                else:
                    print('Adding resource - ' + api)
                    add_resource(api, 'AWS::ResilienceHub::ComputeAppComponent', 'AWS::ApiGatewayV2::Api', region)
        except Exception as error:
            print(error)


# Add RDS global databases
def get_global_dbs(global_dbs, current_resources):
    for db in global_dbs:
        db_resource_exists = check_resource_exists(db, current_resources)
        if db_resource_exists:
            print('Resource already exists in the application - ' + db)
        else:
            print('Adding resource - ' + db)
            add_resource(db, 'AWS::ResilienceHub::DatabaseAppComponent', 'AWS::RDS::GlobalCluster', 'us-east-1')


# Add Route53 recordsets
def get_recordsets(recordsets, current_resources):
    for recordset in recordsets:
        recordset_resource_exists = check_resource_exists(recordset, current_resources)
        if recordset_resource_exists:
            print('Resource already exists in the application - ' + recordset)
        else:
            print('Adding resource - ' + recordset)
            add_resource(recordset, 'AWS::ResilienceHub::NetworkingAppComponent', 'AWS::Route53::RecordSet',
                         'us-east-1')


# Check if a resource already exists in the application
def check_resource_exists(resourceId, current_resources):
    if resourceId in str(current_resources):
        return True
    return False


# Add a resource to the app
def add_resource(resourceId, componentType, resourceType, region):
    # Create new app component
    arh.create_app_version_app_component(
        appArn=app_ARN,
        name=resourceId.replace('.', '-'),
        type=componentType
    )

    # Add resource to draft app version
    arh.create_app_version_resource(
        appArn=app_ARN,
        appComponents=[
            resourceId.replace('.', '-')
        ],
        awsRegion=region,
        logicalResourceId={
            'identifier': resourceId.replace('.', '-')
        },
        physicalResourceId=resourceId,
        resourceName=resourceId.replace('.', '-'),
        resourceType=resourceType
    )

    # Resolve resources
    resolve_resource = arh.resolve_app_version_resources(
        appArn=app_ARN,
        appVersion='draft'
    )

    resolve_status = arh.describe_app_version_resources_resolution_status(
        appArn=app_ARN,
        appVersion='draft',
        resolutionId=resolve_resource['resolutionId']
    )['status']

    # Wait for resolve to complete
    while resolve_status in {'Pending', 'InProgress'}:
        print('Waiting for resolution to complete. Current status - ' + resolve_status)
        time.sleep(2)
        resolve_status = arh.describe_app_version_resources_resolution_status(
            appArn=app_ARN,
            appVersion='draft',
            resolutionId=resolve_resource['resolutionId']
        )['status']

    if resolve_status == 'Success':
        print('Resource resolution succeeded for: ' + resourceType + ' - ' + resourceId)
    elif resolve_status == 'Failed':
        print('Resource resolution failed for: ' + resourceType + ' - ' + resourceId)

