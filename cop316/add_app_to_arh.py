import boto3
import os
import argparse
import time
import json

def wait_for_app_creation(resilience_hub, app_arn, max_attempts=30, delay=10):
    for _ in range(max_attempts):
        try:
            response = resilience_hub.describe_app(appArn=app_arn)
            if response['app']['status'] == 'Active':
                return True
        except resilience_hub.exceptions.ResourceNotFoundException:
            pass
        time.sleep(delay)
    return False

def wait_for_import_completion(resilience_hub, app_arn, max_attempts=30, delay=10):
    for _ in range(max_attempts):
        try:
            response = resilience_hub.describe_draft_app_version_resources_import_status(appArn=app_arn)
            if response['status'] == 'Success':
                return True
        except resilience_hub.exceptions.ResourceNotFoundException:
            pass
        time.sleep(delay)
    if response:    
        print(f"Import failed: {response.get('statusMessage', 'Unknown error')}")
    return False


def wait_for_assessment_completion(resilience_hub, assessment_arn, max_attempts=30, delay=10):
    for _ in range(max_attempts):
        try:
            assessment_response = resilience_hub.describe_app_assessment(assessmentArn=assessment_arn)
            if assessment_response['assessment']['assessmentStatus'] == 'Success':
                return True
        except resilience_hub.exceptions.ResourceNotFoundException:
            pass
        time.sleep(delay)
    if assessment_response:    
        print(f"assessment failed: {assessment_response['assessment'].get('message', 'Unknown error')}")
    return False


def add_app_to_resilience_hub(stack_name, app_name, region):
    resilience_hub = boto3.client('resiliencehub', region_name=region)
    cfn = boto3.client('cloudformation', region_name=region)

    try:
        # Get the CloudFormation stack ARN
        stack_response = cfn.describe_stacks(StackName=stack_name)
        stack_arn = stack_response['Stacks'][0]['StackId']

        # Create the application in Resilience Hub
        app_response = resilience_hub.create_app(
            name=app_name,
            description=f"Application created from CloudFormation stack {stack_name}",
            assessmentSchedule="Daily"
        )

        app_arn = app_response['app']['appArn']
        print(f"Application '{app_name}' creation initiated with ARN: {app_arn}")

        # Wait for the application to be created
        print("Waiting for the application to be created...")
        if not wait_for_app_creation(resilience_hub, app_arn):
            print("Timed out waiting for application creation.")
            return None

        print("Application created successfully.")


        # Import the CloudFormation stack to the application
        print("Importing CloudFormation stack resources...")
        resilience_hub.import_resources_to_draft_app_version(
            appArn=app_arn,
            sourceArns=[stack_arn]
        )

        # Wait for the import to complete
        if not wait_for_import_completion(resilience_hub, app_arn):
            print("Timed out or failed waiting for resource import.")
            return None

        print("Resources imported successfully.")

        # Create a resiliency policy
        policy_response = resilience_hub.create_resiliency_policy(
            policyName=f"{app_name}-policy",
            policyDescription=f"Resiliency policy for {app_name}",
            policy={
                "Software": {
                    "rpoInSecs": 45,
                    "rtoInSecs": 2700
                },
                "AZ": {
                    "rpoInSecs": 3600,
                    "rtoInSecs": 14400
                },
                "Hardware": {
                    "rpoInSecs": 3600,
                    "rtoInSecs": 14400
                }
            },
            tier="Critical"
        )
        if policy_response['policy']:
            policy_arn = policy_response['policy']['policyArn']
        print(f"Resiliency policy created with ARN: {policy_arn}")

        # Associate the policy with the application
        resilience_hub.update_app(
            appArn=app_arn,
            policyArn=policy_arn
        )
        print(f"Resiliency policy associated with the application")

        # Publish the application
        version_response = resilience_hub.publish_app_version(appArn=app_arn)
        app_version = version_response["appVersion"]
        print(f"Application version published {app_version}")

        assessment_response = resilience_hub.start_app_assessment(
            appArn=app_arn,
            appVersion=app_version,
            assessmentName='demo-assessment'
        )

        assessment_arn = assessment_response['assessment']['assessmentArn']
        print(f"Assessment '{app_name}' creation initiated with ARN: {assessment_arn}")

        if not wait_for_assessment_completion(resilience_hub, assessment_arn):
            print("Timed out or failed waiting for assessment.")
            return None

        print(f"assessment completed successfully")

        recommendation_response = resilience_hub.list_app_component_recommendations(
            assessmentArn=assessment_arn,
            maxResults=100
        )

        formatted_json = json.dumps(recommendation_response, indent=4)

        json_output = open('recommendations.json', 'w')
        json_output.write(formatted_json)
        json_output.close

        return app_arn

    except Exception as e:
        print(f"Error: {str(e)}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Add an application to AWS Resilience Hub")
    parser.add_argument("stack_name", help="Name of the deployed CloudFormation stack")
    parser.add_argument("app_name", help="Name for the Resilience Hub application")
    parser.add_argument("region", help="AWS region of the stack and Resilience Hub")
    args = parser.parse_args()

    # Ensure AWS credentials are available
    if not (os.environ.get('AWS_ACCESS_KEY_ID') and
            os.environ.get('AWS_SECRET_ACCESS_KEY') and
            os.environ.get('AWS_SESSION_TOKEN')):
        print("AWS credentials not found. Please set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN environment variables.")
        return

    # Call the function to add the application to Resilience Hub
    app_arn = add_app_to_resilience_hub(args.stack_name, args.app_name, args.region)

    if app_arn:
        print(f"Application successfully added to Resilience Hub with ARN: {app_arn}")
    else:
        print("Failed to add the application to Resilience Hub.")

if __name__ == "__main__":
    main()