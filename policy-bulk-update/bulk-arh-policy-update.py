'''  Bulk policy update to multiple Resilience Hub applications
    Inputs: 
        -p, --policy-arn: ARN of the Resilience Hub Policy
        -a, --target-app-arns: Target ARH App ARNs
        -f, --target-app-file: File containing the ARH App ARNs
        -s, --schedule: Schedule for the policy
        -v, --verbose: Verbose output
'''

from pprint import pprint
import argparse

import boto3


def update_policy_for_an_app(arh, policy_arn, app_arn, schedule, verbose):
    if verbose:
        print(f"Updating policy {policy_arn} for {app_arn}")
    try:
        if schedule is not None:
            response = arh.update_app(
                policyArn=policy_arn,
                appArn=app_arn,
                assessmentSchedule=schedule
            )
        else:
            response = arh.update_app(
                policyArn=policy_arn,
                appArn=app_arn
            )
    except:
        print(f"Error updating policy {policy_arn} for {app_arn}")
        raise

    if verbose:
        pprint(response)

def update_policy_for_apps (arh, policy_arn, app_arns, schedule, verbose):
    for app_arn in app_arns.split(','):
        update_policy_for_an_app(arh, policy_arn, app_arn, schedule, verbose)

def update_policy_for_apps_from_file(arh, policy_arn, file_name, schedule, verbose):
    with open(file_name) as f:
        for app_arn in f:
            update_policy_for_an_app(arh, policy_arn, app_arn.strip(), schedule, verbose)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bulk policy update script for AWS Resilience Hub")
    parser.add_argument("-p", "--policy-arn", type=str,
        help="ARN of the Resilience Hub Policy", required=True)

    # You need either the list of app ARNs or the file containing the list of app ARNs
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--target-app-arns", type=str, help="Target ARH App ARNs")
    group.add_argument("-f", "--target-app-file", type=str, help="File containing the ARH App ARNs")

    parser.add_argument("-s", "--schedule", type=str,
        help="Assesmant Schedule - valid values Disabled|Daily",choices=['Disabled', 'Daily'],)
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode")
    args = parser.parse_args()

    # Parse the ARN of the policy to get the AWS region
    region = args.policy_arn.split(':')[3]
    if args.verbose:
        print(f"AWS Region {region}")
    client = boto3.client('resiliencehub',region)

    if args.target_app_arns is not None:
        update_policy_for_apps(client, args.policy_arn, args.target_app_arns,
            args.schedule, args.verbose)
    elif args.target_app_file is not None:
        update_policy_for_apps_from_file(client, args.policy_arn, args.target_app_file,
            args.schedule, args.verbose)
    print("Policy update completed")
