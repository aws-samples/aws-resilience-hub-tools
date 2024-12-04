import boto3
import os
import sys

def activate_post_launch_actions(source_server_id, drs_client):
    """
    Activates the "Volume integrity validation" and "Validate disk space" post-launch actions for a given source server.
    """
    post_launch_actions = [
        "AWSMigration-VerifyMountedVolumes",
        "AWSMigration-ValidateDiskSpace"
    ]

    drs_client.update_launch_configuration(
        sourceServerID=source_server_id,
        postLaunchEnabled=True,
    )

    response = drs_client.list_launch_actions(
        resourceId=source_server_id
    )

    for action in response['items']:
        if action['actionCode'] in post_launch_actions:
            drs_client.put_launch_action(
                actionCode=action['actionCode'],
                actionId=action['actionId'],
                actionVersion=action['actionVersion'],
                active=True,
                category=action['category'],
                description=action['description'],
                name=action['name'],
                optional=action['optional'],
                order=action['order'],
                parameters=action['parameters'],
                resourceId=source_server_id
            )

def main():
    """
    Main function that connects to AWS DRS using temporary credentials from environment variables,
    activates the post-launch actions, and adds two validation actions.
    """
    # Get temporary credentials from environment variables
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    aws_session_token = os.getenv("AWS_SESSION_TOKEN")

    # Get region and source server IDs from command-line arguments
    if len(sys.argv) < 3:
        print("Usage: python script.py <region> <source_server_id1> [<source_server_id2> ...]")
        sys.exit(1)

    region = sys.argv[1]
    source_server_ids = sys.argv[2:]

    # Connect to AWS DRS
    drs_client = boto3.client(
        "drs",
        region_name=region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token
    )

    # Activate post-launch actions and add 2 validate actions
    for source_server_id in source_server_ids:
        activate_post_launch_actions(source_server_id, drs_client)


if __name__ == "__main__":
    main()