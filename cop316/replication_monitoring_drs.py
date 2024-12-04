import boto3
import sys
import time
import os

def verify_replication_continuous(source_server_ids, drs_client):
    """
    Verifies that the specified source servers have a continuous replication.
    """
    while True:
        all_servers_ready = True
        response = drs_client.describe_source_servers(
                filters={
                    'sourceServerIDs': source_server_ids
                }
        )
        for source_server_details in response["items"]:
            data_replication_info = source_server_details["dataReplicationInfo"]
            if data_replication_info["dataReplicationState"] != "CONTINUOUS":
                print(f"Source server {source_server_details["sourceServerID"]} is not in a continuous replication state.")
                all_servers_ready = False
            else:
                print(f"Source server {source_server_details["sourceServerID"]} is in a continuous replication state.")
        if all_servers_ready:
            return True
        time.sleep(60)  # Wait for 60 seconds before checking again
    return False

def main():
    """
    Main function that connects to AWS DRS using temporary credentials, accepts source server IDs from the command line,
    and verifies that the servers have a continuous replication.
    """
    # Get temporary credentials from environment variables
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    aws_session_token = os.getenv("AWS_SESSION_TOKEN")

    region = sys.argv[1]
    source_server_ids = sys.argv[2:]

    if not source_server_ids:
        print("Please provide at least one source server ID as a command-line argument.")
        sys.exit(1)

    # Connect to AWS DRS
    drs_client = boto3.client(
        "drs",
        region_name=region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token
    )

    # Verify the replication is continuous for each source server
    if verify_replication_continuous(source_server_ids, drs_client):
        print("All source servers have a continuous replication.")
    else:
        print("One or more source servers do not have a continuous replication.")

if __name__ == "__main__":
    main()
