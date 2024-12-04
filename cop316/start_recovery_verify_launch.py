import boto3
import sys
import time
import os

def start_recovery(source_server_ids, drs_client):
    """
    Starts recovery for all specified source servers in a single job, setting isDrill to True.
    """
    try:
        # Prepare the sourceServers parameter
        source_servers = [{"sourceServerID": server_id} for server_id in source_server_ids]

        # Prepare the request parameters
        request_params = {
            "isDrill": True,
            "sourceServers": source_servers
        }

        # Make the API call
        response = drs_client.start_recovery(**request_params)
        
        job = response['job']
        job_id = job['jobID']
        job_status = job['status']
        job_type = job['type']

        print(f"Started recovery drill. Job ID: {job_id}, Status: {job_status}, Type: {job_type}.")

        # Print information about participating servers
        for server in job['participatingServers']:
            source_id = server['sourceServerID']
            launch_status = server['launchStatus']
            print(f"Server {source_id} launch status: {launch_status}")

        return job_id
    except Exception as e:
        print(f"Failed to start recovery drill: {str(e)}.")
        return None

def check_recovery_job_status(job_id, source_server_ids, drs_client):
    """
    Checks the status of the recovery job and individual server recoveries within the job.
    """
    while True:
        response = drs_client.describe_jobs(filters={"jobIDs": [job_id]})
        jobs = response['items']
        
        if not jobs:
            print(f"Job {job_id} not found")
            return False
        
        job = jobs[0]
        job_status = job['status']
        
        if job_status == 'COMPLETED':
            all_servers_ready = True
            for server in job['participatingServers']:
                server_id = server['sourceServerID']
                launch_status = server['launchStatus']
                
                if launch_status == 'LAUNCHED':
                    print(f"Recovery drill for server {server_id} completed successfully.")
                    
                    # Check launch actions status
                    launch_actions_status = server.get('launchActionsStatus', {})
                    for run in launch_actions_status.get('runs', []):
                        action = run['action']
                        run_status = run.get('status', 'UNKNOWN')  # Handle optional status
                        print(f"  Action '{action['name']}' status: {run_status}")
                        if run_status != 'SUCCEEDED':
                            all_servers_ready = False
                            
                elif launch_status in ['FAILED', 'STOPPED']:
                    print(f"Recovery drill for server {server_id} failed or was stopped.")
                    return False
                else:
                    print(f"Unexpected status for server {server_id}: {launch_status}.")
                    all_servers_ready = False
            
            if all_servers_ready:
                return True
        elif job_status in ['FAILED', 'STOPPED']:
            print(f"Recovery drill job {job_id} failed or was stopped")
            return False
        else:
            print(f"Recovery drill job {job_id} still in progress. Status: {job_status}.")
        
        time.sleep(60)  # Wait for 60 seconds before checking again

def main():
    """
    Main function that connects to AWS DRS using temporary credentials, accepts source server IDs from the command line,
    starts recovery drill, and checks the recovery status and post-launch actions.
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

    # Start recovery drill for all source servers in a single job
    job_id = start_recovery(source_server_ids, drs_client)
    if job_id:
        print("Recovery drill started for all source servers in a single job.")
    else:
        print("Failed to start recovery drill.")
        sys.exit(1)

    # Check recovery job status and individual server recovery status
    if check_recovery_job_status(job_id, source_server_ids, drs_client):
        print("Recovery drill job and all individual server recoveries have completed successfully.")
    else:
        print("Recovery drill job or one or more individual server recoveries failed or were stopped.")
        sys.exit(1)

if __name__ == "__main__":
    main()