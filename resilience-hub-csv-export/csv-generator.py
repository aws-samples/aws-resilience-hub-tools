import boto3
import csv

 # Get list of regions
ec2 = boto3.client('ec2')
regions = []
region_details = ec2.describe_regions()['Regions']
for region_detail in region_details:
    regions.append(region_detail['RegionName'])

# Generate a new CSV file and populate headers
with open('resilience-report.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Application Name", "Assessment Name", "Assessment Compliance Status", "End Time", "Estimated Overall RTO", "Estimated Overall RPO", "Target RTO", "Target RPO", "Application Compliance Status", "Resiliency Score", "Last Assessed", "Application Tier", "Region"])

# Loop over each region
for region in regions:
    try:
        arh = boto3.client('resiliencehub', region_name=region)
        apps = arh.list_apps()
    except:
        continue

    # Get list of apps in a region
    app_arns = []
    for app in apps['appSummaries']:
        app_arns.append(app['appArn'])
    while 'NextToken' in apps:
        apps = arh.list_apps(NextToken = apps['NextToken'])
        for app in apps['appSummaries']:
            app_arns.append(app['appArn'])
    
    # Loop over list of apps to retrieve details
    for app in app_arns:
        app_details = arh.describe_app(appArn=app)['app']
        app_name = app_details['name']
        app_compliance = app_details['complianceStatus']
        app_res_score = app_details['resiliencyScore']
        app_tier = 'unknown'
        
        # Check if a resiliency policy is associated with the application
        if 'policyArn' in app_details:
            app_res_policy = app_details['policyArn']
            policy_details = arh.describe_resiliency_policy(
                policyArn=app_res_policy
            )
            app_tier = policy_details['policy']['tier']
        
        # Check if an application has been assessed
        if app_compliance == 'NotAssessed':
            with open('resilience-report.csv', 'a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([app_name, '', 'NotAssessed', '', '', '', '', '', app_compliance, app_res_score, '', app_tier, region])
            continue
        
        app_last_assessed = app_details['lastAppComplianceEvaluationTime']
        
        # Get list of assessments for the application
        assessment_summaries = arh.list_app_assessments(appArn=app)['assessmentSummaries']
        
        while 'NextToken' in assessment_summaries:
            assessment_summaries.append(arh.list_app_assessments(appArn=app, NextToken = assessment_summaries['NextToken'])['assessmentSummaries'])
        
        # Loop over list of assessments to get details
        for assessment in assessment_summaries:
            assessment_arn = assessment['assessmentArn']
            assessment_status = assessment['assessmentStatus']
            
            # Get assessment details if it is a successful assessment
            if assessment_status == 'Success':
                assessment_details = arh.describe_app_assessment(assessmentArn=assessment_arn)

                if assessment_details['assessment']['compliance'] == {}:
                    continue

                assessment_name = assessment_details['assessment']['assessmentName']
                assessment_compliance_status = assessment_details['assessment']['complianceStatus']
                end_time = assessment_details['assessment']['endTime']
                current_rto_az = assessment_details['assessment']['compliance']['AZ']['currentRtoInSecs']
                current_rto_hardware = assessment_details['assessment']['compliance']['Hardware']['currentRtoInSecs']
                current_rto_software = assessment_details['assessment']['compliance']['Software']['currentRtoInSecs']
                current_rpo_az = assessment_details['assessment']['compliance']['AZ']['currentRpoInSecs']
                current_rpo_hardware = assessment_details['assessment']['compliance']['Hardware']['currentRpoInSecs']
                current_rpo_software = assessment_details['assessment']['compliance']['Software']['currentRpoInSecs']
                target_rto_az = assessment_details['assessment']['policy']['policy']['AZ']['rtoInSecs']
                target_rto_hardware = assessment_details['assessment']['policy']['policy']['Hardware']['rtoInSecs']
                target_rto_software = assessment_details['assessment']['policy']['policy']['Software']['rtoInSecs']
                target_rpo_az = assessment_details['assessment']['policy']['policy']['AZ']['rpoInSecs']
                target_rpo_hardware = assessment_details['assessment']['policy']['policy']['Hardware']['rpoInSecs']
                target_rpo_software = assessment_details['assessment']['policy']['policy']['Software']['rpoInSecs']
                
                # Aggregate RTO and RPO values for current and target
                current_rto = max(current_rto_az, current_rto_hardware, current_rto_software)
                current_rpo = max(current_rpo_az, current_rpo_hardware, current_rpo_software)
                target_rto = min(target_rto_az, target_rto_hardware, target_rto_software)
                target_rpo = min(target_rpo_az, target_rpo_hardware, target_rpo_software)
                
                # Check if application is multi-region and updated aggregates accordingly
                if 'Region' in assessment_details['assessment']['policy']['policy']:
                    current_rto_region = assessment_details['assessment']['compliance']['Region']['currentRtoInSecs']
                    current_rpo_region = assessment_details['assessment']['compliance']['Region']['currentRpoInSecs']
                    target_rto_region = assessment_details['assessment']['policy']['policy']['Region']['rtoInSecs']
                    target_rpo_region = assessment_details['assessment']['policy']['policy']['Region']['rpoInSecs']
                    
                    if current_rto < current_rto_region:
                        current_rto = current_rto_region
                    if current_rpo < current_rpo_region:
                        current_rpo = current_rpo_region
                    if target_rto > target_rto_region:
                        target_rto = target_rto_region
                    if target_rpo > target_rpo_region:
                        target_rpo = target_rpo_region
                
                # Populate data into the CSV file    
                with open('resilience-report.csv', 'a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([app_name, assessment_name, assessment_compliance_status, end_time.strftime("%Y-%m-%d %H:%M:%S"), current_rto, current_rpo, target_rto, target_rpo, app_compliance, app_res_score, app_last_assessed.strftime("%Y-%m-%d %H:%M:%S"), app_tier, region])
                    