import boto3
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import red, green
from datetime import timedelta

def seconds_to_time(seconds):
    return str(timedelta(seconds=seconds))

# Get list of regions
ec2 = boto3.client('ec2')
regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

doc = SimpleDocTemplate("resilience-report.pdf", pagesize=letter)
flowables = []

style = getSampleStyleSheet()["BodyText"]
header_style = ParagraphStyle('header',
                              parent=style,
                              fontSize=14,
                              spaceAfter=12)

# Loop over each region
for region in regions:
    try:
        arh = boto3.client('resiliencehub', region_name=region)
        apps = arh.list_apps()
    except:
        continue

    # Get list of apps in a region
    app_arns = [app['appArn'] for app in apps['appSummaries']]
    while 'NextToken' in apps:
        apps = arh.list_apps(NextToken = apps['NextToken'])
        for app in apps['appSummaries']:
            app_arns.append(app['appArn'])

    # Loop over list of apps to retrieve details
    for app_arn in app_arns:
        app_details = arh.describe_app(appArn=app_arn)['app']
        app_name = app_details['name']
        app_arn = app_details['appArn']
        app_compliance = app_details['complianceStatus']
        app_res_score = app_details['resiliencyScore']
        app_tier = 'unknown'

        # Check if a resiliency policy is associated with the application
        if 'policyArn' in app_details:
            policy_details = arh.describe_resiliency_policy(policyArn=app_details['policyArn'])
            app_tier = policy_details['policy']['tier']

        flowables.append(Paragraph(f"<u>Application:</u> {app_name}", header_style))
        flowables.append(Spacer(1, 12))
        flowables.append(Paragraph(f"<b>ARN:</b> {app_arn}", style))
        flowables.append(Paragraph(f"<b>Compliance Status:</b> {app_compliance}", style))
        flowables.append(Paragraph(f"<b>Resiliency Score:</b> {app_res_score}", style))
        flowables.append(Paragraph(f"<b>Application Tier:</b> {app_tier}", style))
        flowables.append(Spacer(1, 12))

        if app_compliance != 'NotAssessed':
            assessment_arns = []
            assessment_summaries = arh.list_app_assessments(appArn=app_arn)['assessmentSummaries']

            for assessment in assessment_summaries:
                assessment_arns.append(assessment['assessmentArn'])

            while 'NextToken' in assessment_summaries:
                assessment_summaries = arh.list_app_assessments(appArn=app_arn, NextToken = assessment_summaries['NextToken'])['assessmentSummaries']
                for assessment in assessment_summaries:
                    assessment_arns.append(assessment['assessmentArn'])

            assessment_details_list = [arh.describe_app_assessment(assessmentArn=arn)['assessment'] for arn in assessment_arns]

            # Get the latest assessment
            latest_assessment = max(assessment_details_list, key=lambda x: x['endTime'])

            # Filter successful assessments
            successful_assessments = [a for a in assessment_details_list if a['assessmentStatus'] == 'Success']

            # Get the latest successful assessment
            if successful_assessments:
                latest_assessment = max(successful_assessments, key=lambda x: x['endTime'])
                assessment_name = latest_assessment['assessmentName']
                assessment_compliance_status = latest_assessment['complianceStatus']
                end_time = latest_assessment['endTime']
                flowables.append(Paragraph(f"<b>Latest Assessment Name:</b> {assessment_name}", style))
                flowables.append(Paragraph(f"<b>Assessment Compliance Status:</b> {assessment_compliance_status}", style))
                flowables.append(Paragraph(f"<b>End Time:</b> {end_time}", style))
                flowables.append(Spacer(1, 12))

                for dtype in ['AZ', 'Region', 'Hardware', 'Software']:
                    if dtype in latest_assessment['compliance']:
                        current_rto = seconds_to_time(latest_assessment['compliance'][dtype]['currentRtoInSecs'])
                        target_rto = seconds_to_time(latest_assessment['policy']['policy'][dtype]['rtoInSecs'])
                        current_rpo = seconds_to_time(latest_assessment['compliance'][dtype]['currentRpoInSecs'])
                        target_rpo = seconds_to_time(latest_assessment['policy']['policy'][dtype]['rpoInSecs'])
                        rto_description = latest_assessment['compliance'][dtype]['rtoDescription']
                        rpo_description = latest_assessment['compliance'][dtype]['rpoDescription']

                        rto_color = green if latest_assessment['compliance'][dtype]['currentRtoInSecs'] <= latest_assessment['policy']['policy'][dtype]['rtoInSecs'] else red
                        rpo_color = green if latest_assessment['compliance'][dtype]['currentRpoInSecs'] <= latest_assessment['policy']['policy'][dtype]['rpoInSecs'] else red

                        flowables.append(Paragraph(f"<b>{dtype} Disruption Type:</b>", style))
                        flowables.append(Paragraph(f"<b> <font color='{rto_color}'>Current RTO:</font> </b> {current_rto} <b>Target RTO:</b> {target_rto}", style))
                        flowables.append(Paragraph(f"<b> Description: </b> {rto_description}", style))
                        flowables.append(Paragraph(f"<b> <font color='{rpo_color}'>Current RPO:</font> </b> {current_rpo} <b>Target RPO:</b> {target_rpo}", style))
                        flowables.append(Paragraph(f"<b> Description: </b> {rpo_description}", style))
                        flowables.append(Spacer(1, 12))

doc.build(flowables)

