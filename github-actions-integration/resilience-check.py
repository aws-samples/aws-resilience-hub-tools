import boto3
import os
import time

def resilience_check():
    app_arn = os.environ['AppARN']
    StackARN = os.environ['StackARN']

    arh = boto3.client('resiliencehub', region_name='##### Specify AWS Region #####')

    print('Starting import')
    import_resources = arh.import_resources_to_draft_app_version(
        appArn=app_arn,
        sourceArns=[
            StackARN,
        ]
    )

    import_status = arh.describe_draft_app_version_resources_import_status(
        appArn=app_arn
    )

    print('Waiting for import to complete, current status = ' + import_status['status'])

    while (import_status['status'] in {'Pending', 'InProgress'}):
        time.sleep(5)
        import_status = arh.describe_draft_app_version_resources_import_status(
            appArn=app_arn
        )
        print('Waiting for import to complete, current status = ' + import_status['status'])
        
    if import_status['status'] == 'Failed':
        raise Exception('Resource import failed - ' + str(import_status))
        
    print('Import status - ' + import_status['status'])
        
    publish_app = arh.publish_app_version(
        appArn=app_arn
    )
    
    print('Starting assessment')
    start_assessment = arh.start_app_assessment(
            appArn=app_arn,
            appVersion='release',
            assessmentName='GitHub-actions-assessment'
        )

    assessmentARN = start_assessment['assessment']['assessmentArn']

    assessment_status = arh.describe_app_assessment(
    assessmentArn=assessmentARN
    )['assessment']
    
    print('Waiting for assessment to complete, current status - ' + assessment_status['assessmentStatus'])
    
    while (assessment_status['assessmentStatus'] in {'Pending', 'InProgress'}):
        time.sleep(5)
        assessment_status = arh.describe_app_assessment(
            assessmentArn=assessmentARN
        )['assessment']
        print('Waiting for assessment to complete, current status - ' + assessment_status['assessmentStatus'])
        
    print('Assessment status - ' + assessment_status['assessmentStatus'])
        
    if assessment_status['assessmentStatus'] == 'Failed':
        raise Exception('Assessment failed - ' + str(assessment_status))
        
    if assessment_status['complianceStatus'] == 'PolicyBreached':
        print('Resiliency policy breached')
        raise Exception('Resiliency policy breached')
    else:
        print('Resiliency policy met')

if __name__ == "__main__":
    resilience_check()
