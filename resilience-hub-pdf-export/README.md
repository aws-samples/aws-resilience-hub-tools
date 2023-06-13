# Export AWS Resilience Hub assessment results into a PDF file

This guide shows how to export assessment results for all applications defined within AWS Resilience Hub in an account into a PDF file. This PDF file can then be used for better visualisation, analytics, and reporting. The solution can be extended to include results from other accounts as well.

## Execution

1. Ensure you have the necessary libraries installed in your Python environment. You can do so using the pip install command:
   ```
   pip install boto3 reportlab
   ```

2. Run [pdf-generator.py](./pdf-generator.py) in an environment that includes permissions to make API calls to Resilience Hub. The environment also needs to have the [AWS SDK for Python (Boto3)](https://aws.amazon.com/sdk-for-python/) and [ReportLab library](https://www.reportlab.com/) installed.
   
   ```
   python pdf-generator.py
   ```

## Output

The script will generate a PDF file that contains details of all latest assessments for all applications defined within Resilience Hub. The PDF file will be stored in the same location as where the script was executed and contains the following information in a table format:

* **Application Name** - the name of the application as defined within Resilience Hub.
* **Application ARN** - the ARN of an application.
* **Assessment Name** - the name of an assessment for an application.
* **Assessment Compliance Status** - indicates if the associated assessment was evaluated as being compliant with the resiliency policy.
* **End Time** - identifies the end time of an assessment.
* **Estimated Overall RTO** - indicates the estimated achievable Recovery Time Objective (RTO) at the time of assessment (the maximum value across all disruption types is selected).
* **Estimated Overall RPO** - indicates the estimated achievable Recovery Point Objective (RPO) at the time of assessment (the maximum value across all disruption types is selected).
* **Target RTO** - indicates the targeted RTO based on the associated resiliency policy (the minimum value across all disruption types is selected).
* **Target RPO** - indicates the targeted RPO based on the associated resiliency policy (the minimum value across all disruption types is selected).
* **Application Compliance Status** - indicates if the application (based on the latest assessment) was evaluated as being compliant with the resiliency policy.
* **Resiliency Score** - the [resiliency score](https://docs.aws.amazon.com/resilience-hub/latest/userguide/resil-score.html) of the application.
* **Last Assessed** - timestamp of the most recent assessment.
* **Application Tier** - application tier as defined by the resiliency policy associated with the application.

The PDF file has a clean layout, separated for each application, note that it might take a few minutes as we scan every application in every region.
