# Export AWS Resilience Hub assessment results into a CSV file

Export assessment results for all applications defined within AWS Resilience Hub in an account into a CSV file. This CSV file can then be used to perform analytics and reporting. The solution can be expanded to include results from other accounts as well.

## Execution

Run [csv-generator.py](./csv-generator.py) in an environment that includes permissions to make API calls to Resilience Hub. The environment also needs to have the [AWS SDK for Python (Boto3)](https://aws.amazon.com/sdk-for-python/) installed.

```
python csv-generator.py
```

## Output

The script will generate a CSV file that contains details of all assessments for all applications defined within Resilience Hub in a single region. The CSV file will be stored in the same location as where the script was executed and contains the following information:

* **Application Name** - the name of the application as defined within Resilience Hub
* **Assessment Name** - the name of an assessment for an application
* **Assessment Compliance Status** - indicates if the associated assessment was evaluated as being compliant with the resiliency policy
* **End Time** - identifies the end time of an assessment
* **Estimated Overall RTO** - indicates the estimated achievable Recovery Time Objective (RTO) at the time of assessment (the maximum value across all disruption types is selected)
* **Estimated Overall RPO** - indicates the estimated achievable Recovery Point Objective (RPO) at the time of assessment (the maximum value across all disruption types is selected)
* **Target RTO** - indicates the targeted RTO based on the associated resiliency policy (the minimum value across all disruption types is selected)
* **Target RPO** - indicates the targeted RPO based on the associated resiliency policy (the minimum value across all disruption types is selected)
* **Application Compliance Status** - indicates if the application (based on the latest assessment) was evaluated as being compliant with the resiliency policy
* **Resiliency Score** - the [resiliency score](https://docs.aws.amazon.com/resilience-hub/latest/userguide/resil-score.html) of the application
* **Last Assessed** - timestamp of the most recent assessment
* **Application Tier** - application tier as defined by the resiliency policy associated with the application
* **Region** - the AWS Region where the application is defined in Resilience Hub

You can see a sample report here - [sample-resilience-report.csv](./sample-resilience-report.csv)
