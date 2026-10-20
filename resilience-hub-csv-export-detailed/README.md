# Export AWS Resilience Hub assessment results into a CSV file (detailed version)

This folder has one script for each version of AWS Resilience Hub:

| Script | Use it for | Writes |
|---|---|---|
| [csv-generator.py](./csv-generator.py) | AWS Resilience Hub (classic): applications, assessments and the resiliency score | a CSV file |
| [csv-generator-nextgen.py](./csv-generator-nextgen.py) | Next generation AWS Resilience Hub: services, failure mode assessments, findings and resilience tests | a CSV file, a colored Excel copy and an HTML report |

Both scripts are read-only. They check every enabled Region of the account and write their files to the current directory.

## AWS Resilience Hub (classic): csv-generator.py

Export assessment results for all applications defined within AWS Resilience Hub in an account into a CSV file. This CSV file can then be used to perform analytics and reporting. The solution can be expanded to include results from other accounts as well. This script outputs the detailed version of the assessment, including fields related to the resilience score breakdown (RPO/RTO, Test, SOP and Alert scores).

### Execution

Run [csv-generator.py](./csv-generator.py) in an environment that includes permissions to make API calls to Resilience Hub. The environment also needs to have the [AWS SDK for Python (Boto3)](https://aws.amazon.com/sdk-for-python/) installed.

```
python3 csv-generator.py
```

On Windows, use `python csv-generator.py`.

### Output

The script will generate a CSV file that contains details of all assessments for all applications defined within Resilience Hub in every enabled Region. The CSV file will be stored in the same location as where the script was executed and contains the following information:

* **Application Name** - the name of the application as defined within Resilience Hub
* **Assessment Name** - the name of an assessment for an application
* **Assessment Compliance Status** - indicates if the associated assessment was evaluated as being compliant with the resiliency policy
* **End Time** - identifies the end time of an assessment
* **Estimated Overall RTO** - indicates the estimated achievable Recovery Time Objective (RTO) at the time of assessment (the maximum value across all disruption types is selected)
* **Estimated Overall RPO** - indicates the estimated achievable Recovery Point Objective (RPO) at the time of assessment (the maximum value across all disruption types is selected)
* **Target RTO** - indicates the targeted RTO based on the associated resiliency policy (the minimum value across all disruption types is selected)
* **Target RPO** - indicates the targeted RPO based on the associated resiliency policy (the minimum value across all disruption types is selected)
* **Application Compliance Status** - indicates if the application (based on the latest assessment) was evaluated as being compliant with the resiliency policy
* **Resiliency Score** - the [resiliency score](https://docs.aws.amazon.com/resilience-hub/latest/userguide/resil-score.html) of the application. Max value 100.
* **RTO/RPO Compliance** - the resilience score breakdown for RPO/RTO. Max value 40.
* **Alarms Implemented** - the resilience score breakdown for Alarms. Max value 20.
* **SOPs Implemented** - the resilience score breakdown for SOPs. Max value 20.
* **FIS Experiments Implemented** - the resilience score for resilience testing using FIS. Max value 20. 
* **Last Assessed** - timestamp of the most recent assessment
* **Application Tier** - application tier as defined by the resiliency policy associated with the application
* **Region** - the AWS Region where the application is defined in Resilience Hub

You can see a sample report here - [sample-resilience-report.csv](./sample-resilience-report.csv)

## Next generation AWS Resilience Hub: csv-generator-nextgen.py

The next generation of AWS Resilience Hub (generally available since May 28, 2026) models workloads as services and evaluates them with failure mode assessments. It has no resiliency score, so `csv-generator.py` can't export it. [csv-generator-nextgen.py](./csv-generator-nextgen.py) exports every next generation service in the account and:

* derives a resiliency score on the same 0–100 scale, with the same 40-point RTO/RPO part as the classic score
* checks each service against the requirements of the two milestones of the AWS Resilience Acceleration Pilot (RAP): M1 Assessment and M2 Remediation
* lists the findings to address and the findings fixed

### Regions

Next generation Resilience Hub is available in us-east-1, us-east-2, us-west-2, ca-central-1, eu-west-1, eu-west-2, eu-west-3, eu-central-1, eu-north-1, ap-south-1, ap-southeast-1, ap-southeast-2, ap-northeast-1, ap-northeast-2 and sa-east-1 (checked October 19, 2026). In me-south-1, eu-south-1, af-south-1, ap-east-1 and us-west-1 only the classic version is available: the script reports these Regions, and `csv-generator.py` exports their applications. A service can include resources from other Regions; the **Workload Regions** column shows where it runs.

Sources: [Supported Regions](https://docs.aws.amazon.com/resilience-hub/latest/userguide/next-gen-supported-regions.html), [Resilience Hub endpoints](https://docs.aws.amazon.com/general/latest/gr/resiliencehub.html), [Migrating from classic](https://docs.aws.amazon.com/resilience-hub/latest/userguide/next-gen-migrating.html).

### Execution

You need Python 3.8 or later, Boto3 1.43.62 or later (the first version with the next generation testing APIs) and credentials with these read-only permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "resiliencehub:ListServices",
        "resiliencehub:GetService",
        "resiliencehub:ListFailureModeAssessments",
        "resiliencehub:ListFailureModeFindings",
        "resiliencehub:ListTestRuns",
        "resiliencehub:ListTestTemplates",
        "sts:GetCallerIdentity",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    }
  ]
}
```

```
pip3 install --upgrade boto3
python3 csv-generator-nextgen.py
```

On Windows, use `python csv-generator-nextgen.py`. In AWS CloudShell, upgrade with `pip3 install --user --upgrade boto3`, because CloudShell can ship a Boto3 version without next generation support. With an older Boto3, the script prints the upgrade command and stops before any API call.

The script needs network access only to call the AWS APIs.

### Output

The script writes three files named `resilience-report-<account-id>-<mm-dd-yy-HH_MM>`, the same file name pattern as `csv-generator.py`:

* **.csv** - the report
* **.xlsx** - a colored copy to read in Excel (READY in green, NOT READY in red), written with the Python standard library
* **.html** - a report page built with [Cloudscape](https://cloudscape.design), the design system of the AWS console: an overview, a page per service with every requirement and its actual value, and the findings and assessments tables. The page is self-contained and works offline: React, the Cloudscape components and the font are inlined, and its Content-Security-Policy blocks every network request. It needs JavaScript.

The terminal shows the same pre-check, in color when the terminal supports it (`NO_COLOR` and `FORCE_COLOR` are honored). Don't open and re-save the CSV in Excel: values such as `10/20` turn into dates.

The CSV has one row per successful failure mode assessment, newest first. A service that has never been assessed gets one row with `NotAssessed`. The service columns repeat on each row of the service; the assessment columns describe the assessment of the row.

* **Application Name** - the service name
* **RAP M1 Assessment Check** - `READY` when the service meets every M1 Assessment requirement (see below), otherwise `NOT READY`
* **RAP M2 Remediation Check** - `READY` when the service meets every M2 Remediation requirement, otherwise `NOT READY`
* **RAP Gaps** - the requirements not met, plus notes for the reviewer: fixes marked resolved but not yet verified by an assessment, and HIGH findings marked irrelevant. `None` when nothing is missing
* **Resiliency Score (RAP-derived)** - 0–100, the sum of the next three columns
* **RTO/RPO Compliance** - `x/40`, from the latest assessment
* **Findings Remediated** - `x/40`
* **Recovery Tests Score** - `x/20`
* **HIGH Findings Fixed** - for example `3 of 4 (75%)`, plus `; 1 irrelevant` when HIGH findings are marked irrelevant
* **Target RTO** - the strictest of the Multi-AZ and Multi-Region RTO targets of the resilience policy
* **Target RPO** - the strictest of the Multi-AZ RPO, Multi-Region RPO and data recovery (time between backups) targets
* **Application Compliance Status** - `PolicyMet` when every DR target of the policy is rated achievable, otherwise `PolicyBreached`; `MissingPolicy` when the policy has no DR target; `NotAssessed`
* **Rerun Needed** - `Yes` when the service configuration changed after the last assessment
* **Recovery Test Runs** - the latest finished run of each required recovery test
* **Open Findings**, **Resolved Findings**, **Resolved Pending Re-assessment**, **Irrelevant Findings** - counts by severity, for example `H:1 M:0 L:2`
* **Assessment ID**, **Assessment Compliance Status**, **End Time** - the failure mode assessment of the row
* **Achievability** - the rating of each policy component in the assessment of the row
* **Findings In Assessment** - the number of findings the assessment of the row produced
* **Last Assessed** - the end time of the latest successful assessment
* **Policy** - the resilience policy name(s)
* **Region** - the Region where the service is defined
* **Workload Regions** - the Regions where the service operates
* **Service Account** - the account that owns the service
* **Findings To Address** - open findings, HIGH first, with the policy component they affect, for example `[HIGH] <name> (Multi-AZ)`
* **Findings Fixed** - findings fixed and verified by an assessment

You can see a sample report here - [sample-resilience-report-nextgen.csv](./sample-resilience-report-nextgen.csv)

### How the score is derived

The score uses the same 0–100 scale as the classic resiliency score. Missing or unverified data never raises it.

* **RTO/RPO compliance (40)** - 40 × the share of the policy's DR targets (Multi-AZ, Multi-Region, data recovery) rated `ACHIEVABLE` by the latest assessment. A target the assessment didn't rate counts as not achievable.
* **Findings remediated (40)** - the share of findings fixed, weighted HIGH 3, MEDIUM 2, LOW 1. Findings marked irrelevant are left out. A finding marked resolved counts once a later successful assessment has verified it: the assessment ended after the finding was marked, with a 15-minute margin.
* **Recovery tests (20)** - the share of required recovery tests whose latest finished run passed. The AZ recovery test is always required; Multi-Region recovery is required when the policy has Multi-Region targets.

### RAP milestone checks

| Check | READY when every requirement is met |
|---|---|
| RAP M1 Assessment Check | a successful failure mode assessment; Target RTO ≤ 4 hours; Target RPO ≤ 15 minutes; the assessment is current (Rerun Needed = `No`) |
| RAP M2 Remediation Check | all M1 Assessment requirements; RTO/RPO compliance 40/40; score ≥ 70; at least 80% of HIGH findings fixed and verified; the latest AZ recovery test run passed |

READY is a pre-check of what Resilience Hub data can show, not an approval. For the RAP fund request requirements, refer to your AWS Partner Development Manager (PDM).

### The report page

The `.html` page is built from [csv-generator-ui](./csv-generator-ui) (React and the Cloudscape components) and embedded in the script, so the script stays a single file. The script only fills in the report data. To change the page, edit `csv-generator-ui/src/` and rebuild with `npm ci --ignore-scripts && npm run build` in that folder. The licenses of the bundled packages are listed in the page.
