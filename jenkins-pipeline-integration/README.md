# Integrate AWS Resilience Hub with Jenkins Pipelines

Achieve continual resilience by integrating resilience checks into your Continuous Integration/Continuoys Delivery (CI/CD) pipelines. This solution describes how you can integrate AWS Resilience Hub with your CI/CD pipeline if you are using [Jenkins Pipeline](https://www.jenkins.io/doc/book/pipeline/) and follows a process similar to what is described in [this blog post](https://aws.amazon.com/blogs/architecture/continually-assessing-application-resilience-with-aws-resilience-hub-and-aws-codepipeline/). 

## Prerequisites

**A.	Create an AWS user account for Jenkins with the appropriate permissions**
1.	Sign in to AWS Management console and open the IAM console.
2.	Select **Policies** in the navigation pane and choose **Create policy**.
3.	Select the **JSON** tab.
4.	Replace the example placeholder with the permissions provided in the [Resilience Hub user guide](https://docs.aws.amazon.com/resilience-hub/latest/userguide/security-iam-resilience-hub-permissions.html#security-iam-resilience-hub-same-account).
5.	Choose **Next:Tags**. Followed by **Next:Review**.
6.	On the **Review policy** page, for Name, enter a name for the policy, such as **JenkinsResHubPolicy**.
7.	Choose **Create policy**.
8.	In the navigation pane, choose **Users** and then choose **Add users**.
9.	In the **Set user details** section, specify a user name (for example, JenkinsUser).
10.	In the **Select AWS access type** section, choose **Access key - Programmatic access**.
11.	Choose **Next:Permissions**.
12.	In the **Set permissions** for section, choose **Attach existing policies directly**.
13.	In the filter field, enter the name of the policy you created earlier.
14.	Select the check box next to the policy, and then choose **Next: Tags** followed by **Next:Review**.
15.	Verify the details, and then choose **Create user**.
16.	Save the access and secret keys. You will use these credentials in the next step.

**B.	Install and configure AWS CLI and CloudBees AWS Credentials Plugin on the Jenkins Agent**
1.	Install AWS CLI on the Jenkins agent following the [instructions](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
2.	Install the [aws-credentials](https://plugins.jenkins.io/aws-credentials/) plugin on the Jenkins agent.
3.	Choose **Manage Jenkins**, then **Manage Credentials** and followed by **Add Credentials**.
4.	Select **AWS Credentials**.
5.	Specify an ID and then add the credentials obtained in Step A. Save the credential ID. You will use this in the pipeline script.

## Deployment
Update your pipeline scripts as per the example provided in [Jenkinsfile](./Jenkinsfile). Specifically, add the  **assessment** stage into the script for your pipelines. Ensure that you have updated the following placeholders:
  * **AWS_DEFAULT_REGION** - specify the AWS Region where the application exists on Resilience Hub 
  * **STACK_ARN** - specify the ARN of the AWS CloudFormation stack that you are updating as a part of your deployment
  * **APP_ARN** - specify the ARN of the application you have defined within Resilience Hub
  * **CREDENTIAL_ID** - specify the credential id you added in Step B 5 above.

Note: Install the [Pipeline Utility Steps](https://www.jenkins.io/doc/pipeline/steps/pipeline-utility-steps/) plugin if you do not already have that.
