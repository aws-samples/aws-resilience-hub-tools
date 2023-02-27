# Integrate AWS Resilience Hub with GitHub Actions

Achieve continual resilience by integrating resilience checks into your Continuous Integration/Continuoys Delivery (CI/CD) pipelines. This solution describes how you can integrate AWS Resilience Hub with your CI/CD pipeline if you are using [GitHub Actions](https://docs.github.com/en/actions) and follows a process similar to what is described in [this blog post](https://aws.amazon.com/blogs/architecture/continually-assessing-application-resilience-with-aws-resilience-hub-and-aws-codepipeline/). 

## Deployment

1. Update your deploy.yaml file as per the example provided in [deploy.yml](./deploy.yml). Specifically, add the last job titled **resilience-check** into your own deploy.yaml file, after all the deployment jobs. Ensure that you have updated the following placeholders with real values based on your use case:
    * **aws-region** - specify the AWS Region where the application exists on Resilience Hub 
    * **StackARN** - specify the ARN of the AWS CloudFormation stack that you are updating as part of your deployment
    * **AppARN** - specify the ARN of the application you have defined within Resilience Hub

    **NOTE: You might have to update the step *Configure AWS Credentials* under the *resilience-check* job depending on the methodology for authenticating access to your AWS environment.**

1. Update the [resilience-check.py](./resilience-check.py) and specify the AWS Region where the application exists on Resilience Hub.
1. Add the script [resilience-check.py](./resilience-check.py) to the **scripts** folder under **.github** (this is located at the root of your project). If the directory **scripts** does not exist, create it under **.github** and add the resilience-check.py script to it.
1. Commit and push these changes to your repository.
