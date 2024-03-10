# arh-bulk-policy-update



## Use Case Details

Adding a capability of bulk policy update to multiple Resilience Hub applications. For example, the customer would like to assign same policy XYZ to 20 applications already onboarded in Resilience Hub.
The script takes the below as input:
1. ARN of Resilience Hub policy
2. List of target app ARNs with following alternatives:
    a. Array of script parameters
    b. Filename with app ARNs per line
3. Optional parameter: --assessmentSchedule with valid values Disabled | Daily

Script will call Resilience Hub API [UpdateApp](https://docs.aws.amazon.com/resilience-hub/latest/APIReference/API_UpdateApp.html) to update policy of every given Resilience Hub application and optionally turn on/off daily assessments.