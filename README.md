Security Specialty Project
Welcome to my Security Monitoring System for KMS and Secrets Manager.

In this project, we will build a security-focused monitoring and response architecture using multiple AWS services.
The environment will include a secret stored in AWS Secrets Manager, encrypted using a Customer Managed Key (CMK) from AWS KMS. We will configure a strict key policy to ensure that only authorized administrators can manage the key.
Additionally, we will configure AWS CloudTrail to monitor API calls related to both Secrets Manager and KMS. CloudTrail logs will be delivered to an encrypted Amazon S3 bucket protected with bucket policies to ensure audit log retention and integrity.
In the event of a malicious or unauthorized API call against the secret or the CMK, Amazon EventBridge will capture the event and trigger an AWS Lambda function. The Lambda function will automatically remediate or roll back unauthorized configuration changes. Finally, Amazon SNS will notify administrators about the security incident.


⸻


1. First Step: Create Users
We will begin by creating a KMS administrator user. The goal is to ensure the user follows the principle of least privilege.
I will name the user “axel-kms-admin” and grant AWS Management Console access.
![Security Project](screenshots/axelkmsadmin.png)

In this case, I will attach an inline policy directly to the user. However, in a production environment, administrators would typically belong to a group with policies attached to the group itself. That approach follows AWS best practices, but for this lab environment, I will keep the configuration simple.
As shown below, the policy is written in JSON format. This is an Identity-Based Policy. These policies define what actions a user, role, or group can perform within an AWS account.
In this case, I will allow only the permissions required for the services used throughout this project.
Important Note:
In AWS, every action is denied by default unless it is explicitly allowed. If an action is not explicitly allowed, AWS automatically treats it as an implicit deny.
Additionally, even if an Identity-Based Policy explicitly allows access, another policy type can still override it with an explicit deny.
For example, a user may have permission to access an S3 bucket through an Identity-Based Policy, but if the bucket’s Resource-Based Policy explicitly denies access, the final result will still be a deny.
To successfully perform an action in AWS:
* The action must be explicitly allowed.
* The action must not be explicitly denied by any other applicable policy.
![Security Project](screenshots/kmsadminpolicy.png)

Now I will create a Permission Boundary.
A Permission Boundary is another type of policy that defines the maximum permissions a user or role can have. Even if an Identity-Based Policy or Resource-Based Policy allows an action, the action will still be denied if the Permission Boundary does not allow it.
Permission Boundaries are extremely useful for restricting privilege escalation and controlling which services or actions administrators can access.

![Security Project](screenshots/kmsadminboundary.png)
![Security Project](screenshots/kmsadminboundary2.png)

Now we go back to the user creation process and attach both policies.
![Security Project](screenshots/kmsadminpoliciesattached.png)

At this point, we have successfully created our KMS administrator user.
 ![Security Project](screenshots/adminusercreated.png)


⸻


Now I will log in as the axel-kms-admin user and navigate to AWS KMS to create our Customer Managed Key (CMK).
A CMK is an encryption key created and managed by the customer. It gives us full control over the key configuration, policies, rotation settings, and administrative permissions.

![Security Project](screenshots/creationofkmskey.png)
We will create a symmetric key for encryption and decryption operations.
Symmetric keys use the same cryptographic key for both encryption and decryption. In contrast, asymmetric keys use a public/private key pair and are commonly used for signing or verification operations.
Typically, the public key can be distributed externally, while the private key remains securely managed by AWS KMS and is never exposed to customers.

![Security Project](screenshots/creationofkmskey2.png)

Under the Alias configuration, we will name the key:
cmk-for-secrets-manager
Aliases are useful because they provide a friendly name for KMS keys. They are especially valuable for manual key rotation strategies.
For example, if automatic rotation is not supported for a specific key type (commonly asymmetric keys), we can create a new key and assign the same alias to it. Applications continue using the alias without requiring configuration changes.
Descriptions and tags are optional.
Tags can also be used for Attribute-Based Access Control (ABAC). For example, we could allow a principal to use a KMS key only if the resource tag Environment=Dev is present.
For this lab, we will leave tags as default.

![Security Project](screenshots/creationofkmskey3.png)

At this point, we encounter an error.
When designing IAM permissions, we usually grant only the minimum permissions required for the user to perform their tasks. In this case, we intentionally restricted some IAM actions, but our KMS administrator still requires certain IAM permissions to list users and attach policies during the KMS key creation process.
To troubleshoot this issue, we must review both the Identity-Based Policy and the Permission Boundary to determine which policy is denying the required actions.
Additionally, we will create another user that will only be allowed to encrypt and decrypt data using the KMS key through Secrets Manager.
This second user will also use a Permission Boundary, but access to the KMS key itself will be granted through the KMS Resource-Based Policy.
![Security Project](screenshots/kmserrorkeypolicycreation.png)

Now, within the IAM Console, let’s review both the Identity-Based Policy and the Permission Boundary.

![Security Project](screenshots/identitybasedpolicy.png)
![Security Project](screenshots/permissionboundary.png)

As shown below, we do not currently have an explicit allow for:
* iam:ListUsers
* iam:ListRoles
Additionally, our Permission Boundary does not allow these actions either.
As mentioned previously, if an action is not explicitly allowed, AWS denies it by default.
Let’s update the Identity-Based Policy first.
![Security Project](screenshots/resolvingissueidentitybasedpolicy.png)
However, notice that our Permission Boundary still does not allow iam:ListUsers and iam:ListRoles.
Even though we added the permissions to the Identity-Based Policy, the Permission Boundary still blocks them.
To resolve this, we will update the Permission Boundary and allow only:
* iam:ListUsers
* iam:ListRoles
![Security Project](screenshots/ResolvingIssuePermissionBoundary.png)
Great — before returning to KMS, we now need to create another user named “axel-user”.
This user will only be allowed to encrypt and decrypt data using the KMS key, but will not be able to manage or view the key configuration itself.
![Security Project](screenshots/axelkmsuser.png)

We will also attach a Permission Boundary to this user.

![Security Project](screenshots/permissionboundaryaxeluser.png)
![Security Project](screenshots/permissionboundaryaxeluser2.png)
![Security Project](screenshots/axelusercreated.png)


Now, returning to the axel-kms-admin user, we can configure:
* Key administrators
* Key users
![Security Project](screenshots/keyadmins.png)
![Security Project](screenshots/keyusers.png)
At this point, we can finally create the KMS key.
AWS will automatically generate a KMS Key Policy based on the administrators and users we configured previously.

![Security Project](screenshots/kmskeycreated.png)
![Security Project](screenshots/kmskeycreated2.png)

If you encounter an error requesting the permission tag:GetResources, you must update both:
* The Identity-Based Policy
* The Permission Boundary

![Security Project](screenshots/tagresourcesIdentitybasedpolicy.png)
![Security Project](screenshots/tagresourcespermissionboundary.png)

-------------------------------------------------------------------------
# Next Step: Create a Secret in AWS Secrets Manager

Next, we will navigate to AWS Secrets Manager and create a new secret.

Before doing so, we must grant our user the necessary permissions.

As shown previously, AWS Secrets Manager is already allowed in the user's Permission Boundary. However, services must also be explicitly allowed within the user's Identity-Based Policy.

![Security Project](screenshots/secretsmanagerallowedforkmsuser.png)
![Security Project](screenshots/secretsmanagerallowedforkmsuser2.png)

Now we will log in using the **axel-kms-user** account and navigate to the AWS Secrets Manager console.

Create a new secret and select:

* **Other type of secret**

We will use the **Key/Value** format.

In my case, the secret name will be:

`SecuritySpecialty/projectmadebyaxel`

Under the **Encryption Key Configuration**, we will select the KMS key we created previously:

* `cmk-for-secrets-manager`

However, at this point we encounter another issue.

AWS displays an error indicating that the user does not have the `kms:ListAliases` permission.

This happens because `kms:ListAliases` is required for AWS Secrets Manager to list available KMS aliases during the secret creation process. Since this is considered a broader KMS operation, we must explicitly allow it within the user's Identity-Based Policy.

![Security Project](screenshots/idbspolforuser.png)

Now attach the updated policy to the user.

![Security Project](screenshots/idbspolforuser2.png)

After updating the permissions, the previous error disappears.

![Security Project](screenshots/creationofsecret2.png)

You can skip the remaining optional configurations, such as **automatic rotation**.

Automatic rotation allows Secrets Manager to rotate secrets automatically using an AWS Lambda function. This feature is commonly used for database credentials, API keys, or other sensitive secrets that require periodic rotation for security purposes.

For this lab environment, we will simply store the secret.

![Security Project](screenshots/creationofsecret3.png)

At this point, our secret has been successfully created.

(screenshots/secretsuccessfullycreated.png)

---

# Behind the Scenes: KMS Grants

To allow AWS services such as Secrets Manager to use a Customer Managed KMS Key on behalf of a user, additional permissions are required.

The following permissions are commonly needed:

* `kms:CreateGrant`
* `kms:ListGrants`
* `kms:RetireGrant`

These permissions can be granted either through:

* an Identity-Based Policy, or
* the KMS Key Resource-Based Policy.

KMS Grants allow AWS services to temporarily use the CMK for cryptographic operations without permanently exposing permissions.

Once the operation is completed, the grant can be retired automatically.

![Security Project](screenshots/grantpermissions.png)
--------------------------------------------
# Testing KMS Permissions

Now let's perform a quick test to demonstrate the difference between what a KMS administrator can do versus what a KMS user can do.

For this step, you will need to create and attach the required policy to both:

* `axel-kms-admin`
* `axel-kms-user`

We will use AWS CloudShell to test the permissions.

You will need the following policy configuration:

---

Next, we will attempt to encrypt a file using AWS KMS.

Before starting, let's verify our current identity using:

```bash
aws sts get-caller-identity
```

This command allows us to confirm which IAM user or role is currently authenticated.

Now list the KMS keys available in the AWS account.

After that, create a file named:

```bash
file.txt
```

Inside the file, write:

```text
SecurityProject
```

Now, from both accounts, execute the following command:

```bash
aws kms encrypt --key-id (KMS key ARN or alias) --plaintext fileb://file.txt --output text --query CiphertextBlob
```

As shown below:

* the **KMS administrator** cannot encrypt the file,
* while the **KMS user** successfully encrypts the data.

![Security Project](screenshots/cloudshelladmin.png)
![Security Project](screenshots/cloudshelluser.png)

This behavior occurs because the administrator user is only authorized to manage the KMS key itself.

Typical administrative permissions include:

* creating keys,
* deleting keys,
* attaching policies,
* configuring aliases,
* and managing key settings.

However, the administrator is not allowed to perform cryptographic operations unless those permissions are explicitly granted.

In contrast, the KMS user is authorized to perform cryptographic actions such as:

* `kms:Encrypt`
* `kms:Decrypt`
* `kms:GenerateDataKey`
* and grant-related operations for AWS services.

This separation of duties is an important security best practice because it prevents administrators from accessing sensitive encrypted data while still allowing them to manage the encryption infrastructure.
-------------------------------------------------------------
# Next Step: Monitoring, Detection, and Remediation Pipeline

In this step, we will build a full security pipeline for monitoring, detecting, and remediating events using:

* AWS CloudTrail
* Amazon EventBridge
* AWS Lambda
* Amazon SNS

---

## IAM Permissions Setup for KMS Admin

First, we need to attach the required permissions to the **axel-kms-admin** user in order to manage all services involved in the pipeline.

We will create separate policies for each service:

* CloudTrail access policy
* EventBridge access policy
* Lambda access policy
* SNS access policy

A critical permission required in this setup is:

**`iam:PassRole`**

This permission allows the admin to assign an execution role to Lambda functions.

However, we must carefully scope this permission.

We will restrict the **Resource** field so that the user can only pass roles to a specific Lambda function. If we use `"*"`, the user could assign arbitrary IAM roles to services, which introduces a serious privilege escalation risk.

---

### CloudTrail Policy

![Security Project](screenshots/cloudtrailpolicy.png)

### EventBridge Policy

![Security Project](screenshots/eventbridgepolicy.png)

### SNS Policy

![Security Project](screenshots/snspolicy.png)

### Lambda Policy

![Security Project](screenshots/lambdapolicy.png)

After creating these policies, we update both:

* the Identity-Based Policies
* the Permission Boundary

![Security Project](screenshots/policiesattached.png)

---

## S3 Access for CloudTrail Logs

We also need to allow access to Amazon S3, since CloudTrail stores logs in an S3 bucket.

This step is required for proper logging and auditing.

![Security Project](screenshots/s3policy.png)

---

## CloudTrail Configuration

Now we go to the CloudTrail console and create a new Trail.
![Security Project](screenshots/cloudtrail.png)

As part of the setup, CloudTrail automatically creates an S3 bucket to store logs.

The trail name can be left as default or customized.

![Security Project](screenshots/cloudtrail2.png)

Once the trail is created:

* the S3 bucket is automatically provisioned
* CloudTrail starts delivering logs

AWS also automatically generates a bucket policy that restricts access so that only CloudTrail can write logs to it.

![Security Project](screenshots/s3cloudtrail.png)

---

## S3 Encryption

By default, S3 buckets use **SSE-S3 encryption**, which is fully managed by AWS.

Alternatively, we can use **SSE-KMS encryption**, which provides stronger control and auditing.

However, with SSE-KMS:

* users must have permission to access the S3 bucket
* AND permission to use the KMS key used for encryption and decryption

This adds an additional security layer for sensitive audit logs.

![Security Project](screenshots/bucketencryption.png)

---

## EventBridge Setup

Now we configure Amazon EventBridge.

We will create a rule using an event pattern.

![Security Project](screenshots/eventbridge.png)

At this stage, we encounter an error.

This happens because our Identity-Based Policy does not yet allow:

* `events:ListEventBuses`
* `events:CreateEventBus`
* `events:DescribeEventBus`

To fix this, we update the policy and add the required permissions.
![Security Project](screenshots/eventbridgefixingpolicy.png)

After applying the fix, we go back to EventBridge to create the rule again, and the error should now be resolved.

![Security Project](screenshots/rulecreation.png)

Next, under Event source, we select:

Other

Then we choose:

Custom pattern (JSON editor)

Here we define an event pattern to filter specific API calls, since these operations can represent a potential security risk and must be monitored closely.

![Security Project](screenshots/rulecreation2.png)
---

## Lambda Function Creation

Before completing the EventBridge rule, we must create our Lambda function.

Go to AWS Lambda and select:

* **Author from scratch**
* Function name: `kms-remediation-function`
* Runtime: Python 3.10 (later upgraded to 3.13)

![Security Project](screenshots/lambdafunctioncreated.png)
![Security Project](screenshots/lambdafunctioncreated2.png)

Once created, we copy the Lambda ARN for later use in IAM policy scoping.

---

## Fine-Grained Lambda Permissions

Now we refine our Lambda permissions.

Instead of using `"Resource": "*"`, we scope permissions to:

* the specific Lambda function ARN

This ensures the user can only manage and invoke this specific function.

We define three policy sections:

### 1. Lambda administration (scoped to function ARN)

Allows management operations only on the remediation Lambda.

![Security Project](screenshots/statement1.png)

### 2. Global listing permissions

Used for discovery operations such as listing Lambda functions.

These require `"Resource": "*"` because they are not resource-specific.

However, modification permissions remain restricted to the Lambda ARN.
![Security Project](screenshots/statement2.png)

### 3. CloudWatch Logs permissions

Used for debugging and execution monitoring.

![Security Project](screenshots/statement3.png)

Final Lambda policy:

![Security Project](screenshots/policyforlambdafunction.png)

---

## EventBridge Target Configuration

Now we return to EventBridge.

We set the target as:

* Lambda function: `kms-remediation-function`

We also create a new IAM role that allows EventBridge to invoke the Lambda function.

![Security Project](screenshots/rulecreation3.png)

At this stage, we encounter another error.

The issue is that our Permission Boundary does not allow IAM role creation.

We update the Permission Boundary accordingly.

![Security Project](screenshots/rulecreationerror.png)

---

## IAM Role Creation Fix

We add the required API actions to the Permission Boundary.

However, this alone is not enough.

We also need to update the Identity-Based Policy to explicitly allow the action.

![Security Project](screenshots/fixingroleerror.png)

After updating both policies, the issue is resolved.

![Security Project](screenshots/idbpfixed.png)

If errors persist, we must also verify:

* `iam:AttachRolePolicy`
* Permission Boundary deny statements

![Security Project](screenshots/denystatement.png)

---

## iam:PassRole Configuration

We also need to allow `iam:PassRole` for the KMS admin.

This permission must be carefully scoped:

* Preferably limited to specific IAM roles
* Constrained using `iam:PassedToService`

For this lab, we temporarily allow broader scope (`Resource: "*"`) while restricting services to:

* `lambda.amazonaws.com`
* `events.amazonaws.com`

This ensures the role can only be passed to EventBridge and Lambda services.

![Security Project](screenshots/passroleadminboundary.png)
![Security Project](screenshots/passroleadminidbp.png)

---

## EventBridge Rule Creation Success

After fixing all permissions, we successfully create the EventBridge rule.

![Security Project](screenshots/rulecreation4.png)
![Security Project](screenshots/rulesuccessfullycreated.png)

---

## Testing the Pipeline

To test the system:

1. We deploy a Python function in Lambda that logs incoming events
2. We trigger a change by disabling the CMK using AWS CLI
3. We ensure Lambda is deployed after every code update

![Security Project](screenshots/testingpipeline1.png)
![Security Project](screenshots/testingpipeline2.png)

In CloudWatch Logs, we can see:

* the event received
* user identity
* timestamp
* action performed on the CMK

This confirms that our monitoring pipeline is working correctly.

---

## Final Result

We now have a fully functional security pipeline:

CloudTrail → EventBridge → Lambda → SNS

It successfully:

* detects sensitive API calls
* logs security events
* triggers automated responses
* provides visibility into user activity

---

## Runtime Upgrade Note

Finally, we updated the Lambda runtime from Python 3.10 to Python 3.13 due to deprecation of the older version.

//////////////////////////////////////////////////////////////////////
Remediation and Notification

Now it's time to implement the remediation and notification components of our solution.

Let's move to Python and PyCharm.

The project contains the following files:

pythonexamplecode.py
eventexample.json
template.yaml

As shown below, this is the code I wrote for the Lambda function. While the implementation is relatively simple, it is sufficient for the requirements of this project.

The lambda_function.py file contains the business logic executed when the Lambda function is triggered. This is where the remediation actions are performed in response to the events captured by EventBridge.

I also included an eventexample.json file, which represents a sample event generated by EventBridge after receiving information from CloudTrail. This file can be used to simulate and test events locally.

Finally, the template.yaml file defines the AWS SAM configuration, including:

The Lambda function location
The handler
The runtime
The function name
Other deployment settings

Using these three files, you can test the solution locally with AWS SAM before deploying it to AWS.

In addition, a requirements.txt file is included to install all dependencies required to execute the Lambda function locally.

Granting Permissions to the Lambda Function

Before uploading our Lambda function, we need to configure the permissions it requires.

Navigate to the AWS Lambda Console and open the function.

The function will need permissions to interact with:

AWS KMS
Amazon SNS

These permissions are required because the Lambda function will perform remediation actions and send notifications when security events occur.

While reviewing the Lambda function under:

Configuration → Permissions

we encounter an error indicating that our Permission Boundary does not allow the iam:GetRole action.

Let's fix that first.

![Security Project](screenshots/getiampolicyerror.png)

Hardening IAM Policies

Before proceeding, we will improve the security posture of our environment by hardening the IAM policies and Permission Boundaries.

The initial policies were intentionally broader to simplify the setup process. Now we will replace them with more restrictive configurations that better follow security best practices.

Creating Dedicated Permission Boundaries

We will create two separate Permission Boundaries:

One for the KMS administrator
One for the KMS user

Permission Boundaries should be designed according to the responsibilities of the identity they are attached to.

KMS Administrator Permission Boundary

For the KMS administrator, we will allow only the services required for this project, including:

AWS KMS
AWS Secrets Manager
AWS CloudTrail
Amazon CloudWatch Logs
Amazon SNS
Amazon EventBridge
AWS Lambda
tag:GetResources
AWS CloudShell

In this lab environment, the KMS administrator also performs certain security administration tasks.

In a production environment, these responsibilities would typically be separated across multiple roles. For example:

One administrator would manage KMS.
Another administrator would manage IAM.
Security operations personnel would manage monitoring and incident response.

However, for simplicity, the lab consolidates these responsibilities into a single user.

We will also explicitly deny privilege escalation actions to reduce the risk of abuse.

Finally, we allow role passing operations using carefully scoped conditions.

Role passing is one of the most sensitive IAM permissions because it can be abused to obtain elevated privileges.

For this reason, we restrict it using the iam:PassedToService condition so that roles can only be passed to approved AWS services such as:

Lambda
EventBridge

![Security Project](screenshots/permissionboundaryforadminkms.png) 
![Security Project](screenshots/permissionboundaryforadminkms2.png)

Save the Permission Boundary and attach it to the KMS administrator.

Here goes attachedpermissionboundarytokmsadmin.png

KMS User Permission Boundary

Next, we create a dedicated Permission Boundary for the KMS user.

This boundary grants only the permissions required to perform cryptographic operations while explicitly denying actions that could result in privilege escalation.

![Security Project](screenshots/permissionboundaryforuserkms.png)
![Security Project](screenshots/permissionboundaryforuserkms2.png)

Attach the Permission Boundary to the KMS user.

![Security Project](screenshots/permissionboundaryattachedtokmsuser.png)

Identity-Based Policy Hardening

Now let's review our Identity-Based Policies.

KMS Administrator Policy

Previously, our KMS administrator policy included permissions for several services.

To better align with the principle of least privilege, we will reduce the scope of this policy so that it contains only permissions directly related to KMS administration.

This is closer to what a real KMS administrator policy would look like.

![Security Project](screenshots/idbpforarealkmsadmin.png)

IAM Administrator Policy

Next, we create a separate policy for IAM administration.

For the purposes of this lab, we will attach it to the same user.

In a production environment, this policy would normally be assigned to a dedicated IAM administrator and would likely contain additional restrictions.

![Security Project](screenshots/idbpforIAMadmin.png)

Hardening the PassRole Policy

Finally, we revisit the PassRole policy.

This is one of the most sensitive permissions in AWS because it allows users to delegate IAM roles to AWS services.

If not properly restricted, it can become a significant privilege escalation vector.

To mitigate this risk, we use the iam:PassedToService condition.

This ensures that IAM roles can only be passed to specific AWS services that are required for the solution.

In our case, the policy allows role passing only to approved services such as:

AWS Lambda
Amazon EventBridge

This approach significantly reduces the attack surface while still allowing the functionality required by the project.

![Security Project](screenshots/fixingpassrolepolicy.png)

///////////////////////////////////////
## Hardening the KMS User Identity-Based Policy

Next, we will improve the security of the Identity-Based Policy attached to our KMS user.

Previously, we created a policy called:

`secrets-manager-policy-for-user`

While functional, the policy was not as restrictive as we would like from a security perspective. To better align with the principle of least privilege, we will redesign it.

As mentioned earlier, AWS requires broader permissions for resource discovery operations. Because of this, our first statement allows the user to discover Secrets Manager resources.

### Statement 1 – Secret Discovery

This statement allows:

* `secretsmanager:ListSecrets`

Since this is a discovery operation, AWS requires the permission to be granted with:

```json
"Resource": "*"
```

This is a common pattern across AWS services for list and discovery APIs.

### Statement 2 – Secret Management

The second statement is responsible for managing the secret itself.

Here we apply the principle of least privilege by granting only the permissions required to interact with the specific secret.

Examples include:

* `secretsmanager:DescribeSecret`
* `secretsmanager:GetResourcePolicy`
* `secretsmanager:GetSecretValue`
* `secretsmanager:ListSecretVersionIds`
* `secretsmanager:TagResource`

Unlike discovery permissions, these actions are scoped directly to the specific secret ARN.

This prevents the user from accessing secrets owned by other users or applications within the account.

If the user needs to create additional secrets in the future, we can explicitly grant the required creation permissions while maintaining strict resource scoping wherever possible.

![Security Project](screenshots/secrets-manager-idbp-user.png)

At this point, we have significantly improved the security posture of our Identity-Based Policies and Permission Boundaries.

Now let's continue hardening the remaining policies and Resource-Based Policies.

---

## Hardening Service Policies

Next, we will revisit three policies created earlier:

* CloudTrail Policy
* EventBridge Policy
* S3 Policy

The goal is the same across all three services:

Grant only the permissions required and scope them as narrowly as possible.

---

### CloudTrail Policy Hardening

For CloudTrail, discovery operations such as:

* `cloudtrail:DescribeTrails`
* `cloudtrail:GetTrail`

may require broader permissions.

However, administrative actions such as:

* `cloudtrail:StartLogging`
* `cloudtrail:StopLogging`
* `cloudtrail:PutEventSelectors`

should be scoped directly to the specific Trail ARN whenever possible.

This reduces the risk of accidental or unauthorized modifications to other CloudTrail configurations.

![Security Project](screenshots/hardeningcloudtrailpolicy.png)

---

### EventBridge Policy Hardening

For EventBridge, we separate discovery actions from administrative actions.

Discovery operations include:

* `events:ListRules`
* `events:ListTargetsByRule`
* `events:DescribeEventBus`
* `events:ListEventBuses`

These often require broader permissions.

Administrative operations such as:

* `events:PutRule`
* `events:PutTargets`
* `events:EnableRule`
* `events:DescribeRule`

should be restricted to specific EventBridge resources whenever possible.

This ensures administrators can only modify the resources they are responsible for.

![Security Project](screenshots/hardeningeventbridgepolicy.png)

---

### S3 Policy Hardening

Amazon S3 follows a similar pattern.

For example, if an administrator needs visibility into available buckets, we can allow:

* `s3:ListAllMyBuckets`

using:

```json
"Resource": "*"
```

We can further restrict access using conditions such as:

```json
"aws:RequestedRegion": "us-east-2"
```

to ensure operations are limited to approved regions.

Administrative actions such as:

* `s3:PutEncryptionConfiguration`
* `s3:PutBucketPolicy`
* `s3:PutBucketVersioning`

should always be scoped to the specific bucket ARN whenever possible.

This helps prevent unauthorized modifications to other buckets within the account.

![Security Project](screenshots/hardenings3policy.png)

---

## Resource Creation Permissions

In some cases, users need permissions to create resources.

Examples include:

* Creating CloudTrail Trails
* Creating EventBridge Rules
* Creating Event Buses
* Creating S3 Buckets

For this project, the infrastructure has already been created, so these permissions are no longer required.

However, when resource creation is necessary, permissions should be constrained as much as possible.

For example, bucket creation can be restricted to a specific AWS Region such as:

`us-east-2`

The objective is always to grant only the permissions required for the task being performed.

---

## A More Secure Environment

At this stage, we have:

* Hardened our Permission Boundaries
* Hardened our Identity-Based Policies
* Applied stricter resource scoping
* Reduced opportunities for privilege escalation
* Improved adherence to the principle of least privilege

As a result, our environment is now significantly more secure than the initial implementation.

---

## Uploading the Lambda Function and Configuring SNS

Now it's time to return to our Lambda function.

The next steps are:

1. Create an SNS topic for notifications and update your code.
2. Deploy the Lambda function to AWS.
3. Configure the execution role with the permissions required to interact with SNS.
4. Subscribe an email endpoint to receive security alerts.
5. Integrate SNS into the remediation workflow so that administrators are notified whenever a security event is detected and remediated.

This will complete the final stage of our monitoring, detection, remediation, and notification pipeline.


## Creating the SNS Topic

Before deploying the Lambda function, we need to create our SNS topic because the Lambda function will use it to send security notifications.

Let's navigate to the Amazon SNS console.

![Security Project](screenshots/snserrorpolicy.png)

As shown above, SNS returns an access error because our administrator user does not yet have the required permissions.

Let's fix that.

To follow the principle of least privilege, we will create a dedicated SNS policy with only the permissions required for this stage of the project.

For discovery operations, we allow broader permissions because listing resources is generally considered a low-risk action.

Therefore, we allow:

* SNS listing operations using `Resource: "*"`

We will also grant:

* `sns:CreateTopic`

At this point, we intentionally leave out topic management permissions because the topic does not exist yet.

After creating the topic, we will update the policy and scope those permissions to the specific SNS topic ARN.

![Security Project](screenshots/snspolicyv1.png)

**Important:** Attach the policy to the KMS administrator user.

---

## Creating the SNS Topic

Now we can return to the SNS console and create the topic.

For this project, we will use:

* Type: **Standard**
* Name: **security-topic**

Then create the topic.

![Security Project](screenshots/creatingtopicsns.png)
![Security Project](screenshots/topiccreated.png)

---

## Restricting SNS Permissions

Once the topic has been created, copy its ARN.

Now return to the SNS policy and add a new statement.

This statement allows management actions only on the specific topic we created.

Examples include:

* Publishing messages
* Creating subscriptions
* Viewing topic attributes
* Managing subscriptions
* Other topic-specific administrative actions

This approach follows the principle of least privilege by restricting access to a single SNS topic instead of granting permissions across all topics in the account.

![Security Project](screenshots/snspolicyv2.png)
---

## Updating the Lambda Function

Now we can return to our Lambda code in PyCharm.

Update the function and replace the placeholder value in the `sns_topic_arn` variable with the ARN of the SNS topic we just created.

![Security Project](screenshots/arnsnslambda.png)

This allows the Lambda function to publish notifications to the correct SNS topic whenever a monitored security event occurs.

---

## Deploying the Lambda Function

Before uploading the code, authenticate with AWS using either:

* AWS IAM Identity Center (`aws login`)
* AWS CLI credentials (`aws configure`)

In my environment, I initially skipped this step because my current Permission Boundary and Identity-Based Policies did not allow the creation of access keys through:

* `iam:CreateAccessKey`

After correcting the permissions, authentication can be completed normally.

Once authenticated, update the Lambda function code.

If the required permissions are configured correctly, AWS returns a JSON response containing the updated Lambda function details.

```bash
aws lambda update-function-code \
  --function-name kms-remediation-function \
  --zip-file fileb://lambda_function.zip
```
![Security Project](screenshots/lambdauploaded.png)
![Security Project](screenshots/lambdauploaded2.png)

---

## Updating the Lambda Execution Role

Now we need to update the Lambda execution role.

The function requires permissions to publish messages to Amazon SNS.

While reviewing the environment, I noticed that the **IAM-admin-policy** had not yet been attached to the KMS administrator user.

Additionally, I updated the policy to include:

* `iam:ListPolicies`
* `iam:ListGroups`

These permissions are required for some IAM management and discovery operations.

![Security Project](screenshots/ attaching-iam-admin.png)
![Security Project](screenshots/ attaching-iam-admin2.png)
---

## Granting SNS Permissions to Lambda

Now we return to the KMS administrator account.

Attach the Lambda SNS policy to the Lambda execution role.

This grants the Lambda function permission to publish notifications to the SNS topic.

Without these permissions, remediation actions would execute successfully, but notifications would fail.

![Security Project](screenshots/ lambdatosns.png)

---

## Creating an SNS Subscription

Next, we need to create a subscription so administrators can receive notifications.

Navigate to the SNS console and create a new subscription.

![Security Project](screenshots/ creatingsubscriptionsns.png)

For this project, we will use an email endpoint.

Whenever a monitored security event occurs, SNS will send an email notification to the configured address.

---

## Confirming the Subscription

AWS will send a confirmation email to the address provided.

You must confirm the subscription before SNS can deliver notifications.

If the subscription is not confirmed, notifications will not be delivered.

![Security Project](screenshots/ emailsubscription.png)
![Security Project](screenshots/ aws-subscription-confirmed.png)
---

## First Pipeline Completed

At this point, we have successfully completed our first end-to-end security pipeline:

**CloudTrail → EventBridge → Lambda → SNS**

The solution can now:

* Detect security-related API calls
* Trigger automated remediation logic
* Send notifications to administrators
* Provide visibility into potentially malicious activity

Now it's time to test the entire workflow and identify any remaining issues that need to be corrected before moving to the final remediation phase.

/////////////////////////////////////////
## Testing the Remediation Pipeline

Now it's time to test the remediation pipeline.

To do this, we will navigate to the AWS KMS console and disable our Customer Managed Key (CMK).

If everything has been configured correctly, the following should happen automatically:

1. CloudTrail records the API call.
2. EventBridge captures the event.
3. Lambda is triggered.
4. The CMK is automatically re-enabled.
5. An SNS notification is sent to the administrator.

![Security Project](screenshots/disablingcmk.png)
---

## Troubleshooting the Pipeline

If you do not receive an email notification and the key is not automatically re-enabled, the first place to investigate is CloudWatch Logs.

Navigate to the Lambda function logs and review the execution output.

![Security Project](screenshots/ cwlogstroubleshooting.png)

In my case, the logs revealed that the Lambda execution role did not have permission to:

* Publish messages to SNS
* Execute `kms:EnableKey`
* Execute other KMS remediation actions required by the function

After reviewing the configuration, I discovered that I had attached the wrong policy to the Lambda execution role.

Instead of attaching the SNS policy, I had accidentally attached the Lambda administration policy.

![Security Project](screenshots/ attachingrightpermissionlambdasns.png)

---

## Granting KMS Permissions to Lambda

To allow the Lambda function to remediate KMS-related events, I created a dedicated policy granting permissions to perform actions against the CMK.

The policy was scoped directly to the CMK ARN to follow the principle of least privilege.

This allows the function to re-enable the key whenever a monitored event triggers remediation.

![Security Project](screenshots/lambdaandkmspolicy.png)

After creating the policy, attach it to the Lambda execution role.

![Security Project](screenshots/attachingpolicytoexecutionrole.png)

At this point, both required policies are attached to the execution role.

(screenshots/policiesattachedtolambda.png)

---

## Retesting the Pipeline

Now let's test the solution again.

To generate a new event, I manually re-enabled the CMK and then disabled it once more.

![Security Project](screenshots/retryingpipeline.png)

After refreshing the KMS console, we can observe that the key was automatically re-enabled by the remediation workflow.

Even though the CMK was disabled manually, the pipeline detected the event and restored the key state.
![Security Project](screenshots/keyenabledbypipeline.png)
This confirms that the automated remediation process is working correctly.

---

## SNS Notification Verification

If everything is functioning properly, you should also receive an SNS notification email containing information about the detected event.

The notification includes details such as:

* Event source
* User identity
* Timestamp
* Action performed
* Remediation status

![Security Project](screenshots/emailfromsns.png)

At this stage, our first monitoring, detection, remediation, and notification pipeline has been successfully completed.

---

# Final Step: Monitoring Secret Access with CloudWatch Alarms

While the previous pipeline focused on active remediation, this final section focuses on visibility and monitoring.

Our goal is to detect whenever a secret is accessed through the `GetSecretValue` API call.

---

## Sending CloudTrail Logs to CloudWatch Logs

Navigate to:

**CloudTrail → Trails → Management Trail**

Enable CloudWatch Logs integration.

During this process:

* Create a new CloudWatch Log Group
* Create a new IAM Role

![Security Project](screenshots/cloudtrailtocloudwatchlogs.png)

If you encounter permissions errors while creating log groups, the following policy may help:

![Security Project](screenshots/policyforcreatingcwloggroup.png)

Attach the policy to the KMS administrator user.

You may also need to add:

`cloudtrail:UpdateTrail`

to your CloudTrail administration policy.

![Security Project](screenshots/updatetrailapicall.png)

Additionally, update your PassRole policy to allow CloudTrail to assume the required role.

![Security Project](screenshots/passrolepolicycloudtrail.png)

After these changes, the CloudTrail-to-CloudWatch Logs integration should be created successfully.

---

## Updating the CloudWatch Policy

Before continuing, we will improve our CloudWatch permissions using the same least-privilege approach applied throughout the project.

![Security Project](screenshots/updatingcwadminpolicy.png)

As shown, discovery permissions such as:

* `logs:DescribeLogGroups`
* `logs:DescribeLogStreams`

are allowed broadly.

However, permissions involving:

* Log events
* Metric filters
* Metrics

are scoped specifically to the CloudTrail Log Group.

We also include permissions required to create CloudWatch alarms.

This approach provides the functionality we need while minimizing unnecessary access.

---

## Creating the Metric Filter

Navigate to CloudWatch Logs and select the CloudTrail Log Group.

Create a new metric filter.

The filter pattern will be:

```text
GetSecretValue
```

![Security Project](screenshots/metricfilter.png)

Configure:

* Filter Name: `GetSecretValue-Filter`
* Metric Namespace: `SecurityMetrics`
* Metric Name: `SecretWasAccessed`

The namespace acts as a logical grouping for related metrics.

The metric name should clearly describe the activity being monitored.

![Security Project](screenshots/metricfilter2.png)

---

## Creating the CloudWatch Alarm

Select the metric created by the filter and create a new alarm.

Use the following settings:

* Statistic: **Sum**
* Period: **5 Minutes**
* Threshold Type: **Static Threshold**

Using **Sum** allows CloudWatch to count the number of secret access events during the evaluation period.

This alarm will trigger whenever a secret is accessed.

![Security Project](screenshots/metricalarm.png)

Leave the alarm state configuration as default.

Create a new SNS topic and provide an email address that will receive notifications.

![Security Project](screenshots/metricalarm2.png)

---

## Confirming the Subscription

AWS sends a confirmation email to the configured address.

Open the email and confirm the subscription.
![Security Project](screenshots/emailgetsecretsvaluetopicsubscription.png)
![Security Project](screenshots/emailgetsecretsvaluetopicsubscription2.png)

After confirming, return to the CloudWatch alarm configuration.

Set the alarm name:

`Secret Was Accessed`

Then proceed with the remaining steps.

![Security Project](screenshots/metricalarm3.png)

Finally, create the alarm.

(screenshots/metricalarmcreated.png)

---

## Testing the Alarm

Now let's test the monitoring solution.

Using the AWS CLI, retrieve the secret value.

This action generates a `GetSecretValue` API call, which CloudTrail records and sends to CloudWatch Logs.

![Security Project](screenshots/testingalarm.png)

Within a few minutes, the metric filter should detect the event and trigger the alarm.

Navigate to CloudWatch Alarms and verify the alarm state.

![Security Project](screenshots/alarmstate.png)

The alarm state has changed successfully.

This confirms that the monitoring solution is functioning correctly.

---

## Notification Verification

Finally, check your email inbox.

You should receive a notification indicating that the secret was accessed.

![Security Project](screenshots/alarm-getsecretvalue.png)

---

# Project Complete

At this point, the project is fully operational.

We successfully built a security monitoring system capable of:

* Encrypting secrets using AWS KMS
* Enforcing least-privilege access controls
* Monitoring API activity with CloudTrail
* Detecting security events with EventBridge
* Automatically remediating unauthorized actions with Lambda
* Sending security notifications through SNS
* Monitoring secret access using CloudWatch Logs and Alarms
* Applying Permission Boundaries and resource-level restrictions to reduce privilege escalation risks

This architecture demonstrates multiple AWS Security Specialty concepts, including IAM security, KMS administration, Secrets Manager protection, event-driven remediation, security monitoring, and operational visibility.


