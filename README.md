# -# 🔐 Build a Security Monitoring System on AWS

---

In this project, I will demonstrate how to set up a monitoring system using AWS CloudTrail, CloudWatch Logs & Metrics, and Amazon SNS to track access to secrets. I’m working on this project to gain a deeper understanding of AWS monitoring and alerting services and to receive real-time email notifications when a secret access event occurs.

---

## 🛠️ Tools and AWS Services Used

- AWS Secrets Manager
- AWS CloudTrail
- Amazon CloudWatch Logs & Metrics
- Amazon SNS (Simple Notification Service)
- Amazon S3 (for CloudTrail log storage)
- IAM (for role-based permissions)
- AWS CLI + CloudShell

---

## 🔑 Step 1: Create a Secret in AWS Secrets Manager

To begin the project, I created a sensitive secret in **AWS Secrets Manager** that I plan to monitor for access events throughout the rest of this setup.

I logged into the AWS Management Console using my IAM Admin user. From the console, I navigated to **Secrets Manager** and initiated the process by selecting **Store a new secret**.

I chose the **Other type of secret** option since I was not storing database credentials. Under the **Key/value** tab, I defined a secret key-value pair where:
- Key: `The Secret is`
- Value: `Abracadabraushushush` (a placeholder sensitive value)

For encryption, I retained the default AWS-managed key (`aws/secretsmanager`). I proceeded by clicking **Next**, and on the configuration screen, I named the secret:  
**`oneofthetopSecretInfo`**

I optionally included a description to indicate that this secret was created for a security monitoring project using CloudTrail, CloudWatch, and SNS.

Rotation settings were skipped since rotation is not required for this demonstration. I reviewed the configuration summary:
- Secret type: Other type of secret
- Encryption: aws/secretsmanager (default)
- Secret name: TopSecretInfo
- Rotation: Disabled

Once confirmed, I clicked **Store** to finalize. A green banner confirmed successful creation, after which I selected **View details** to confirm that the secret had been stored properly.


![/images/step-1-secret.png](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/c5b24f54b64fe4f83762e20a8f64d9931d2b81e9/assets/Screenshot%202025-07-15%20143057.png)


With this, the sensitive information I intend to monitor is now securely stored. 


---


## 🏞️ Step 2: Set Up CloudTrail to Monitor Secret Access

To monitor access to my secret (`oneofthetopSecretInfo`), I configured **AWS CloudTrail**, which tracks all management events in my AWS account. CloudTrail is essential for auditing and monitoring activity, especially when it comes to detecting unauthorized access to sensitive information.

I began by navigating to the CloudTrail service from the AWS Console and created a new trail named:

For log storage, I created a new S3 bucket following the naming convention:

I kept the default settings for log file validation and disabled SSE-KMS encryption to avoid unnecessary charges. SNS notifications and CloudWatch integration were left disabled at this point, as they are configured in later steps.

### 🔍 Event Logging Configuration

During setup, I chose to track **Management Events** only. These events include actions like reading, updating, and deleting AWS resources—specifically `GetSecretValue`, which is used when a secret is accessed.

I selected both **Read** and **Write** API activity:
- **Read** includes metadata actions like `DescribeSecret`
- **Write** includes sensitive operations like retrieving the secret value (`GetSecretValue`), which is critical for this monitoring project

To reduce unnecessary log volume, I excluded:
- **AWS KMS events**, as they are too frequent and not directly useful in this context
- **Amazon RDS Data API events**, which aren't relevant to secret access

After reviewing the configuration, I clicked **Create trail**, and received a success message confirming that my trail was set up correctly. This ensured that all future access to the secret would be logged in my S3 bucket for analysis and monitoring.



![Step 2 - CloudTrail Setup](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/205a10d4bac3adf245d601df449e01ddf0a1b976/assets/Screenshot%202025-07-15%20145838.png)

With CloudTrail now configured, I was ready to verify that it correctly logs events whenever the secret is accessed, either through the Console or via the AWS CLI.


---

## 📡 Step 3: Generate and Verify Secret Access Events Using CloudTrail

To validate that CloudTrail is correctly logging sensitive activity, I tested access to the secret `TopSecretInfo` in two different ways via the **Secrets Manager Console** and through the **AWS CLI in CloudShell**. The objective was to ensure that each access attempt triggers a `GetSecretValue` event and is recorded in CloudTrail.


### 🔍 Secret Access (Two Methods)

#### 🖥️ Access via AWS Console

I navigated back to **Secrets Manager**, selected my secret `oneofthetopSecretInfo`, and clicked on **Retrieve secret value** from the overview section. This action displayed the secret content and, under the hood, triggered a `GetSecretValue` API call. This event is what I expected CloudTrail to capture.

#### 💻 Access via AWS CLI (CloudShell)

To further validate programmatic access logging, I opened **AWS CloudShell** directly from the console and ran the following command:


aws secretsmanager get-secret-value --secret-id "oneofthetopSecretInfo" --region us-east-2


The secret was successfully retrieved in JSON format, which verified that CLI-based access works as intended.



![Step 3 - Retrieve via Console](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/4cda4080da3935662a68402cf986ab18fb183aeb/assets/Screenshot%202025-07-15%20151837.png)


### 📁 CloudTrail Event Verification

To confirm that both actions were logged, I navigated to **CloudTrail > Event History** in the AWS Console.

Using the **Lookup attributes** filter, I selected `Event source` and searched for:

```
secretsmanager.amazonaws.com
```

This returned a list of events related to AWS Secrets Manager. Among them, I found multiple instances of the `GetSecretValue` event  one generated from the console and another from the CLI command.

Each event entry included details such as:
- **Event Name**: `GetSecretValue`
- **Event Source**: `secretsmanager.amazonaws.com`
- **User Identity**: IAM Admin (Console) and CloudShell session
- **Resource Accessed**: `oneofthetopSecretInfo`

This confirmed that CloudTrail accurately logs every access event to the secret, regardless of the method used to retrieve it.

![CloudTrail Event Verification](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/1536c48e70f3f4e3cb314bee907d2a5f9e5b74f2/assets/Screenshot%202025-07-15%20152717.png)


### ✅ Key Finding

> CloudTrail successfully recorded the `GetSecretValue` activity when I accessed the secret via both the AWS Console and the AWS CLI. This confirms that the logging mechanism works reliably and forms the foundation for building real-time alerting with CloudWatch and SNS in the next step.



Now that CloudTrail is verified to detect and record secret access attempts, the next step is to trigger **alerts** whenever such access occurs.



---

## 📊 Step 4: Track Secrets Access Using CloudWatch Metrics

With CloudTrail successfully logging secret access events, the next step was to set up **Amazon CloudWatch** to analyze these logs and create **metric filters** that help detect and quantify access to my secret (`TopSecretInfo`). This would allow me to build automatic alerting based on secret access patterns.

---

### 🛠️ Enabling CloudWatch Logs for CloudTrail

I started by configuring my existing trail (`secrets-manager-trail`) to deliver log data into CloudWatch Logs. From the CloudTrail console, I selected my trail, clicked **Edit** in the **CloudWatch Logs** section, and enabled logging.

I created a new log group named:
```
myproject-secretsmanager-loggroup
```

Then I created a new IAM role named:
```
CloudTrailRoleForCloudWatchLogs_secrets-manager-trail
```

This IAM role allows CloudTrail to push logs to the designated CloudWatch Log Group while following the principle of least privilege.

After saving the changes, CloudTrail began forwarding log data to CloudWatch.


### 🔎 Verifying CloudWatch Logs Integration

To confirm that logs were being received, I navigated to the **CloudWatch Console**, selected **Log Groups**, and searched for:
```
nextwork-secretsmanager-loggroup
```

Inside the log group, I explored the latest log stream and verified multiple event entries from CloudTrail. These entries confirmed that the logs related to secret access, including `GetSecretValue` API calls, were successfully being streamed into CloudWatch.

This integration is crucial because CloudTrail only stores events for 90 days in Event History, whereas CloudWatch Logs allows for extended retention and advanced analysis.


### 📈 Creating Metric Filters to Detect Secret Access

Once I validated log delivery, I proceeded to create a **Metric Filter** to detect whenever the secret was accessed. Inside the `nextwork-secretsmanager-loggroup`, I chose **Actions > Create metric filter**.

I configured the following pattern:
```
Filter pattern: "GetSecretValue"
```
This pattern ensures the filter detects events involving the retrieval of secret values.

#### Metric Configuration
- **Filter Name:** `GetSecretsValue`
- **Metric Namespace:** `SecurityMetrics`
- **Metric Name:** `Secret is accessed`
- **Metric Value:** `1`
- **Default Value:** `0`

I reviewed the filter configuration and finalized it. CloudWatch confirmed successful creation with a green banner at the top.

This metric will now increment by 1 every time the `GetSecretValue` API is invoked, giving me a real-time counter for secret access frequency.


### ✅ Summary
With CloudTrail forwarding logs to CloudWatch and a custom metric filter now in place, I can continuously monitor access to sensitive secrets. This metric lays the foundation for alerting, which I’ll configure in the next step.

![Step 4 - Metric Filter Setup](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/ef76331e95988c06915c012c197e234dc6bca2c8/assets/Screenshot%202025-07-15%20214644.png)


---



## 🔔 Step 5: Set Up CloudWatch Alarm and SNS Notification

After confirming that CloudWatch Metrics were successfully recording secret access events, I proceeded to build a real-time alerting system using **Amazon CloudWatch Alarms** and **Amazon SNS (Simple Notification Service)**. This ensured that any unauthorized or unexpected access to my secret would immediately trigger an email alert, enabling swift response.


### 📊 Create a CloudWatch Alarm for the Metric

I began by navigating to the CloudWatch console and accessing the **Metric filters** tab under **Logs**. From there, I located the metric filter named `GetSecretsValue`, which I had previously created to track calls to `GetSecretValue`.

After selecting the filter, I clicked **Create alarm**, which launched the alarm configuration workflow.

In the **Metric configuration**, I used the following settings:
- **Namespace**: `SecurityMetrics`
- **Metric name**: `Secret is accessed`
- **Statistic**: `Average`
- **Period**: `5 minutes`

These settings ensure that CloudWatch analyzes the average number of secret access attempts every 5 minutes. This short time window provides timely detection.

Under the **Conditions** section:
- I selected **Static threshold**
- I set **Whenever Secret is accessed is >= 1**

This means that even a single secret access attempt within a 5-minute window would trigger the alarm — an appropriate configuration for high-security monitoring.


### 📬 Create an SNS Topic for Email Notifications

Next, I moved to the **Actions** section of the alarm creation wizard. Under **Notification**, I kept the setting to trigger when the alarm is in the `In alarm` state.

I selected **Create new topic**, and used the following values:
- **Topic name**: `SecurityAlarms`
- **Email endpoint**: my personal email address (e.g., `example@gmail.com`)

This topic would act as the broadcast channel for my alarm system, allowing multiple subscribers in the future if needed.

After creating the topic, AWS sent a **subscription confirmation email** to my inbox. I accessed the email and clicked **Confirm subscription**, which finalized the process and enabled email alerts.

![Step 5 - SNS Subscription Confirmed](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/c10b6a79840b028ef5cb96a55775292edecf9045/assets/Screenshot%202025-07-15%20221923.png)


This setup helps ensure high visibility and quick reaction in case of unauthorized or unintended access to sensitive data.

---


## 🕵️‍♀️ Step 6: Enable Direct SNS Notifications from CloudTrail (Secret Architect Mission)

To explore architectural alternatives, I extended the monitoring system by enabling **direct SNS notifications from CloudTrail**. This step was part of a project extension to evaluate how CloudTrail's built-in notification feature compares to the more fine-tuned CloudWatch Alarms.



### ⚙️ CloudTrail SNS Notification Configuration

I revisited my existing trail named `secrets-manager-ma` in the **CloudTrail** console.

In the **General details** section, I selected **Edit** and scrolled to the **SNS notification delivery** section. There, I checked the **Enabled** box and chose **Use existing SNS topic**.

From the dropdown, I selected the `SecurityAlarms` topic I had created earlier during the CloudWatch Alarm setup.

After verifying the selection, I clicked **Save changes**. This action enabled CloudTrail to send a notification to the SNS topic **each time a log file is delivered** to my S3 bucket, including when secrets are accessed.


### 🔍 Secret Access to Trigger Notification

To test this integration again, I accessed the secret `oneofthetopSecretInfo` by navigating to **Secrets Manager** and clicking **Retrieve secret value**.

This triggered a new `GetSecretValue` event, which was then recorded by CloudTrail. Because SNS delivery was enabled, CloudTrail sent a **notification** as soon as the log file containing the event was uploaded.


### 📬 Observing CloudTrail Notification Behavior

A few minutes after accessing the secret, my email inbox began receiving **multiple notifications** from AWS SNS tied to CloudTrail.

Each email corresponded to a new CloudTrail log file delivery, not just secret access events, but **all** management activity in the account.

![Step 6 - CloudTrail SNS Notifications](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/548ab0ddd82666bda01ef8aa83230264b08ce550/assets/Screenshot%202025-07-15%20223231.png) 


### 🛑 Reverting CloudTrail SNS to Avoid Alert Overload

Once I confirmed the behavior, I returned to the **CloudTrail > Edit trail** section and unchecked the **SNS notification delivery** box to disable the high-volume alerts.

This restored the streamlined, filtered alerting experience enabled by the CloudWatch alarm.

---



## 🧪 Step 7: Test and Troubleshoot Secret Access Notification System

In this step, I tested whether the full monitoring and alerting system was correctly integrated and functioning as expected. The objective was to confirm that accessing the secret triggers a chain of events: CloudTrail logs the access, CloudWatch picks up the log via metric filter, an alarm is triggered, and SNS sends an email alert.

---

### ✅ Verifying CloudTrail Logged the Secret Access Event

To verify that **CloudTrail** recorded the secret access:
- I navigated to **CloudTrail > Event history**
- Filtered logs by setting `Lookup attribute = Event source`
- Entered `secretsmanager.amazonaws.com`

I located the `GetSecretValue` events corresponding to when I accessed the secret. Each event contained:
- IAM identity
- AWS region
- JSON payload confirming access

This confirmed that CloudTrail correctly captured the access event.

![Step 7 - CloudTrail Event History](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/31c9d7a79683056fd00455800ba4d3ca75cb718a/assets/Screenshot%202025-07-15%20225257.png)


### ⚠️ Verifying CloudTrail Log Delivery to CloudWatch

To confirm that CloudTrail was delivering logs to CloudWatch:
- I navigated to **CloudTrail > Trails**
- Selected my trail (`secrets-manager-trail`)
- Checked the **Last log file delivered** timestamp

When no timestamp was shown, I:
- Clicked **Edit** next to **CloudWatch Logs**
- Verified `Enabled` was checked
- Confirmed correct log group name: `myproject-secretsmanager-loggroup`
- Verified IAM role permissions for CloudWatch Logs

After saving changes, the log delivery began successfully.


### ✅ Testing CloudWatch Metric Filter

To ensure the metric filter detects access events:
- I opened **CloudWatch > Log groups**
- Clicked my log group `myproject-secretsmanager-loggroup`
- Selected **Metric filters > GetSecretValue > Edit**
- Pasted sample CloudTrail JSON and clicked **Test pattern**

The filter correctly matched `GetSecretValue`, confirming it was working.

![Step 7 - Metric Filter Test](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/31c9d7a79683056fd00455800ba4d3ca75cb718a/assets/Screenshot%202025-07-15%20230743.png)



### ✅ Testing and Adjusting CloudWatch Alarm

To simulate the alarm trigger:
```bash
aws cloudwatch set-alarm-state --alarm-name "Secret is accessed" --state-value ALARM --state-reason "Manually triggered for testing"
```

This test confirmed that:
- The alarm reached the `ALARM` state
- An email was received (if SNS was confirmed)

If needed, I adjusted the alarm:
- Statistic: `Sum` (instead of `Average`)
- Period: `1 minute` for faster response
- Threshold: `Static`, condition `>= 1`

Saved by clicking **Skip to preview > Update alarm**.

![Step 7 - Alarm Configuration](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/31c9d7a79683056fd00455800ba4d3ca75cb718a/assets/Screenshot%202025-07-15%20232237.png)

---

### ✅ Verifying SNS Email Delivery

To confirm SNS was working:
- I went to **SNS > Topics > SecurityAlarms**
- Clicked **Publish message**
- Sent test with subject `Testing` and message `Wassup`

If I didn’t get the email:
- Checked **SNS > Subscriptions**
- Verified status was `Confirmed`
- If `Pending`, confirmed via email or resent the confirmation

Once confirmed, I got test emails and alarm notifications.

![Step 7 - SNS Email Test](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/31c9d7a79683056fd00455800ba4d3ca75cb718a/assets/Screenshot%202025-07-15%20232637.png)


### 🧠 Final Troubleshooting Checklist

I ensured the following were all working correctly:
- ✅ CloudTrail logs `GetSecretValue`
- ✅ CloudTrail sends logs to CloudWatch
- ✅ CloudWatch metric filter matches correctly
- ✅ CloudWatch alarm triggers
- ✅ SNS email subscription is confirmed, and emails are received

With all components now validated, the system successfully sends email alerts whenever the secret is accessed.

---


## ✅ Step 8: Final Test — Trigger Alarm and Confirm Email Notification

With all fixes and configurations in place, I initiated one final test to ensure the entire monitoring pipeline functions correctly, from secret access to email notification.



### 🔄 Accessing the Secret Again

I navigated to **Secrets Manager**, located my `oneofthetopSecretInfo` secret, and clicked on **Retrieve secret value**.

This action triggered a `GetSecretValue` event, which CloudTrail recorded. CloudTrail then passed the event to CloudWatch, which evaluated it using the configured metric filter and triggered the CloudWatch alarm.



### 📊 Verifying CloudWatch Alarm State

Next, I opened **CloudWatch > Alarms**, selected the **Secret is accessed** alarm, and refreshed the view.

After a short delay (approximately 2–5 minutes), the alarm status transitioned to:

> **In alarm**

This confirmed that the event pipeline worked as expected, the log was processed, matched by the metric filter, and raised the alarm.


### ✉️ Confirming SNS Email Notification

Shortly after the alarm triggered, I received an email from AWS Notifications with the subject line:

> `ALARM: "SecretIsAccessedAlarm"`

This validated that the final link in the monitoring system — SNS email delivery — was also functional.



#### 📸 Screenshot 1: CloudWatch Alarm in 'In Alarm' State  
![CloudWatch Alarm In Alarm](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/607ee87155f92ba6f89c53be68f7686195a7642e/assets/Screenshot%202025-07-15%20233818.png)

#### 📸 Screenshot 2: Email Notification from AWS SNS  
![Email Notification](https://github.com/addula-mounika12/-Build-a-Security-Monitoring-System-on-AWS/blob/9edc9ad64b740d842225fa1f7ab3ad82f1732442/assets/Screenshot%202025-07-15%20233850.png)


### 🏁 Final Outcome

This confirmed a successful setup and test of my end-to-end secret access monitoring system using:

- **CloudTrail** to record API calls
- **CloudWatch Logs + Metric Filters** to detect access patterns
- **CloudWatch Alarms** to trigger alerts
- **SNS** to send email notifications

With this complete, I now have a functioning system that notifies me in real-time when a sensitive secret is accessed.


---

## 🧹 Step 9: Delete AWS Resources to Avoid Charges

At the end of the project, I deleted all the AWS resources I created to avoid any unexpected charges and maintain a clean environment.



### 🗑️ Delete CloudTrail Trail

I started by going to the **CloudTrail** console.

- Selected **Trails** from the left navigation.
- Checked the box next to `secrets-manager-trail`.
- Clicked **Delete**.
- Typed `Delete` in the confirmation dialog box.
- Selected **Delete** to confirm.



### 🪣 Delete S3 Bucket for CloudTrail Logs

Next, I went to the **S3** console.

- Selected **Buckets** in the left navigation.
- Clicked on my CloudTrail S3 bucket (e.g., `nextwork-secrets-manager-trail-yourinitials`).
- Chose **Empty** to delete all contents.
- In the confirmation dialog, typed `permanently delete` and confirmed.

After emptying the bucket:

- I selected the bucket again.
- Clicked **Delete**.
- Entered the full bucket name in the confirmation box.
- Selected **Delete bucket**.



### ⏰ Delete CloudWatch Alarm

I navigated to **CloudWatch > Alarms**.

- Checked the box next to `SecretIsAccessedAlarm`.
- Chose **Actions > Delete**.
- Clicked **Delete** to confirm.


### 📊 Delete CloudWatch Log Group

In the **CloudWatch > Log groups** section:

- Searched for `nextwork-secretsmanager-loggroup`.
- Checked the corresponding box.
- Selected **Actions > Delete log group(s)**.
- Clicked **Delete** in the confirmation dialog.



### 🔐 Delete Secrets Manager Secret

Then, I visited the **Secrets Manager** console.

- Selected **Secrets** in the left panel.
- Checked the box next to the `TopSecretInfo` secret.
- Chose **Actions > Delete secret**.
- On the next screen, confirmed the default **7-day waiting period**.
- Clicked **Schedule deletion**.



### 📣 Delete SNS Topic and Subscription

Finally, I cleaned up my SNS resources.

#### Delete SNS Topic

- Went to **SNS > Topics**.
- Checked the box next to `SecurityAlarms`.
- Clicked **Delete**.
- Typed `delete me` in the confirmation dialog.
- Selected **Delete**.

#### Delete SNS Subscription

- Went to **SNS > Subscriptions**.
- Checked the subscription created for email alerts.
- Clicked **Delete**.
- Confirmed the deletion.



With these deletions, all components of the monitoring system were safely removed, completing the project.
