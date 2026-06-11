import boto3
import logging

from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def extract_event_info(event):
    return {"api_call" : event["detail"]["eventName"] ,
            "affected_key":event["detail"]["responseElements"]["keyId"],
            "aws_region":event["detail"]["awsRegion"],
            "username": event["detail"]["userIdentity"]["sessionContext"]["sessionIssuer"]["userName"],
            "arn_user":event["detail"]["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"],
            "time":event["detail"]["eventTime"],
            "source":event["detail"]["eventSource"]}

def remediation_action(kms_client, event):
    if event["api_call"] == "PutKeyPolicy":
        message = (
            f"KMS Key Policy Modification Detected:\n"
            f"Severity: HIGH\n"
            f"API Call: PutKeyPolicy\n"
            f"Remediation Status: NOT_PERFORMED\n"
            f"Reason: Manual review required before modifying KMS key policies.\n"
            f"A modification to the KMS key policy was detected. This action may alter "
            f"administrative permissions or key usage permissions. The change has been "
            f"flagged for security review.\n"
            f"Details:\n"
            f"Region: '{event['aws_region']}'\n"
            f"User: '{event['username']}' User ARN: '{event['arn_user']}'\n"
            f"Key ID: '{event['affected_key']}'\n"
            f"Timestamp: '{event['time']}'\n"
        )

        return message

    if event["api_call"] == "RevokeGrant":
        message = (
            f"KMS Grant Revocation Detected:\n"
            f"Severity: HIGH\n"
            f"API Call: RevokeGrant\n"
            f"Remediation Status: NOT_PERFORMED\n"
            f"Reason: Grant recreation requires validation of the original grant configuration.\n"
            f"A grant associated with a KMS key was revoked. Access permissions used by "
            f"AWS services or applications may have been affected. The event has been "
            f"flagged for investigation.\n"
            f"Details:\n"
            f"Region: '{event['aws_region']}'\n"
            f"User: '{event['username']}' User ARN: '{event['arn_user']}'\n"
            f"Key ID: '{event['affected_key']}'\n"
            f"Timestamp: '{event['time']}'\n"
        )

        return message

    if event["api_call"] == "DeleteAlias":
        message = (
            f"KMS Alias Deletion Detected:\n"
            f"Severity: MEDIUM\n"
            f"API Call: DeleteAlias\n"
            f"Remediation Status: NOT_PERFORMED\n"
            f"Reason: Alias deletion may be part of a legitimate key migration or maintenance activity.\n"
            f"A KMS alias associated with a protected key was deleted. Applications or "
            f"services referencing the alias may be impacted. The event has been "
            f"flagged for review.\n"
            f"Details:\n"
            f"Region: '{event['aws_region']}'\n"
            f"User: '{event['username']}' User ARN: '{event['arn_user']}'\n"
            f"Key ID: '{event['affected_key']}'\n"
            f"Timestamp: '{event['time']}'\n"
        )

        return message

    if event["api_call"] == "DisableKeyRotation":
        try:
            kms_client.enable_key_rotation(KeyId=event["affected_key"])
        except ClientError as c:
            logger.exception("Remediation failed"+str(c))
            error_code = c.response["Error"]["Code"]
            error_message = c.response["Error"]["Message"]

            message = (f"KMS Key Rotation Disabled:\n"
                           f"Remediation Status: FAILED\n"
                           f"Remediation Action: enable_key_rotation()\n"
                           f"Error Code: "+error_code+"\n"
                           f"Error Message: "+error_message+"\n"
                           f"Details:\n"
                           f"Region: '{event['aws_region']}'\n"
                           f"User:  '{event['username']}' User's ARN: '{event['arn_user']}'\n"
                           f"Key ID: '{event['affected_key']}'\n"
                           f"Timestamp: '{event['time']}'\n")
            return message


        message = (f"KMS Key Rotation Disabled:\n"
                f"Automatic key rotation was disabled for a protected KMS key. Key rotation was immediately re-enabled to maintain compliance and security best practices.\n"
                f"Details:\n"
                f"Region: '{event['aws_region']}'\n"
                f"User:  '{event['username']}' User's ARN: '{event['arn_user']}'\n"
                f"Key ID: '{event['affected_key']}'\n"
                f"Timestamp: '{event['time']}'\n"
                f"Remediation Status: SUCCESS \n")
        return message

    if event["api_call"] == "ScheduleKeyDeletion":
        try:
            kms_client.cancel_key_deletion(KeyId=event["affected_key"])

        except ClientError as c:
            logger.exception("Remediation failed " + str(c))

            error_code = c.response["Error"]["Code"]
            error_message = c.response["Error"]["Message"]

            message = (
                f"KMS Key Deletion Attempt Detected:\n"
                f"Severity: HIGH\n"
                f"API Call: ScheduleKeyDeletion\n"
                f"Remediation Status: FAILED\n"
                f"Remediation Action: cancel_key_deletion()\n"
                f"Error Code: {error_code}\n"
                f"Error Message: {error_message}\n"
                f"Details:\n"
                f"Region: '{event['aws_region']}'\n"
                f"User: '{event['username']}' User ARN: '{event['arn_user']}'\n"
                f"Key ID: '{event['affected_key']}'\n"
                f"Timestamp: '{event['time']}'\n"
            )

            return message

        message = (
            f"KMS Key Deletion Attempt Detected:\n"
            f"Severity: HIGH\n"
            f"API Call: ScheduleKeyDeletion\n"
            f"A request to schedule deletion of a KMS key was detected. "
            f"The deletion process was automatically canceled to protect encrypted data and maintain key availability.\n"
            f"Remediation Status: SUCCESS\n"
            f"Details:\n"
            f"Region: '{event['aws_region']}'\n"
            f"User: '{event['username']}' User ARN: '{event['arn_user']}'\n"
            f"Key ID: '{event['affected_key']}'\n"
            f"Timestamp: '{event['time']}'\n"
        )

        return message

    if event["api_call"] == "DisableKey":
        try:
            kms_client.enable_key(KeyId=event["affected_key"])

        except ClientError as c:
            logger.exception("Remediation failed " + str(c))

            error_code = c.response["Error"]["Code"]
            error_message = c.response["Error"]["Message"]

            message = (
                f"KMS Key Disabled:\n"
                f"Severity: HIGH\n"
                f"API Call: DisableKey\n"
                f"Remediation Status: FAILED\n"
                f"Remediation Action: enable_key()\n"
                f"Error Code: {error_code}\n"
                f"Error Message: {error_message}\n"
                f"Details:\n"
                f"Region: '{event['aws_region']}'\n"
                f"User: '{event['username']}' User ARN: '{event['arn_user']}'\n"
                f"Key ID: '{event['affected_key']}'\n"
                f"Timestamp: '{event['time']}'\n"
            )

            return message

        message = (
            f"KMS Key Disabled:\n"
            f"Severity: HIGH\n"
            f"API Call: DisableKey\n"
            f"A KMS key was disabled. The affected key was automatically re-enabled "
            f"by the remediation Lambda to maintain service availability and prevent "
            f"unauthorized disruption of encrypted resources.\n"
            f"Remediation Status: SUCCESS\n"
            f"Details:\n"
            f"Region: '{event['aws_region']}'\n"
            f"User: '{event['username']}' User ARN: '{event['arn_user']}'\n"
            f"Key ID: '{event['affected_key']}'\n"
            f"Timestamp: '{event['time']}'\n"
        )

        return message


def sns_alert(sns_client, sns_topic_arn, message):
    try:
        sns_client.publish(TopicArn=sns_topic_arn,Message=message)
    except ClientError as e:
        logger.exception("An error was found" +str(e))



def lambda_handler(event, context):
    kms_client = boto3.client('kms')
    sns_client = boto3.client('sns')
    sns_topic_arn = "arn:aws:sns:us-east-2:181179258757:security-topic"
    extracted_event = extract_event_info(event)
    message = remediation_action(kms_client, extracted_event)
    logger.info(f"Processing API Call: {extracted_event['api_call']}")
    if message:
        try:
            sns_alert(sns_client, sns_topic_arn, message)
        except Exception as e:
            logger.exception(f"Failed to publish SNS notification: {e}")
    else:
        logger.error("No alert message generated. SNS notification not sent.")







