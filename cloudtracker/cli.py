#!/usr/bin/env python3
"""
Copyright 2018 Duo Security

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
---------------------------------------------------------------------------
"""

import argparse
import datetime
import boto3
import botocore.exceptions
import logging


from . import run


def main(principals, organization_id, account_id, credentials, principal_types):
    now = datetime.datetime.now()
    parser = argparse.ArgumentParser()

    # Add mutually exclusive arguments for --list, --user, and --role
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--list",
        help="List 'users' or 'roles' that have been active",
        choices=["users", "roles"],
    )
    action_group.add_argument("--user", help="User to investigate", type=str)
    action_group.add_argument("--role", help="Role to investigate", type=str)

    parser.add_argument(
        "--config",
        help="Config file name (default: config.yaml)",
        required=False
    )
    parser.add_argument(
        "--iam",
        dest="iam_file",
        help="IAM output from running `aws iam get-account-authorization-details`",
        required=False,
        default="./data/get-account-authorization-details.json",
        type=str,
    )
    parser.add_argument("--account", help="Account name", required=True, type=str)
    parser.add_argument(
        "--start",
        help="Start of date range (ex. 2018-01-21). Defaults to one year ago.",
        default=(now - datetime.timedelta(days=90)).date().isoformat(),
        required=False,
        type=str,
    )
    parser.add_argument(
        "--end",
        help="End of date range (ex. 2018-01-21). Defaults to today.",
        default=now.date().isoformat(),
        required=False,
        type=str,
    )
    parser.add_argument(
        "--destrole", help="Role assumed into", required=False, default=None, type=str
    )
    parser.add_argument(
        "--permissionsetid", help="Permission Set into", required=False, default=None, type=str
    )
    parser.add_argument(
        "--identity", help="Permission Set identity into", required=False, default=None, type=str
    )
    parser.add_argument(
        "--policies", help="Permission Set policies into", required=False, default=None, type=list
    )
    parser.add_argument(
        "--destpolicy", help="Policy assumed into", required=False, default=None, type=str
    )
    parser.add_argument(
        "--destpolicyarn", help="Policy arn", required=False, default=None, type=str
    )
    parser.add_argument(
        "--destaccount",
        help="Account assumed into (if different)",
        required=False,
        default=None,
        type=str,
    )
    parser.add_argument(
        "--show-used",
        dest="show_used",
        help="Only show privileges that were used",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--ignore-benign",
        dest="show_benign",
        help="Don't show actions that aren't likely to be sensitive, "
        "such as ones that won't exfil data or modify resources",
        required=False,
        action="store_false",
    )
    parser.add_argument(
        "--ignore-unknown",
        dest="show_unknown",
        help="Don't show granted privileges that aren't recorded in CloudTrail, "
        "as we don't know if they are used",
        required=False,
        action="store_false",
    )
    parser.add_argument(
        "--no-color",
        dest="use_color",
        help="Don't use color codes in output",
        required=False,
        action="store_false",
    )
    parser.add_argument(
        "--skip-setup",
        dest="skip_setup",
        help="For Athena, don't create or test for the tables",
        required=False,
        action="store_true",
        default=False,
    )
    args = []
    for principal in principals:
        if all(element in principal_types for element in ['role', 'policy']):
            args.append(parser.parse_args(args=['--account', account_id, '--role', principal['name'], '--destpolicy', principal['attachmentName'], '--destpolicyarn', principal['arn']]))
        elif all(element in principal_types for element in ['user', 'policy']):
            args.append(parser.parse_args(args=['--account', account_id, '--user', principal['name'], '--destpolicy', principal['attachmentName'], '--destpolicyarn', principal['arn']]))
        elif all(element in principal_types for element in ['user', 'role']):
            args.append(parser.parse_args(args=['--account', account_id, '--user', principal['name'], '--destrole', principal['attachmentName']]))
        elif all(element in principal_types for element in ['user', 'permissionset']):
            args.append(parser.parse_args(args=['--account', account_id, '--user', principal['name'], '--permissionsetid', principal['id'], '--identity', principal['identity'], '--policies', principal['policies']]))
        else:
            return []

    try:
        if credentials['type'] == 'self':
            boto3_session = boto3.Session(
                aws_access_key_id=credentials['aws_access_key_id'],
                aws_secret_access_key=credentials['aws_secret_access_key'],
            )

        elif credentials['type'] == 'assumerole':
            boto3_session = boto3.Session(
                aws_access_key_id=credentials['aws_access_key_id'],
                aws_secret_access_key=credentials['aws_secret_access_key'],
                aws_session_token=credentials['session_token'],
                region_name=credentials.get('primary_region', "us-east-1")
            )

    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        logging.debug("Error occurred calling boto3.Session().", exc_info=True)
        logging.error(
            (
                "Unable to initialize the default AWS session, an error occurred: %s. Make sure your AWS credentials "
                "are configured correctly, your AWS config file is valid, and your credentials have the SecurityAudit "
                "policy attached."
            ),
            e,
        )
        return []

    # Create a CloudTrail client
    cloudtrail_client = boto3_session.client('cloudtrail')

    # Retrieve the list of CloudTrail trails
    response = cloudtrail_client.describe_trails()

    # Extract the S3 bucket names from the response
    bucket_names = [trail['S3BucketName'] for trail in response['trailList']]

    if len(bucket_names) == 0:
        return []
    s3 = boto3_session.client('s3')
    trail = None
    cloudtrail_log_paths = {"account": {"path": "AWSLogs/{account_id}/CloudTrail/".format(account_id=account_id)}}
    if organization_id:
        cloudtrail_log_paths["organization"] = {"path": "AWSLogs/{organization_id}/{account_id}/CloudTrail/".format(account_id=account_id, organization_id=organization_id)}
    for log_level, cloudtrail_log_path in cloudtrail_log_paths:
        for bucket in bucket_names:
            try:
                s3.get_object(
                    Bucket=bucket,
                    Key=cloudtrail_log_path["path"],
                )
                cloudtrail_log_paths[log_level]["present"] = True
                cloudtrail_log_paths[log_level]["bucket"] = bucket
                break
            except s3.exceptions.NoSuchKey as e:
                continue

    trail = cloudtrail_log_paths.get("account", {}).get("bucket")
    if cloudtrail_log_paths.get("organization", {}).get("present"):
        trail = cloudtrail_log_paths.get("organization", {}).get("bucket")
    if not trail:
        return []
    config = {
        "account":
            {
                "id": account_id,
                "athena": {
                    "s3_bucket": trail,
                    "path": ''
                }
            }
    }
    if cloudtrail_log_paths.get("organization", {}).get("present"):
        config["account"]["athena"]["org_id"] = organization_id
    data = []
    if args:
        data, output_bucket = run(args, config, boto3_session, args[0].start, args[0].end)
        logging.info(f"cleaning the athena query results")
        output_bucket = output_bucket.split("/")[-1]
        try:
            s3_client = boto3_session.client('s3')

            objects = s3_client.list_objects_v2(Bucket=output_bucket)

            if 'Contents' in objects:
                for obj in objects['Contents']:
                    s3_client.delete_object(Bucket=output_bucket, Key=obj['Key'])

        except Exception as e:
            logging.error(f"Error while cleaning the athena query results: {e}")

    return data
