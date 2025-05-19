"""
Copyright 2018 Summit Route

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

import boto3
import time
import json
import re
import datetime
from dateutil.relativedelta import relativedelta
import logging

from cloudtracker import normalize_api_call

# Much thanks to Alex Smolen (https://twitter.com/alsmola)
# for his post "Partitioning CloudTrail Logs in Athena"
# https://medium.com/@alsmola/partitioning-cloudtrail-logs-in-athena-29add93ee070

# TODO Delete result objects from S3
# TODO Add ability to skip setup
# TODO Add teardown to remove all the athena tables, partitions, and views


NUM_MONTHS_FOR_PARTITIONS = 4


class Athena(object):
    athena = None
    s3 = None
    database = "cloudtracker"
    output_bucket = "aws-athena-query-results-ACCOUNT_ID-REGION"
    search_filter = ""
    table_name = ""
    workgroup = 'primary'
    cdx_logger = None

    def query_athena(
        self, query, context={"Database": database}, do_not_wait=False, skip_header=True, retry=False
    ):
        self.cdx_logger.debug("Making query {}".format(query))
        self.cdx_logger.debug(f"Query context: {context}, do_not_wait: {do_not_wait}, skip_header: {skip_header}, retry_attempt: {retry}")

        # if function call is not for retry we set retry as 1
        if not retry:
            self.retry = 1

        # Make query request dependent on whether the context is None or not
        if context is None:
            response = self.athena.start_query_execution(
                QueryString=query,
                ResultConfiguration={"OutputLocation": self.output_bucket}
            )
        else:
            response = self.athena.start_query_execution(
                QueryString=query,
                QueryExecutionContext=context,
                ResultConfiguration={"OutputLocation": self.output_bucket}
            )
        self.cdx_logger.debug(f"Athena start_query_execution response QueryExecutionId: {response['QueryExecutionId']}")

        if do_not_wait:
            self.cdx_logger.debug(f"Query {response['QueryExecutionId']} submitted, do_not_wait is True.")
            return response["QueryExecutionId"]

        result = self.wait_for_query_to_complete(response["QueryExecutionId"])
        if result:
            # Paginate results and combine them
            rows = []
            paginator = self.athena.get_paginator("get_query_results")
            self.cdx_logger.debug(f"Paginating results for QueryExecutionId: {response['QueryExecutionId']}")
            response_iterator = paginator.paginate(
                QueryExecutionId=response["QueryExecutionId"]
            )
            row_count = 0
            for response in response_iterator:
                for row in response["ResultSet"]["Rows"]:
                    row_count += 1
                    if row_count == 1:
                        if skip_header:
                            # Skip header
                            self.cdx_logger.debug("Skipping header row.")
                            continue
                    rows.append(self.extract_response_values(row))
            self.cdx_logger.debug(f"Query {response['QueryExecutionId']} completed, processed {len(rows)} rows.")
            return rows
        else:
            self.cdx_logger.info(f"Retrying query: {query}")
            return self.query_athena(query, context, do_not_wait, skip_header, True)

    def extract_response_values(self, row):
        result = []
        for column in row["Data"]:
            result.append(column.get("VarCharValue", ""))
        self.cdx_logger.debug(f"Extracted values: {result} from row: {row}")
        return result

    def wait_for_query_to_complete(self, queryExecutionId):
        """
        Returns when the query completes successfully, or raises an exception if it fails or is canceled.
        Waits until the query finishes running.
        """
        self.cdx_logger.debug(f"Waiting for query {queryExecutionId} to complete.")
        while True:
            response = self.athena.get_query_execution(
                QueryExecutionId=queryExecutionId
            )
            state = response["QueryExecution"]["Status"]["State"]
            self.cdx_logger.debug(f"Query {queryExecutionId} current state: {state}")
            if state == "SUCCEEDED":
                self.cdx_logger.info(f"Query {queryExecutionId} SUCCEEDED.")
                return True
            if state == "FAILED" or state == "CANCELLED":
                self.cdx_logger.warning(f"Query {queryExecutionId} {state}. Reason: {response['QueryExecution']['Status'].get('StateChangeReason', 'No reason provided')}")
                # retring if query faild or canceled
                if self.retry > 0:
                    self.retry -= 1
                    self.cdx_logger.info(f"Retrying query {queryExecutionId}. Retries left: {self.retry}")
                    return False
                raise Exception(
                    "Query entered state {state} with reason {reason}".format(
                        state=state,
                        reason=response["QueryExecution"]["Status"][
                            "StateChangeReason"
                        ],
                    )
                )
            self.cdx_logger.debug(
                "Sleeping 1 second while query {} completes".format(queryExecutionId)
            )
            time.sleep(1)

    def wait_for_query_batch_to_complete(self, queryExecutionIds):
        """
        Returns when the query completes successfully, or raises an exception if it fails or is canceled.
        Waits until the query finishes running.
        """
        self.cdx_logger.debug(f"Waiting for query batch to complete. Initial IDs: {list(queryExecutionIds)}")

        while len(queryExecutionIds) > 0:
            response = self.athena.batch_get_query_execution(
                QueryExecutionIds=list(queryExecutionIds)
            )
            for query_execution in response["QueryExecutions"]:
                q_id = query_execution["QueryExecutionId"]
                state = query_execution["Status"]["State"]
                self.cdx_logger.debug(f"Batch query {q_id} current state: {state}")
                if state == "SUCCEEDED":
                    queryExecutionIds.remove(query_execution["QueryExecutionId"])
                if state == "FAILED" or state == "CANCELLED":
                    self.cdx_logger.error(f"Batch query {q_id} {state}. Reason: {query_execution['Status'].get('StateChangeReason', 'No reason provided')}")
                    raise Exception(
                        "Query entered state {state} with reason {reason}".format(
                            state=state,
                            reason=response["QueryExecution"]["Status"][
                                "StateChangeReason"
                            ],
                        )
                    )

                if len(queryExecutionIds) == 0:
                    return
                self.cdx_logger.debug(
                    "Sleeping 1 second while {} queries complete".format(
                        len(queryExecutionIds)
                    )
                )
                time.sleep(1)

    def __init__(self, config, account, boto3_session, start, end, args, cdx_logger):
        self.cdx_logger = cdx_logger
        self.cdx_logger.info("Initializing Athena datasource.")
        self.cdx_logger.debug(f"Received config: {config}, account: {account['id']}, start: {start}, end: {end}")

        # Mute boto except errors
        botocore_logger = logging.getLogger("botocore")
        botocore_logger.setLevel(logging.WARNING)
        if self.cdx_logger and self.cdx_logger.handlers:
            for handler in self.cdx_logger.handlers:
                botocore_logger.addHandler(handler)
            botocore_logger.propagate = False
        else:
            self.cdx_logger.warning("cdx_logger has no handlers. Botocore logs will propagate to root.")

        self.cdx_logger.info(
            "Source of CloudTrail logs: s3://{bucket}/{path}".format(
                bucket=config["s3_bucket"], path=config["path"]
            )
        )

        # Check start date is not older than a year, as we only create partitions for that far back
        if (
            datetime.datetime.now() - datetime.datetime.strptime(start, "%Y-%m-%d")
        ).days > 365:
            self.cdx_logger.error("Start date is over a year old. CloudTracker does not create or use partitions over a year old.")
            raise Exception(
                "Start date is over a year old. CloudTracker does not create or use partitions over a year old."
            )

        #
        # Create date filtering
        #
        self.cdx_logger.debug(f"Creating date filters for start: {start}, end: {end}")
        month_restrictions = set()
        start = start.split("-")
        end = end.split("-")

        if start[0] == end[0]:
            for month in range(int(start[1]), int(end[1]) + 1):
                month_restrictions.add(
                    "(year = '{:0>2}' and month = '{:0>2}')".format(start[0], month)
                )
        else:
            # Add restrictions for months in start year
            for month in range(int(start[1]), 12 + 1):
                month_restrictions.add(
                    "(year = '{:0>2}' and month = '{:0>2}')".format(start[0], month)
                )
            # Add restrictions for months in middle years
            for year in range(int(start[0]), int(end[0])):
                for month in (1, 12 + 1):
                    month_restrictions.add(
                        "(year = '{:0>2}' and month = '{:0>2}')".format(year, month)
                    )
            # Add restrictions for months in final year
            for month in range(1, int(end[1]) + 1):
                month_restrictions.add(
                    "(year = '{:0>2}' and month = '{:0>2}')".format(end[0], month)
                )
        self.cdx_logger.debug(f"Calculated month_restrictions: {month_restrictions}")

        # Combine date filters and add error filter
        self.search_filter = (
            "((" + " or ".join(month_restrictions) + ") and errorcode IS NULL)"
        )
        self.cdx_logger.debug(f"Final search_filter: {self.search_filter}")

        self.table_name = "cloudtrail_logs_{}".format(account["id"])
        self.cdx_logger.info(f"Athena table name set to: {self.table_name}")

        #
        # Display the AWS identity (doubles as a check that boto creds are setup)
        #
        sts = boto3_session.client("sts")
        identity = sts.get_caller_identity()
        self.cdx_logger.info("Using AWS identity: {}".format(identity["Arn"]))
        current_account_id = identity["Account"]
        region = boto3_session.region_name
        self.cdx_logger.debug(f"Current AWS Account ID: {current_account_id}, Region: {region}")

        if "output_s3_bucket" in config:
            self.output_bucket = config["output_s3_bucket"]
        else:
            self.output_bucket = "s3://aws-athena-query-results-{}-{}".format(
                current_account_id, region
            )
        self.cdx_logger.info("Using output bucket: {}".format(self.output_bucket))

        if "workgroup" in config:
            self.workgroup = config["workgroup"]
        self.cdx_logger.info("Using workgroup: {}".format(self.workgroup))

        if not config.get('org_id'):
            cloudtrail_log_path = "s3://{bucket}/{path}/AWSLogs/{account_id}/CloudTrail".format(
                bucket=config["s3_bucket"], path=config["path"], account_id=account["id"]
            )
        else:
            cloudtrail_log_path = "s3://{bucket}/{path}/AWSLogs/{org_id}/{account_id}/CloudTrail".format(
                bucket=config["s3_bucket"], path=config["path"], org_id=config["org_id"], account_id=account["id"]
            )

        self.cdx_logger.info("Account cloudtrail log path: {}".format(cloudtrail_log_path))

        # Open connections to needed AWS services
        self.athena = boto3_session.client("athena")
        self.s3 = boto3_session.client("s3")
        self.cdx_logger.debug("Boto3 clients for Athena and S3 created.")

        if args.skip_setup:
            self.cdx_logger.info("Skipping initial table creation and partition setup as per args.skip_setup.")
            return

        # Check we can access the S3 bucket
        self.cdx_logger.debug(f"Attempting to list S3 objects for bucket '{config['s3_bucket']}' with prefix '{config['path']}' for validation.")
        resp = self.s3.list_objects_v2(
            Bucket=config["s3_bucket"], Prefix=config["path"], MaxKeys=1
        )
        self.cdx_logger.debug(f"S3 list_objects_v2 response keys: {list(resp.keys())}")
        if "Contents" not in resp or len(resp["Contents"]) == 0:
            self.cdx_logger.error(f"S3 bucket has no contents at s3://{config['s3_bucket']}/{config['path']}.")
            exit(
                "ERROR: S3 bucket has no contents.  Ensure you have logs at s3://{bucket}/{path}".format(
                    bucket=config["s3_bucket"], path=config["path"]
                )
            )
        self.cdx_logger.debug("S3 bucket content check passed.")


        # Ensure our database exists
        self.cdx_logger.info(f"Ensuring database '{self.database}' exists.")
        self.query_athena(
            "CREATE DATABASE IF NOT EXISTS {db} {comment}".format(
                db=self.database, comment="COMMENT 'Created by CloudTracker'"
            ),
            context=None,
        )
        self.cdx_logger.debug(f"Database '{self.database}' existence ensured.")

        #
        # Set up table
        #
        self.cdx_logger.info(f"Creating external table '{self.table_name}' if it does not exist.")
        query = """CREATE EXTERNAL TABLE IF NOT EXISTS `{table_name}` (
            `eventversion` string COMMENT 'from deserializer', 
            `useridentity` struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>> COMMENT 'from deserializer', 
            `eventtime` string COMMENT 'from deserializer', 
            `eventsource` string COMMENT 'from deserializer', 
            `eventname` string COMMENT 'from deserializer', 
            `awsregion` string COMMENT 'from deserializer', 
            `sourceipaddress` string COMMENT 'from deserializer', 
            `useragent` string COMMENT 'from deserializer', 
            `errorcode` string COMMENT 'from deserializer', 
            `errormessage` string COMMENT 'from deserializer', 
            `requestparameters` string COMMENT 'from deserializer', 
            `responseelements` string COMMENT 'from deserializer', 
            `additionaleventdata` string COMMENT 'from deserializer', 
            `requestid` string COMMENT 'from deserializer', 
            `eventid` string COMMENT 'from deserializer', 
            `resources` array<struct<arn:string,accountid:string,type:string>> COMMENT 'from deserializer', 
            `eventtype` string COMMENT 'from deserializer', 
            `apiversion` string COMMENT 'from deserializer', 
            `readonly` string COMMENT 'from deserializer', 
            `recipientaccountid` string COMMENT 'from deserializer', 
            `serviceeventdetails` string COMMENT 'from deserializer', 
            `sharedeventid` string COMMENT 'from deserializer', 
            `vpcendpointid` string COMMENT 'from deserializer')
            PARTITIONED BY (region string, year string, month string)
            ROW FORMAT SERDE 
            'com.amazon.emr.hive.serde.CloudTrailSerde' 
            STORED AS INPUTFORMAT 
            'com.amazon.emr.cloudtrail.CloudTrailInputFormat' 
            OUTPUTFORMAT 
            'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
            LOCATION '{cloudtrail_log_path}'""".format(
            table_name=self.table_name, cloudtrail_log_path=cloudtrail_log_path
        )
        self.query_athena(query)
        self.cdx_logger.debug(f"Table '{self.table_name}' existence ensured with location '{cloudtrail_log_path}'.")

        #
        # Create partitions
        #

        self.cdx_logger.info(
            "Checking if all partitions for the past {} months exist".format(
                NUM_MONTHS_FOR_PARTITIONS
            )
        )

        # Get list of current partitions
        query = "SHOW PARTITIONS {table_name}".format(table_name=self.table_name)
        self.cdx_logger.debug(f"Fetching existing partitions for table {self.table_name}.")
        partition_list = self.query_athena(query, skip_header=False)

        partition_set = set()
        for partition_row in partition_list: # Renamed to avoid conflict
            partition_set.add(partition_row[0])
        self.cdx_logger.debug(f"Found {len(partition_set)} existing partitions. Example: {next(iter(partition_set)) if partition_set else 'None'}")


        # Get region list. Using ec2 here just because it exists in all regions.
        regions = boto3_session.get_available_regions("ec2")
        self.cdx_logger.debug(f"Available regions for partitions: {regions}")
        self.cdx_logger.debug(f"Checking partitions for {NUM_MONTHS_FOR_PARTITIONS} months across {len(regions)} regions.")


        queries_to_make = set()

        # Iterate over every month for the past year and build queries to run to create partitions
        for num_months_ago in range(0, NUM_MONTHS_FOR_PARTITIONS):
            date_of_interest = datetime.datetime.now() - relativedelta(
                months=num_months_ago
            )
            year = date_of_interest.year
            month = "{:0>2}".format(date_of_interest.month)
            self.cdx_logger.debug(f"Checking/building partitions for year={year}, month={month}")

            query = ""

            for region in regions:
                if (
                    "region={region}/year={year}/month={month}".format(
                        region=region, year=year, month=month
                    )
                    in partition_set
                ):
                    continue

                query += "PARTITION (region='{region}',year='{year}',month='{month}') location '{cloudtrail_log_path}/{region}/{year}/{month}/'\n".format(
                    region=region,
                    year=year,
                    month=month,
                    cloudtrail_log_path=cloudtrail_log_path,
                )
            if query != "":
                queries_to_make.add(
                    "ALTER TABLE {table_name} ADD ".format(table_name=self.table_name) +
                    query
                )
                self.cdx_logger.debug(f"Added ALTER TABLE query for year={year}, month={month} with {query.count('PARTITION')} parts.")

        # Run the queries
        query_count = len(queries_to_make)
        for query in queries_to_make:
            self.cdx_logger.info("Partition groups remaining to create: {}".format(query_count))
            self.query_athena(query)
            query_count -= 1

    def get_performed_users(self):
        """
        Returns the users that performed actions within the search filters
        """
        self.cdx_logger.debug("Fetching performed users.")
        query = "select distinct userIdentity.userName from {table_name} where {search_filter}".format(
            table_name=self.table_name, search_filter=self.search_filter
        )
        self.cdx_logger.debug(f"Performed users query: {query}")
        response = self.query_athena(query)

        user_names = {}
        for row in response:
            user_name = row[0]
            if user_name == "HIDDEN_DUE_TO_SECURITY_REASONS":
                self.cdx_logger.debug("Skipping user 'HIDDEN_DUE_TO_SECURITY_REASONS'.")
                continue
            user_names[user_name] = True
        self.cdx_logger.info(f"Found {len(user_names)} distinct performed users.")
        return user_names

    def get_performed_roles(self):
        """
        Returns the roles that performed actions within the search filters
        """
        self.cdx_logger.debug("Fetching performed roles.")
        query = "select distinct userIdentity.sessionContext.sessionIssuer.userName from {table_name} where {search_filter}".format(
            table_name=self.table_name, search_filter=self.search_filter
        )
        self.cdx_logger.debug(f"Performed roles query: {query}")
        response = self.query_athena(query)

        role_names = {}
        for row in response:
            role = row[0]
            role_names[role] = True
        self.cdx_logger.info(f"Found {len(role_names)} distinct performed roles.")
        return role_names

    def get_search_query(self):
        # Athena doesn't use this call, but needs to support it being called
        self.cdx_logger.debug("get_search_query called, returning None as it's not used by Athena source.")
        return None

    def map_results_for_arns(self, search_results):
        self.cdx_logger.debug(f"Mapping {len(search_results)} results to ARNs.")
        data = {}
        for result in search_results:
            event = result[0]
            event = event[1: len(event) - 1]
            event = event.split(", ")
            arn = event[2].replace("'", "")
            if not arn in data:
                data[arn] = []
            data[arn].append(result)
        self.cdx_logger.debug(f"Mapped to {len(data)} unique ARNs.")
        return data

    def replace_arn(self, arn_string):
        self.cdx_logger.debug(f"Original ARN for replacement: {arn_string}")
        # Use regex to match the part after assumed-role/ and replace only the last section after the underscore
        pattern = r'(assumed-role/[^/]+_)[^/]+(/[^/]+)'

        # Replace the part after the last underscore with '%'
        updated_arn = re.sub(pattern, r'\1%\2', arn_string)
        self.cdx_logger.debug(f"Replaced ARN: {updated_arn}")
        return updated_arn

    def get_events_from_search(self, searchresults):
        """
        Given the results of a query for events, return these in a more usable fashion
        """
        self.cdx_logger.debug(f"Extracting event names from {len(searchresults)} raw event entries.")
        event_names = {}

        for event in searchresults:
            event = event[0]
            # event is now a string like "{field0=s3.amazonaws.com, field1=GetBucketAcl}"
            # I parse out the field manually
            # TODO Find a smarter way to parse this data

            # Remove the '{' and '}'
            event = event[1: len(event) - 1]

            # Split into 'field0=s3.amazonaws.com' and 'field1=GetBucketAcl'
            event = event.split(", ")
            # Get the eventsource 's3.amazonaws.com'
            service = event[0]
            # Get the service 's3'
            service = service.split(".")[0]

            # Get the eventname 'GetBucketAcl'
            eventname = event[1]

            event_names[normalize_api_call(service, eventname)] = True
        self.cdx_logger.debug(f"Extracted {len(event_names)} unique normalized event names.")
        return event_names

    def get_performed_event_names_by_user(self, _, user_iam):
        """For a user, return all performed events"""
        self.cdx_logger.debug(f"Fetching events for user ARN: {user_iam['Arn']}")
        query = "select distinct (eventsource, eventname) from {table_name} where (userIdentity.arn = '{identity}') and {search_filter}".format(
            table_name=self.table_name,
            identity=user_iam["Arn"],
            search_filter=self.search_filter,
        )
        self.cdx_logger.debug(f"Query for user events: {query}")
        response = self.query_athena(query)
        return self.get_events_from_search(response)

    def get_performed_event_names_by_sso_user(self, _, user_iam):
        """For a user, return all performed events"""
        self.cdx_logger.debug(f"Fetching events for SSO user identity pattern: {user_iam['identity']}")
        query = "select distinct (eventsource, eventname) from {table_name} where (userIdentity.arn like '{identity}') and {search_filter}".format(
            table_name=self.table_name,
            identity=user_iam["identity"], # This should be the pattern like 'arn:aws:sts::ACCOUNT:assumed-role/ROLENAME/%'
            search_filter=self.search_filter,
        )
        self.cdx_logger.debug(f"Query for SSO user events: {query}")
        response = self.query_athena(query)
        return self.get_events_from_search(response)

    def get_performed_event_names_by_role(self, _, role_iam):
        """For a role, return all performed events"""
        self.cdx_logger.debug(f"Fetching events for role ARN: {role_iam['Arn']}")
        query = "select distinct (eventsource, eventname) from {table_name} where (userIdentity.sessionContext.sessionIssuer.arn = '{identity}') and {search_filter}".format(
            table_name=self.table_name,
            identity=role_iam["Arn"],
            search_filter=self.search_filter,
        )
        self.cdx_logger.debug(f"Query for role events: {query}")
        response = self.query_athena(query)
        return self.get_events_from_search(response)

    def get_performed_event_names_by_users(self, _, users_arn):
        """For a users, return all performed events"""
        self.cdx_logger.debug(f"Fetching events for multiple user ARNs (first 100 chars): {users_arn[:100]}...")
        query = "select distinct (eventsource, eventname, userIdentity.arn) from {table_name} where (userIdentity.arn in {identities}) and {search_filter}".format(
            table_name=self.table_name,
            identities=users_arn,
            search_filter=self.search_filter,
        )
        self.cdx_logger.debug(f"Query for multiple user events: {query}")
        response = self.query_athena(query)

        data = self.map_results_for_arns(response)
        users_arn = users_arn[1:-1].replace("'", "")
        users_arn = users_arn.replace(" ", "").split(",")
        events_data = {}
        for arn, results in data.items():
            events_data[arn.split("/")[-1]] = self.get_events_from_search(results)

        for arn in users_arn:
            if not arn.split("/")[-1] in events_data:
                events_data[arn.split("/")[-1]] = {}
        self.cdx_logger.debug(f"Processed events for {len(events_data)} users out of {len(users_arn)} requested.")
        return events_data

    def get_performed_event_names_by_sso_users(self, _, users_arn):
        """For a sso users, return all performed events"""
        self.cdx_logger.debug(f"Fetching events for multiple SSO user ARN patterns (first 100 chars): {users_arn[:100]}...")
        users_arn = users_arn[1:-1].replace("'", "")
        users_arn = users_arn.replace(" ", "").split(",")
        identities = ""
        for arn in users_arn:
            identities = identities + f"userIdentity.arn like '{arn}' or "
        identities = f"({identities[:-4]})"
        self.cdx_logger.debug(f"Generated identities filter for SSO users: {identities}")
        query = "select distinct (eventsource, eventname, userIdentity.arn) from {table_name} where {identities} and {search_filter}".format(
            table_name=self.table_name,
            identities=identities,
            search_filter=self.search_filter,
        )
        self.cdx_logger.debug(f"Query for multiple SSO user events: {query}")
        response = self.query_athena(query)

        data = self.map_results_for_arns(response)
        events_data = {}
        for arn, results in data.items():
            events_data[self.replace_arn(arn)] = self.get_events_from_search(results)

        for arn in users_arn:
            if not arn in events_data:
                events_data[arn] = {}
        self.cdx_logger.debug(f"Processed events for {len(events_data)} SSO user patterns out of {len(users_arn)} requested.")
        return events_data

    def get_performed_event_names_by_roles(self, _, roles_arn):
        """For a roles, return all performed events"""
        self.cdx_logger.debug(f"Fetching events for multiple role ARNs (first 100 chars): {roles_arn[:100]}...")
        query = "select distinct (eventsource, eventname, userIdentity.sessionContext.sessionIssuer.arn) from {table_name} where (userIdentity.sessionContext.sessionIssuer.arn in {identities}) and {search_filter}".format(
            table_name=self.table_name,
            identities=roles_arn,
            search_filter=self.search_filter,
        )
        self.cdx_logger.debug(f"Query for multiple role events: {query}")
        response = self.query_athena(query)

        data = self.map_results_for_arns(response)
        roles_arn = roles_arn[1:-1].replace("'", "").replace(" ", "").split(",")
        events_data = {}
        for arn, results in data.items():
            events_data[arn.split("/")[-1]] = self.get_events_from_search(results)

        for arn in roles_arn:
            if not arn.split("/")[-1] in events_data:
                events_data[arn.split("/")[-1]] = {}
        self.cdx_logger.debug(f"Processed events for {len(events_data)} roles out of {len(roles_arn)} requested.")
        return events_data

    def get_performed_event_names_by_user_in_role(
        self, searchquery, user_iam, role_iam
    ):
        """For a user that has assumed into another role, return all performed events"""
        raise Exception("Not implemented")
        sessionquery = (
            searchquery.query(self.get_query_match("eventName", "AssumeRole"))
            .query(self.get_query_match("userIdentity.arn", user_iam["Arn"]))
            .query(self.get_query_match("requestParameters.roleArn", role_iam["Arn"]))
        )

        event_names = {}
        for roleAssumption in sessionquery.scan():
            sessionKey = roleAssumption.responseElements.credentials.accessKeyId
            # I assume the session key is unique enough to use for identifying role assumptions
            # TODO: I should also be using sharedEventID as explained in:
            # https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/
            # I could also use the timings of these events.
            innerquery = searchquery.query(
                self.get_query_match("userIdentity.accessKeyId", sessionKey)
            ).query(
                self.get_query_match(
                    "userIdentity.sessionContext.sessionIssuer.arn", role_iam["Arn"]
                )
            )

            event_names.update(self.get_events_from_search(innerquery))

        return event_names

    def get_performed_event_names_by_role_in_role(
        self, searchquery, role_iam, dest_role_iam
    ):
        """For a role that has assumed into another role, return all performed events"""
        raise Exception("Not implemented")
        sessionquery = (
            searchquery.query(self.get_query_match("eventName", "AssumeRole"))
            .query(
                self.get_query_match(
                    "userIdentity.sessionContext.sessionIssuer.arn", role_iam["Arn"]
                )
            )
            .query(
                self.get_query_match("requestParameters.roleArn", dest_role_iam["Arn"])
            )
        )

        # TODO I should get a count of the number of role assumptions, since this can be millions

        event_names = {}
        count = 0
        for roleAssumption in sessionquery.scan():
            count += 1
            if count % 1000 == 0:
                # This is just info level information, for cases where many role assumptions have happened
                # I should advise the user to just look at the final role, especially for cases where the same role
                # is continuously assuming into another role and that is the only thing assuming into it.
                print("{} role assumptions scanned so far...".format(count))
            sessionKey = roleAssumption.responseElements.credentials.accessKeyId
            innerquery = searchquery.query(
                self.get_query_match("userIdentity.accessKeyId", sessionKey)
            ).query(
                self.get_query_match(
                    "userIdentity.sessionContext.sessionIssuer.arn",
                    dest_role_iam["Arn"],
                )
            )

            event_names.update(self.get_events_from_search(innerquery))

        return event_names
