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

__version__ = "2.1.5"

import pkg_resources
import re

from colors import color
import jmespath

cloudtrail_supported_actions = None

# Translate CloudTrail name -> IAM name
# Pulled from: http://bit.ly/2txbx1L
# but some of the names there seem reversed
SERVICE_RENAMES = {
    "monitoring": "cloudwatch",
    "email": "ses",
}

# Translate IAM name -> Cloudtrail name (SOAP API name)
# Pulled from https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudtrail-logging.html
# I think S3 is the only service where IAM names are different than the API calls.
EVENT_RENAMES = {
    "s3:listallmybuckets": "s3:listbuckets",
    "s3:getbucketaccesscontrolpolicy": "s3:getbucketacl",
    "s3:setbucketaccesscontrolpolicy": "s3:putbucketacl",
    "s3:getbucketloggingstatus": "s3:getbucketlogging",
    "s3:setbucketloggingstatus": "s3:putbucketlogging",
}

# List of actions seen in CloudTrail logs for which no IAM policies exist.
# These are allowed by default.
NO_IAM = {
    "sts:getcalleridentity": True,
    "sts:getsessiontoken": True,
    "signin:consolelogin": True,
    "signin:checkmfa": True,
    "signin:exitrole": True,
    "signin:renewrole": True,
    "signin:switchrole": True,
}


class Privileges(object):
    """Keep track of privileges an actor has been granted"""

    stmts = None
    roles = None
    aws_api_list = None

    def __init__(self, aws_api_list):
        self.stmts = []
        self.roles = []
        self.aws_api_list = aws_api_list

    def add_stmt(self, stmt):
        """Adds a statement from an IAM policy"""
        if "Action" not in stmt:
            # TODO Implement NotAction
            return
        self.stmts.append(stmt)

    def get_actions_from_statement(self, stmt):
        """Figures out what API calls have been granted from a statement"""
        actions = {}

        for action in make_list(stmt["Action"]):
            # Normalize it
            action = action.lower()
            # Convert it's globbing to a regex
            action = "^" + action.replace("*", ".*") + "$"

            for possible_action in self.aws_api_list:
                for iam_name, cloudtrail_name in EVENT_RENAMES.items():
                    if possible_action == cloudtrail_name:
                        possible_action = iam_name
                if re.match(action, possible_action):
                    actions[possible_action] = True

        return actions

    def determine_allowed(self):
        """After statements have been added from IAM policiies, find all the allowed API calls"""
        actions = {}

        # Look at alloweds first
        for stmt in self.stmts:
            if stmt["Effect"] == "Allow":
                stmt_actions = self.get_actions_from_statement(stmt)
                for action in stmt_actions:
                    if action not in actions:
                        actions[action] = [stmt]
                    else:
                        actions[action].append(stmt)

        # Look at denied
        for stmt in self.stmts:
            if (
                stmt["Effect"] == "Deny" and
                "*" in make_list(stmt.get("Resource", None)) and
                stmt.get("Condition", None) is None
            ):

                stmt_actions = self.get_actions_from_statement(stmt)
                for action in stmt_actions:
                    if action in actions:
                        del actions[action]

        return list(actions)


def make_list(obj):
    """Convert an object to a list if it is not already"""
    if isinstance(obj, list):
        return obj
    return [obj]


def normalize_api_call(service, eventName):
    """Translate API calls to a common representation"""
    service = service.lower()
    eventName = eventName.lower()

    # Remove the dates from event names, such as createdistribution2015_07_27
    eventName = eventName.split("20")[0]

    # Rename the service
    if service in SERVICE_RENAMES:
        service = SERVICE_RENAMES[service]

    return "{}:{}".format(service, eventName)


def get_account_iam(account, boto3_session, cdx_logger):
    """Given account data, retrieve the account's full IAM authorization details."""
    cdx_logger.info(f"Attempting to get IAM account authorization details for account {account['id']}.")
    iam_client = boto3_session.client('iam')
    response = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": []
    }
    try:
        paginator = iam_client.get_paginator('get_account_authorization_details')
        for page in paginator.paginate():
            response['GroupDetailList'].extend(page['GroupDetailList'])
            response['Policies'].extend(page['Policies'])
            response['UserDetailList'].extend(page['UserDetailList'])
            response['RoleDetailList'].extend(page['RoleDetailList'])

            for user_detail in page.get('UserDetailList', []):
                for policy in user_detail.get('UserPolicyList', []):
                    policy['Arn'] = f"arn:aws:iam::{account['id']}:policy/{policy['PolicyName']}"
                    policy['PolicyVersionList'] = [{"Document": policy['PolicyDocument']}]
                    del policy['PolicyDocument']
                    response['Policies'].append(policy)

            for group_detail in page.get('GroupDetailList', []):
                for policy in group_detail.get('GroupPolicyList', []):
                    policy['Arn'] = f"arn:aws:iam::{account['id']}:policy/{policy['PolicyName']}"
                    policy['PolicyVersionList'] = [{"Document": policy['PolicyDocument']}]
                    del policy['PolicyDocument']
                    response['Policies'].append(policy)

            for role_detail in page.get('RoleDetailList', []):
                for policy in role_detail.get('RolePolicyList', []):
                    policy['Arn'] = f"arn:aws:iam::{account['id']}:policy/{policy['PolicyName']}"
                    policy['PolicyVersionList'] = [{"Document": policy['PolicyDocument']}]
                    del policy['PolicyDocument']
                    response['Policies'].append(policy)
        cdx_logger.info("Successfully retrieved IAM account authorization details.")
    except Exception as e:
        cdx_logger.error(f"Failed to retrieve IAM account authorization details: {e}", exc_info=True)
        return response
    return response


def get_allowed_users(account_iam):
    """Return all the users in an IAM file"""
    return jmespath.search("UserDetailList[].UserName", account_iam)


def get_allowed_roles(account_iam):
    """Return all the roles in an IAM file"""
    return jmespath.search("RoleDetailList[].RoleName", account_iam)


def print_actor_diff(performed_actors, allowed_actors, use_color):
    """
    Given a list of actors that have performed actions, and a list that exist in the account,
    print the actors and whether they are still active.
    """
    PERFORMED_AND_ALLOWED = 1
    PERFORMED_BUT_NOT_ALLOWED = 2
    ALLOWED_BUT_NOT_PERFORMED = 3

    actors = {}
    for actor in performed_actors:
        if actor in allowed_actors:
            actors[actor] = PERFORMED_AND_ALLOWED
        else:
            actors[actor] = PERFORMED_BUT_NOT_ALLOWED

    for actor in allowed_actors:
        if actor not in actors:
            actors[actor] = ALLOWED_BUT_NOT_PERFORMED

    for actor in sorted(actors.keys()):
        if actors[actor] == PERFORMED_AND_ALLOWED:
            colored_print("  {}".format(actor), use_color, "white")
        elif actors[actor] == PERFORMED_BUT_NOT_ALLOWED:
            # Don't show users that existed but have since been deleted
            continue
        elif actors[actor] == ALLOWED_BUT_NOT_PERFORMED:
            colored_print("- {}".format(actor), use_color, "red")
        else:
            raise Exception("Unknown constant")


def get_user_iam(username, account_iam, cdx_logger):
    """Given the IAM of an account, and a username, return the IAM data for the user"""
    cdx_logger.debug(f"Getting IAM data for user: {username}")
    user_iam = jmespath.search(
        "UserDetailList[] | [?UserName == `{}`] | [0]".format(username), account_iam
    )
    if not user_iam:
        cdx_logger.warning(f"User '{username}' not found in account IAM data.")
    return user_iam


def get_role_iam(rolename, account_iam, cdx_logger):
    """Given the IAM of an account, and a role name, return the IAM data for the role"""
    cdx_logger.debug(f"Getting IAM data for role: {rolename}")
    role_iam = jmespath.search(
        "RoleDetailList[] | [?RoleName == `{}`] | [0]".format(rolename), account_iam
    )
    if not role_iam:
        cdx_logger.warning(f"Role '{rolename}' not found in account IAM data.")
    return role_iam


def get_policy_iam(policyname, account_iam, cdx_logger):
    """Given the IAM of an account, and a role name, return the IAM data for the role"""
    cdx_logger.debug(f"Getting IAM data for policy: {policyname}")
    policy_iam = jmespath.search(
        "Policies[] | [?PolicyName == `{}`] | [0]".format(policyname), account_iam
    )
    if not policy_iam:
        cdx_logger.warning(f"Policy '{policyname}' not found in account IAM data.")
    return policy_iam


def get_user_allowed_actions(aws_api_list, user_iam, account_iam, cdx_logger):
    """Return the privileges granted to a user by IAM"""
    cdx_logger.debug(f"Determining allowed actions for user: {user_iam.get('UserName', 'Unknown')}")
    groups = user_iam["GroupList"]
    managed_policies = user_iam["AttachedManagedPolicies"]

    privileges = Privileges(aws_api_list)

    # Get permissions from groups
    for group in groups:
        group_iam = jmespath.search(
            "GroupDetailList[] | [?GroupName == `{}`] | [0]".format(group), account_iam
        )
        if group_iam is None:
            cdx_logger.debug(f"Group '{group}' not found for user.")
            continue
        # Get privileges from managed policies attached to the group
        for managed_policy in group_iam.get("AttachedManagedPolicies", []):
            policy_filter = "Policies[?Arn == `{}`].PolicyVersionList[?IsDefaultVersion == true] | [0][0].Document"
            policy = jmespath.search(
                policy_filter.format(managed_policy["PolicyArn"]), account_iam
            )
            if policy is None:
                cdx_logger.debug(f"Managed policy '{managed_policy['PolicyArn']}' not found for group '{group}'.")
                continue
            for stmt in make_list(policy.get("Statement", [])):
                privileges.add_stmt(stmt)

        # Get privileges from in-line policies attached to the group
        for inline_policy in group_iam.get("GroupPolicyList", []):
            policy = inline_policy.get("PolicyDocument")
            if policy:
                for stmt in make_list(policy.get("Statement", [])):
                    privileges.add_stmt(stmt)

    # Get privileges from managed policies attached to the user
    for managed_policy in managed_policies:
        policy_filter = "Policies[?Arn == `{}`].PolicyVersionList[?IsDefaultVersion == true] | [0][0].Document"
        policy = jmespath.search(
            policy_filter.format(managed_policy["PolicyArn"]), account_iam
        )
        if policy is None:
            cdx_logger.debug(f"Managed policy '{managed_policy['PolicyArn']}' not found for user.")
            continue
        for stmt in make_list(policy.get("Statement", [])):
            privileges.add_stmt(stmt)

    # Get privileges from inline policies attached to the user
    for stmt in (
        jmespath.search("UserPolicyList[].PolicyDocument.Statement", user_iam) or []
    ):
        privileges.add_stmt(stmt)

    allowed_actions = privileges.determine_allowed()
    cdx_logger.debug(f"Determined {len(allowed_actions)} allowed actions for user.")
    return allowed_actions


def get_role_allowed_actions(aws_api_list, role_iam, account_iam, cdx_logger):
    """Return the privileges granted to a role by IAM"""
    cdx_logger.debug(f"Determining allowed actions for role: {role_iam.get('RoleName', 'Unknown')}")
    privileges = Privileges(aws_api_list)

    # Get privileges from managed policies
    for managed_policy in role_iam.get("AttachedManagedPolicies", []):
        policy_filter = "Policies[?Arn == `{}`].PolicyVersionList[?IsDefaultVersion == true] | [0][0].Document"
        policy = jmespath.search(
            policy_filter.format(managed_policy["PolicyArn"]), account_iam
        )
        if policy is None:
            cdx_logger.debug(f"Managed policy '{managed_policy['PolicyArn']}' not found for role.")
            continue
        for stmt in make_list(policy.get("Statement", [])):
            privileges.add_stmt(stmt)

    # Get privileges from attached policies
    for policy in role_iam.get("RolePolicyList", []):
        if "PolicyDocument" in policy:
            for stmt in make_list(policy["PolicyDocument"].get("Statement", [])):
                privileges.add_stmt(stmt)

    allowed_actions = privileges.determine_allowed()
    cdx_logger.debug(f"Determined {len(allowed_actions)} allowed actions for role.")
    return allowed_actions


def get_policy_allowed_actions(aws_api_list, policy_iam, account_iam, cdx_logger):
    """Return the privileges granted by a policy"""
    cdx_logger.debug(f"Determining allowed actions for policy: {policy_iam.get('PolicyName', 'Unknown')}")
    privileges = Privileges(aws_api_list)

    # Get privileges from managed policies
    policy_filter = "Policies[?Arn == `{}`].PolicyVersionList[?IsDefaultVersion == true] | [0][0].Document"
    policy = jmespath.search(
        policy_filter.format(policy_iam["Arn"]), account_iam
    )
    if policy:
        for stmt in make_list(policy.get("Statement", [])):
            privileges.add_stmt(stmt)
    else:
        cdx_logger.warning(f"Policy document not found for ARN: {policy_iam['Arn']}")


    allowed_actions = privileges.determine_allowed()
    cdx_logger.debug(f"Determined {len(allowed_actions)} allowed actions for policy.")
    return allowed_actions


def is_recorded_by_cloudtrail(action):
    """Given an action, return True if it would be logged by CloudTrail"""
    if action in cloudtrail_supported_actions:
        return True
    return False


def colored_print(text, use_color=True, color_name="white"):
    """Print with or without color codes"""
    if use_color:
        print(color(text, fg=color_name))
    else:
        print(text)


def print_diff(performed_actions, allowed_actions, printfilter, use_color):
    """
    For an actor, given the actions they performed, and the privileges they were granted,
    print what they were allowed to do but did not, and other differences.
    """
    PERFORMED_AND_ALLOWED = 1
    PERFORMED_BUT_NOT_ALLOWED = 2
    ALLOWED_BUT_NOT_PERFORMED = 3
    ALLOWED_BUT_NOT_KNOWN_IF_PERFORMED = 4

    actions = {}

    used_permissions = []
    unused_permissions = []

    for action in performed_actions:
        # Convert to IAM names
        for iam_name, cloudtrail_name in EVENT_RENAMES.items():
            if action == cloudtrail_name:
                action = iam_name

        # See if this was allowed or not
        if action in allowed_actions:
            actions[action] = PERFORMED_AND_ALLOWED
        else:
            if action in NO_IAM:
                # Ignore actions in cloudtrail such as sts:getcalleridentity that are allowed
                # whether or not they are in IAM
                continue
            actions[action] = PERFORMED_BUT_NOT_ALLOWED

    # Find actions that were allowed, but there is no record of them being used
    for action in allowed_actions:
        if action not in actions:
            if not is_recorded_by_cloudtrail(action):
                actions[action] = ALLOWED_BUT_NOT_KNOWN_IF_PERFORMED
            else:
                actions[action] = ALLOWED_BUT_NOT_PERFORMED

    for action in sorted(actions.keys()):
        # Convert CloudTrail name back to IAM name
        display_name = action

        if not printfilter.get("show_benign", True):
            # Ignore actions that won't exfil or modify resources
            if ":list" in display_name or ":describe" in display_name:
                continue

        if actions[action] == PERFORMED_AND_ALLOWED:
            # colored_print("  {}".format(display_name), use_color, "white")
            used_permissions.append(display_name)
        elif actions[action] == PERFORMED_BUT_NOT_ALLOWED:
            continue
            # colored_print("+ {}".format(display_name), use_color, "green")
        elif actions[action] == ALLOWED_BUT_NOT_PERFORMED:
            if printfilter.get("show_used", True):
                # Ignore this as it wasn't used
                continue
            # colored_print("- {}".format(display_name), use_color, "red")
            unused_permissions.append(display_name)
        elif actions[action] == ALLOWED_BUT_NOT_KNOWN_IF_PERFORMED:
            if printfilter.get("show_used", True):
                # Ignore this as it wasn't used
                continue
            if printfilter.get("show_unknown", True):
                0
                # colored_print("? {}".format(display_name), use_color, "yellow")
        else:
            raise Exception("Unknown constant")
    return unused_permissions, used_permissions


def get_account(accounts, account_name):
    """
    Gets the account struct from the config file, for the account name specified

    accounts: array of accounts from the config file
    account_name: name to search for (or ID)
    """
    for account in accounts:
        if account_name == account["name"] or account_name == str(account["id"]):
            # Sanity check all values exist
            if "name" not in account or "id" not in account:
                exit(
                    "ERROR: Account {} does not specify an id or iam in the config file".format(
                        account_name
                    )
                )

            # Sanity check account ID
            if not re.search("[0-9]{12}", str(account["id"])):
                exit("ERROR: {} is not a 12-digit account id".format(account["id"]))

            return account
    exit("ERROR: Account name {} not found in config".format(account_name))
    return None


def read_aws_api_list(aws_api_list_file="aws_api_list.txt", cdx_logger=None):
    """Read in the list of all known AWS API calls"""
    if cdx_logger:
        cdx_logger.info(f"Reading AWS API list from {aws_api_list_file}.")
    api_list_path = pkg_resources.resource_filename(
        __name__, "data/{}".format(aws_api_list_file)
    )
    aws_api_list = {}

    with open(api_list_path) as f:
        lines = f.readlines()
    for line in lines:
        parts = line.rstrip().split(":")
        if len(parts) == 2:
            service, event = parts
            aws_api_list[normalize_api_call(service, event)] = True
    if cdx_logger:
        cdx_logger.info(f"Successfully read {len(aws_api_list)} AWS API calls.")

    return aws_api_list


def run(args, config, boto3_session, start, end, account_iam, datasource, principals_arn, athena_boto3_session, cdx_logger):
    """Perform the requested command"""
    cdx_logger.info("Starting run function")
    use_color = args[0].use_color

    account = config["account"]
    if not datasource:
        if "elasticsearch" in config:
            cdx_logger.debug("Using Elasticsearch as datasource")
            try:
                from cloudtracker.datasources.es import ElasticSearch
            except ImportError:
                exit(
                    "Elasticsearch support not installed. Install with support via "
                    "'pip install git+https://github.com/duo-labs/cloudtracker.git#egg=cloudtracker[es1]' for "
                    "elasticsearch 1 support, or "
                    "'pip install git+https://github.com/duo-labs/cloudtracker.git#egg=cloudtracker[es6]' for "
                    "elasticsearch 6 support"
                )
            datasource = ElasticSearch(config["elasticsearch"], start, end, cdx_logger)
        else:
            cdx_logger.debug("Using Athena as datasource")
            from cloudtracker.datasources.athena import Athena
            if not athena_boto3_session:
                athena_boto3_session = boto3_session
            datasource = Athena(config['account']["athena"], account, athena_boto3_session, start, end, args[0], cdx_logger)

    # Read AWS actions
    cdx_logger.debug("Reading AWS API list")
    aws_api_list = read_aws_api_list(cdx_logger=cdx_logger)

    # Read cloudtrail_supported_events
    cdx_logger.debug("Reading CloudTrail supported actions")
    global cloudtrail_supported_actions
    ct_actions_path = pkg_resources.resource_filename(
        __name__, "data/{}".format("cloudtrail_supported_actions.txt")
    )
    cloudtrail_supported_actions = {}
    with open(ct_actions_path) as f:
        lines = f.readlines()
    for line in lines:
        (service, event) = line.rstrip().split(":")
        cloudtrail_supported_actions[normalize_api_call(service, event)] = True

    if not account_iam:
        cdx_logger.debug("Fetching account IAM details")
        account_iam = get_account_iam(account, boto3_session, cdx_logger)
        cdx_logger.debug("Finished fetching account IAM details")


    search_query = datasource.get_search_query()

    users_performed_actions = {}
    roles_performed_actions = {}
    if args[0].user:
        cdx_logger.debug(f"Fetching performed actions for users based on args: {args[0]}")
        if args[0].destpolicy:
            users_performed_actions = datasource.get_performed_event_names_by_users(search_query, principals_arn)
        elif args[0].permissionsetid:
            users_performed_actions = datasource.get_performed_event_names_by_sso_users(search_query, principals_arn)
    elif args[0].role:
        cdx_logger.debug(f"Fetching performed actions for roles based on args: {args[0]}")
        roles_performed_actions = datasource.get_performed_event_names_by_roles(search_query, principals_arn)

    policy_allowed_actions = {}
    data = []
    for arg in args:
        cdx_logger.debug(f"Processing argument: {arg}")
        if arg.list:
            actor_type = arg.list
            cdx_logger.info(f"Listing actors of type: {actor_type}")

            if actor_type == "users":
                allowed_actors = get_allowed_users(account_iam)
                performed_actors = datasource.get_performed_users()
            elif actor_type == "roles":
                allowed_actors = get_allowed_roles(account_iam)
                performed_actors = datasource.get_performed_roles()
            else:
                exit("ERROR: --list argument must be one of 'users' or 'roles'")

            print_actor_diff(performed_actors, allowed_actors, use_color)

        else:
            if arg.destaccount:
                cdx_logger.debug(f"Getting destination account: {arg.destaccount}")
                destination_account = get_account(config["accounts"], arg.destaccount)
            else:
                destination_account = account

            destination_iam = account_iam

            search_query = datasource.get_search_query()

            if arg.user:
                username = arg.user
                cdx_logger.info(f"Processing user: {username}")
                if not username in users_performed_actions:
                    if arg.permissionsetid:
                        user_iam = {
                            "identity": arg.identity
                        }
                        cdx_logger.debug(f"Using identity for permissionsetid: {arg.identity}")
                    else:
                        user_iam = get_user_iam(username, account_iam, cdx_logger)
                        cdx_logger.debug(f"Fetched IAM details for user: {username}")


                    if not user_iam:
                        cdx_logger.warning(f"Could not find IAM details for user: {username}")
                        continue
                # print(
                #     "Getting info for user {}".format(
                #         arg.user
                #     )
                # )

                if arg.destrole:
                    cdx_logger.info(f"Analyzing AssumeRole into role: {arg.destrole} for user {username}")
                    dest_role_iam = get_role_iam(arg.destrole, destination_iam, cdx_logger)
                    if not dest_role_iam:
                        cdx_logger.warning(f"Could not find destination role: {arg.destrole}")
                        continue
                    print("Getting info for AssumeRole into {}".format(arg.destrole))

                    allowed_actions = get_role_allowed_actions(
                        aws_api_list, dest_role_iam, destination_iam, cdx_logger
                    )
                    cdx_logger.debug(f"Calculated allowed actions for destination role: {arg.destrole}")

                    performed_actions = datasource.get_performed_event_names_by_user_in_role(
                        search_query, user_iam, dest_role_iam
                    )
                    cdx_logger.debug(f"Fetched performed actions for user {username} assuming role {arg.destrole}")

                elif arg.destpolicy:
                    cdx_logger.info(f"Analyzing policy: {arg.destpolicy} for user {username}")
                    # print("Getting info for policy {}".format(arg.destpolicy))
                    if not arg.destpolicy in policy_allowed_actions:
                        dest_policy_iam = get_policy_iam(arg.destpolicy, destination_iam, cdx_logger)
                        if not dest_policy_iam:
                            policy_allowed_actions[arg.destpolicy] = []
                            cdx_logger.warning(f"Could not find destination policy: {arg.destpolicy}")
                            continue
                        policy_allowed_actions[arg.destpolicy] = get_policy_allowed_actions(
                            aws_api_list, dest_policy_iam, destination_iam, cdx_logger
                        )
                        cdx_logger.debug(f"Calculated allowed actions for policy: {arg.destpolicy}")
                    allowed_actions = policy_allowed_actions[arg.destpolicy]
                    if not allowed_actions:
                        cdx_logger.info(f"No allowed actions found for policy: {arg.destpolicy}")
                        continue

                    if not username in users_performed_actions:
                        users_performed_actions[username] = datasource.get_performed_event_names_by_user(
                            search_query, user_iam
                        )
                        cdx_logger.debug(f"Fetched performed actions for user: {username}")
                    performed_actions = users_performed_actions[username]

                elif arg.permissionsetid:
                    cdx_logger.info(f"Analyzing permissionsetid: {arg.permissionsetid} for user identity {user_iam['identity']}")
                    allowed_actions = []
                    for policy in arg.policies:
                        if not policy in policy_allowed_actions:
                            dest_policy_iam = get_policy_iam(policy, destination_iam, cdx_logger)
                            if not dest_policy_iam:
                                policy_allowed_actions[policy] = []
                                cdx_logger.warning(f"Could not find policy: {policy} for permissionsetid")
                                continue
                            policy_allowed_actions[policy] = get_policy_allowed_actions(
                                aws_api_list, dest_policy_iam, destination_iam, cdx_logger
                            )
                            cdx_logger.debug(f"Calculated allowed actions for policy: {policy} for permissionsetid")
                        allowed_actions.extend(policy_allowed_actions[policy])
                    if not allowed_actions:
                        cdx_logger.info(f"No allowed actions found for permissionsetid: {arg.permissionsetid}")
                        continue

                    if not user_iam["identity"] in users_performed_actions:
                        users_performed_actions[user_iam["identity"]] = datasource.get_performed_event_names_by_user(
                            search_query, user_iam
                        )
                        cdx_logger.debug(f"Fetched performed actions for user identity: {user_iam['identity']}")
                    performed_actions = users_performed_actions[user_iam["identity"]]

                else:
                    cdx_logger.info(f"Analyzing user: {username}")
                    allowed_actions = get_user_allowed_actions(
                        aws_api_list, user_iam, account_iam, cdx_logger
                    )
                    cdx_logger.debug(f"Calculated allowed actions for user: {username}")
                    performed_actions = datasource.get_performed_event_names_by_user(
                        search_query, user_iam
                    )
                    cdx_logger.debug(f"Fetched performed actions for user: {username}")

            elif arg.role:
                rolename = arg.role
                cdx_logger.info(f"Processing role: {rolename}")
                if not rolename in roles_performed_actions:
                    role_iam = get_role_iam(rolename, account_iam, cdx_logger)
                    if not role_iam:
                        cdx_logger.warning(f"Could not find IAM details for role: {rolename}")
                        continue
                # print("Getting info for role {}".format(rolename))

                if arg.destrole:
                    cdx_logger.info(f"Analyzing AssumeRole into role: {arg.destrole} for role {rolename}")
                    dest_role_iam = get_role_iam(arg.destrole, destination_iam, cdx_logger)
                    print("Getting info for AssumeRole into {}".format(arg.destrole))
                    if not dest_role_iam:
                        cdx_logger.warning(f"Could not find destination role: {arg.destrole}")
                        continue

                    allowed_actions = get_role_allowed_actions(
                        aws_api_list, dest_role_iam, destination_iam, cdx_logger
                    )
                    cdx_logger.debug(f"Calculated allowed actions for destination role: {arg.destrole}")
                    performed_actions = datasource.get_performed_event_names_by_role_in_role(
                        search_query, role_iam, dest_role_iam
                    )
                    cdx_logger.debug(f"Fetched performed actions for role {rolename} assuming role {arg.destrole}")
                elif arg.destpolicy:
                    cdx_logger.info(f"Analyzing policy: {arg.destpolicy} for role {rolename}")
                    # print("Getting info for policy {}".format(arg.destpolicy))
                    if not arg.destpolicy in policy_allowed_actions:
                        dest_policy_iam = get_policy_iam(arg.destpolicy, destination_iam, cdx_logger)
                        if not dest_policy_iam:
                            policy_allowed_actions[arg.destpolicy] = []
                            cdx_logger.warning(f"Could not find destination policy: {arg.destpolicy}")
                            continue
                        policy_allowed_actions[arg.destpolicy] = get_policy_allowed_actions(
                            aws_api_list, dest_policy_iam, destination_iam, cdx_logger
                        )
                        cdx_logger.debug(f"Calculated allowed actions for policy: {arg.destpolicy}")
                    allowed_actions = policy_allowed_actions[arg.destpolicy]
                    if not allowed_actions:
                        cdx_logger.info(f"No allowed actions found for policy: {arg.destpolicy}")
                        continue

                    if not rolename in roles_performed_actions:
                        roles_performed_actions[rolename] = datasource.get_performed_event_names_by_role(
                            search_query, role_iam
                        )
                        cdx_logger.debug(f"Fetched performed actions for role: {rolename}")
                    performed_actions = roles_performed_actions[rolename]
                else:
                    cdx_logger.info(f"Analyzing role: {rolename}")
                    allowed_actions = get_role_allowed_actions(
                        aws_api_list, role_iam, account_iam, cdx_logger
                    )
                    cdx_logger.debug(f"Calculated allowed actions for role: {rolename}")
                    performed_actions = datasource.get_performed_event_names_by_role(
                        search_query, role_iam
                    )
                    cdx_logger.debug(f"Fetched performed actions for role: {rolename}")
            else:
                cdx_logger.error("Neither user nor role specified")
                exit("ERROR: Must specify a user or a role")

            printfilter = {}
            printfilter["show_unknown"] = arg.show_unknown
            printfilter["show_benign"] = arg.show_benign
            printfilter["show_used"] = arg.show_used
            unused_permissions = []
            used_permissions = []
            for action in allowed_actions:
                if action in performed_actions:
                    used_permissions.append(action)
                else:
                    unused_permissions.append(action)

            # unused_permissions, used_permissions = print_diff(performed_actions, allowed_actions, printfilter, use_color)
            principal = {}
            if arg.user:
                principal["name"] = arg.user
            elif arg.role:
                principal["name"] = arg.role
            if arg.destpolicy:
                principal["attachmentName"] = arg.destpolicy
                principal['policyArn'] = arg.destpolicyarn
            elif arg.destrole:
                principal["attachmentName"] = arg.destrole
            elif arg.permissionsetid:
                principal["id"] = arg.permissionsetid

            principal.update({
                "usedPermissions": used_permissions,
                "unusedPermissions": unused_permissions
            })
            data.append(principal)

    cdx_logger.info("Finished run function")
    return data, datasource.output_bucket, account_iam, datasource
