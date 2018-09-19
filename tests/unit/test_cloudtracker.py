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

import sys
import unittest
from unittest.mock import patch
from io import StringIO
from contextlib import contextmanager

from cloudtracker import (get_role_allowed_actions,
                          get_role_iam,
                          make_list,
                          normalize_api_call,
                          print_actor_diff,
                          print_diff,
                          Privileges,
                          read_aws_api_list)


@contextmanager
def capture(command, *args, **kwargs):
    """Capture stdout in order to check it"""
    out, sys.stdout = sys.stdout, StringIO()
    try:
        command(*args, **kwargs)
        sys.stdout.seek(0)
        yield sys.stdout.read()
    finally:
        sys.stdout = out


class TestCloudtracker(unittest.TestCase):
    """Test class for cloudtracker"""
    aws_api_list = None

    def __init__(self, *args, **kwargs):
        super(TestCloudtracker, self).__init__(*args, **kwargs)
        self.aws_api_list = read_aws_api_list()

    def test_make_list(self):
        """Test make_list"""
        self.assertEquals(["hello"], make_list("hello"))


    def test_get_actions_from_statement(self):
        """Test get_actions_from_statement"""

        privileges = Privileges(self.aws_api_list)

        stmt = {"Action": ["s3:PutObject"], "Resource": "*", "Effect": "Allow"}
        self.assertEquals(privileges.get_actions_from_statement(stmt),
                          {'s3:putobject': True})

        stmt = {"Action": ["s3:PutObject*"], "Resource": "*", "Effect": "Allow"}
        self.assertEquals(privileges.get_actions_from_statement(stmt),
                          {'s3:putobject': True, 's3:putobjectacl': True, 's3:putobjecttagging': True})

        stmt = {"Action": ["s3:*ObjectT*"], "Resource": "*", "Effect": "Allow"}
        self.assertEquals(privileges.get_actions_from_statement(stmt),
                          {'s3:deleteobjecttagging': True,
                           's3:getobjecttagging': True,
                           's3:getobjecttorrent': True,
                           's3:putobjecttagging': True})

    def test_policy(self):
        """Test having multiple statements, some allowed, some denied"""
        privileges = Privileges(self.aws_api_list)
        # Create a privilege object with some allowed and denied
        stmt = {"Action": ["s3:*ObjectT*"], "Resource": "*", "Effect": "Allow"}
        privileges.add_stmt(stmt)
        stmt = {'Action': ['s3:GetObjectTagging', 's3:GetObjectTorrent'],
                "Resource": "*",
                "Effect": "Deny"}
        privileges.add_stmt(stmt)
        self.assertEquals(sorted(privileges.determine_allowed()),
                          sorted(['s3:putobjecttagging', 's3:deleteobjecttagging']))

    def test_get_actions_from_statement_with_resources(self):
        """
        Test that even when we are denied access to one resource,
        the actions are still marked as allowed.
        """
        privileges = Privileges(self.aws_api_list)
        policy = [
            {
                "Action": "s3:*",
                "Effect": "Allow",
                "Resource": "*"
            },
            {
                "Action": "s3:CreateBucket",
                "Effect": "Deny",
                "Resource": "*"
            },
            {
                "Action": "s3:*",
                "Effect": "Deny",
                "Resource": [
                    "arn:aws:s3:::super-sensitive-bucket",
                    "arn:aws:s3:::super-sensitive-bucket/*"
                ]
            }
        ]
        for stmt in policy:
            privileges.add_stmt(stmt)
        self.assertTrue('s3:deletebucket' in privileges.determine_allowed())
        self.assertTrue('s3:createbucket' not in privileges.determine_allowed())


    def test_get_actions_from_statement_with_array_of_resources(self):
        """
        Test array of resources
        """
        privileges = Privileges(self.aws_api_list)
        policy = [
            {
                "Action": "s3:*",
                "Effect": "Allow",
                "Resource": "*"
            },
            {
                "Action": "s3:CreateBucket",
                "Effect": "Deny",
                "Resource": ["arn:aws:s3:::super-sensitive-bucket", "*"]
            }
        ]
        for stmt in policy:
            privileges.add_stmt(stmt)
        self.assertTrue('s3:deletebucket' in privileges.determine_allowed())
        self.assertTrue('s3:createbucket' not in privileges.determine_allowed())


    def test_get_actions_from_statement_with_conditions(self):
        """
        Test that even when we are denied access based on a condition,
        the actions are still marked as allowed.
        """
        privileges = Privileges(self.aws_api_list)
        policy = [
            {
                "Sid": "AllowAllActionsForEC2",
                "Effect": "Allow",
                "Action": "ec2:*",
                "Resource": "*"
            },
            {
                "Sid": "DenyStopAndTerminateWhenMFAIsNotPresent",
                "Effect": "Deny",
                "Action": [
                    "ec2:StopInstances",
                    "ec2:TerminateInstances"
                ],
                "Resource": "*",
                "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": False}}
            }
        ]
        for stmt in policy:
            privileges.add_stmt(stmt)
        self.assertTrue('ec2:startinstances' in privileges.determine_allowed())
        self.assertTrue('ec2:stopinstances' in privileges.determine_allowed())


    def test_normalize_api_call(self):
        """Test normalize_api_call"""
        # Ensure the numbers at the end are removed
        self.assertEquals(normalize_api_call('lambda', 'ListTags20170331'), 'lambda:listtags')
        # Ensure service renaming occurs
        self.assertEquals(normalize_api_call('monitoring', 'DescribeAlarms'), 'cloudwatch:describealarms')


    def test_print_actor_diff(self):
        """Test print_actor_diff"""
        with capture(print_actor_diff, [], [], False) as output:
            self.assertEquals('', output)

        # Test output when you have 3 configured users, but only two actually did anything
        with capture(print_actor_diff, ['alice', 'bob'], ['alice', 'bob', 'charlie'], False) as output:
            self.assertEquals('  alice\n  bob\n- charlie\n', output)


    def test_print_diff(self):
        """Test print_diff"""

        with capture(print_diff, [], [], {}, False) as output:
            self.assertEquals('', output)

        def mocked_is_recorded_by_cloudtrail(action):
            """Instead of reading the whole file, just cherry pick this one action used in the tests"""
            if action == 's3:putobject':
                return False
            return True

        # One action allowed, and performed, and should be shown
        with patch('cloudtracker.is_recorded_by_cloudtrail', side_effect=mocked_is_recorded_by_cloudtrail):
            with capture(print_diff,
                         ['s3:createbucket'], # performed
                         ['s3:createbucket'], # allowed
                         {'show_benign': True, 'show_used': False, 'show_unknown': True}, False) as output:
                self.assertEquals('  s3:createbucket\n', output)

        # 3 actions allowed, one is used, one is unused, and one is unknown; show all
        with patch('cloudtracker.is_recorded_by_cloudtrail', side_effect=mocked_is_recorded_by_cloudtrail):
            with capture(print_diff,
                         ['s3:createbucket', 'sts:getcalleridentity'], # performed
                         ['s3:createbucket', 's3:putobject', 's3:deletebucket'], # allowed
                         {'show_benign': True, 'show_used': False, 'show_unknown': True}, False) as output:
                self.assertEquals('  s3:createbucket\n- s3:deletebucket\n? s3:putobject\n', output)

        # Same as above, but only show the used one
        with patch('cloudtracker.is_recorded_by_cloudtrail', side_effect=mocked_is_recorded_by_cloudtrail):
            with capture(print_diff,
                         ['s3:createbucket', 'sts:getcalleridentity'], # performed
                         ['s3:createbucket', 's3:putobject', 's3:deletebucket'], # allowed
                         {'show_benign': True, 'show_used': True, 'show_unknown': True}, False) as output:
                self.assertEquals('  s3:createbucket\n', output)

        # Hide the unknown
        with patch('cloudtracker.is_recorded_by_cloudtrail', side_effect=mocked_is_recorded_by_cloudtrail):
            with capture(print_diff,
                         ['s3:createbucket', 'sts:getcalleridentity'], # performed
                         ['s3:createbucket', 's3:putobject', 's3:deletebucket'], # allowed
                         {'show_benign': True, 'show_used': False, 'show_unknown': False}, False) as output:
                self.assertEquals('  s3:createbucket\n- s3:deletebucket\n', output)

    # Role IAM policy to be used in different tests
    role_iam = {
        "AssumeRolePolicyDocument": {},
        "RoleId": "AROA00000000000000000",
        "CreateDate": "2017-01-01T00:00:00Z",
        "InstanceProfileList": [],
        "RoleName": "test_role",
        "Path": "/",
        "AttachedManagedPolicies": [],
        "RolePolicyList": [
            {
                "PolicyName": "KmsDecryptSecrets",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Action": [
                                "kms:DescribeKey",
                                "kms:Decrypt"
                            ],
                            "Resource": "*",
                            "Effect": "Allow",
                            "Sid": ""
                        }
                    ]
                }
            },
            {
                "PolicyName": "S3PutObject",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Action": [
                                "s3:PutObject",
                                "s3:PutObjectAcl",
                                "s3:ListBucket"
                            ],
                            "Resource": "*",
                            "Effect": "Allow"
                        }
                    ]
                }
            }
        ],
        "Arn": "arn:aws:iam::111111111111:role/test_role"
    }

    def test_get_role_iam(self):
        """Test get_role_iam"""
        account_iam = {
            "RoleDetailList": [self.role_iam],
            "UserDetailList": [],
            "GroupDetailList": [],
            "Policies": []
        }

        self.assertEquals(self.role_iam, get_role_iam("test_role", account_iam))


    def test_get_role_allowed_actions(self):
        """Test get_role_allowed_actions"""
        account_iam = {
            "RoleDetailList": [self.role_iam],
            "UserDetailList": [],
            "GroupDetailList": [],
            "Policies": []
        }

        aws_api_list = read_aws_api_list()
        self.assertEquals(sorted(['s3:putobject', 'kms:describekey', 'kms:decrypt', 's3:putobjectacl']),
                          sorted(get_role_allowed_actions(aws_api_list, self.role_iam, account_iam)))
