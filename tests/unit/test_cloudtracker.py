"""
Copyright 2017-present, Duo Security

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
---------------------------------------------------------------------------
"""

import sys
import unittest
from cStringIO import StringIO
from contextlib import contextmanager
import mock

from cloudtracker import make_list, read_aws_api_list, Privileges, normalize_api_call, print_actor_diff, print_diff, get_role_iam, get_role_allowed_actions

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

    def test_make_list(self):
        """Test make_list"""
        self.assertEquals(["hello"], make_list("hello"))


    def test_get_actions_from_statement(self):
        """Test get_actions_from_statement"""
        aws_api_list = read_aws_api_list()
        privileges = Privileges(aws_api_list)
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

        # Create a privile object with some allowed and denied
        privileges.add_stmt(stmt)
        privileges.add_stmt({'Action': ['s3:GetObjectTagging', 's3:GetObjectTorrent'],
                             "Resource": "*",
                             "Effect": "Deny"})
        self.assertEquals(privileges.determine_allowed(), ['s3:putobjecttagging', 's3:deleteobjecttagging'])


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
        with mock.patch('cloudtracker.is_recorded_by_cloudtrail', side_effect=mocked_is_recorded_by_cloudtrail):
            with capture(print_diff,
                         ['s3:createbucket'], # performed
                         ['s3:createbucket'], # allowed
                         {'show_benign': True, 'show_used': False, 'show_unknown': True}, False) as output:
                self.assertEquals('  s3:createbucket\n', output)

        # 3 actions allowed, one is used, one is unused, and one is unknown; show all
        with mock.patch('cloudtracker.is_recorded_by_cloudtrail', side_effect=mocked_is_recorded_by_cloudtrail):
            with capture(print_diff,
                         ['s3:createbucket', 'sts:getcalleridentity'], # performed
                         ['s3:createbucket', 's3:putobject', 's3:deletebucket'], # allowed
                         {'show_benign': True, 'show_used': False, 'show_unknown': True}, False) as output:
                self.assertEquals('  s3:createbucket\n- s3:deletebucket\n? s3:putobject\n', output)

        # Same as above, but only show the used one
        with mock.patch('cloudtracker.is_recorded_by_cloudtrail', side_effect=mocked_is_recorded_by_cloudtrail):
            with capture(print_diff,
                         ['s3:createbucket', 'sts:getcalleridentity'], # performed
                         ['s3:createbucket', 's3:putobject', 's3:deletebucket'], # allowed
                         {'show_benign': True, 'show_used': True, 'show_unknown': True}, False) as output:
                self.assertEquals('  s3:createbucket\n', output)

        # Hide the unknown
        with mock.patch('cloudtracker.is_recorded_by_cloudtrail', side_effect=mocked_is_recorded_by_cloudtrail):
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
        self.assertEquals(['s3:putobject', 'kms:describekey', 'kms:decrypt', 's3:putobjectacl'],
                          get_role_allowed_actions(aws_api_list, self.role_iam, account_iam))
