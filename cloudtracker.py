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
import yaml
import datetime

from cloudtracker import run
__VERSION__ = '2.0.0'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config",
                        help="Config file name",
                        required=False, default="config.yaml", type=str)
    parser.add_argument("--iam", dest='iam_file',
                        help="IAM output from running `aws iam get-account-authorization-details`",
                        required=False, default="./data/get-account-authorization-details.json", type=str)
    parser.add_argument("--account",
                        help="Account name",
                        required=True, type=str)
    parser.add_argument("--start",
                        help="Start of date range (ex. 2018-01-21). Defaults to one year ago.",
                        required=False, type=str)
    parser.add_argument("--end",
                        help="End of date range (ex. 2018-01-21). Defaults to today.",
                        required=False, type=str)
    parser.add_argument("--list",
                        help="List \'users\' or \'roles\' that have been active",
                        required=False, choices=['users', 'roles'])
    parser.add_argument("--user",
                        help="User to investigate",
                        required=False, default=None, type=str)
    parser.add_argument("--role",
                        help="Role to investigate",
                        required=False, default=None, type=str)
    parser.add_argument("--destrole",
                        help="Role assumed into",
                        required=False, default=None, type=str)
    parser.add_argument("--destaccount",
                        help="Account assumed into (if different)",
                        required=False, default=None, type=str)
    parser.add_argument("--show-used", dest='show_used',
                        help="Only show privileges that were used",
                        required=False, action='store_true')
    parser.add_argument("--ignore-benign", dest='show_benign',
                        help="Don't show actions that aren't likely to be sensitive, "
                        "such as ones that won't exfil data or modify resources",
                        required=False, action='store_false')
    parser.add_argument("--ignore-unknown", dest='show_unknown',
                        help="Don't show granted privileges that aren't recorded in CloudTrail, "
                        "as we don't know if they are used",
                        required=False, action='store_false')
    parser.add_argument("--no-color", dest='use_color',
                        help="Don't use color codes in output",
                        required=False, action='store_false')
    parser.add_argument("--skip-setup", dest='skip_setup',
                        help="For Athena, don't create or test for the tables",
                        required=False, action='store_true', default=False)

    args = parser.parse_args()

    if not (args.user or args.role or args.list):
        parser.error('Must specify a user, role, or list')
    if args.user and args.role:
        parser.error("Must specify a user or a role, not both. Use \"destole\" for assumed role")
    if args.list and (args.user or args.role):
        parser.error('Do not specify a user or role when listing')

    if args.start is None:
        start = datetime.datetime.now() - datetime.timedelta(days=365)
        args.start = '{}-{:0>2}-{:0>2}'.format(start.year, start.month, start.day)
    if args.end is None:
        end = datetime.datetime.now()
        args.end = '{}-{:0>2}-{:0>2}'.format(end.year, end.month, end.day)

    # Read config
    try:
        with open(args.config, 'r') as stream:
            try:
                config = yaml.load(stream)
            except yaml.YAMLError as e:
                exit("ERROR: Loading yaml for config file {}\n{}".format(args.config, e))
    except Exception as e:
        exit("ERROR: Loading config file {}\n{}".format(args.config, e))

    run(args, config, args.start, args.end)

if __name__ == "__main__":
    main()
