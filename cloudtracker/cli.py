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

import yaml

from . import run


def main():
    now = datetime.datetime.now()
    parser = argparse.ArgumentParser()

    # Add mutually exclusive arguments for --list, --user, and --role
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--list",
                              help="List \'users\' or \'roles\' that have been active",
                              choices=['users', 'roles'])
    action_group.add_argument("--user",
                              help="User to investigate",
                              type=str)
    action_group.add_argument("--role",
                              help="Role to investigate",
                              type=str)

    parser.add_argument("--config",
                        help="Config file name (default: config.yaml)",
                        required=False, default="config.yaml",
                        type=argparse.FileType('r'))
    parser.add_argument("--iam", dest='iam_file',
                        help="IAM output from running `aws iam get-account-authorization-details`",
                        required=False, default="./data/get-account-authorization-details.json", type=str)
    parser.add_argument("--account",
                        help="Account name",
                        required=True, type=str)
    parser.add_argument("--start",
                        help="Start of date range (ex. 2018-01-21). Defaults to one year ago.",
                        default=(now - datetime.timedelta(days=365)).date().isoformat(),
                        required=False, type=str)
    parser.add_argument("--end",
                        help="End of date range (ex. 2018-01-21). Defaults to today.",
                        default=now.date().isoformat(),
                        required=False, type=str)
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

    # Read config
    try:
        config = yaml.load(args.config)
    except yaml.YAMLError as e:
        raise argparse.ArgumentError(
            None,
            "ERROR: Could not load yaml from config file {}\n{}".format(args.config.name, e)
        )

    run(args, config, args.start, args.end)
