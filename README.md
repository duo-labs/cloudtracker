CloudTracker helps you find over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.

*Intro post: https://duo.com/blog/introducing-cloudtracker-an-aws-cloudtrail-log-analyzer*


This document will describe the setup that uses Athena and how to use the tool.  CloudTracker no longer requires ElasticSearch, but if you'd like to use CloudTracker with ElasticSearch please see [ElasticSearch installation and ingestion](docs/elasticsearch.md).

Setup
=====

### Step 1: Setup CloudTracker

```
python3 -m venv ./venv && source venv/bin/activate
pip install cloudtracker
```

Note: To install with ElasticSearch support, see the [ElasticSearch docs](docs/elasticsearch.md).

### Step 2: Download your IAM data
Download a copy of the IAM data of an account using the AWS CLI:

```
mkdir -p account-data
aws iam get-account-authorization-details > account-data/demo_iam.json
```

### Step 3: Configure CloudTracker

Create a `config.yaml` file with contents similar to:

```
athena:
  s3_bucket: my_log_bucket
  path: my_prefix
accounts:
  - name: demo
    id: 111111111111
    iam: account-data/demo_iam.json
```

This assumes your CloudTrail logs are at `s3://my_log_bucket/my_prefix/AWSLogs/111111111111/CloudTrail/`
Set `my_prefix` to `''` if you have no prefix.

If your CloudTrail is managed through an organisation you can configure this in the `athena` section:

```
athena:
  s3_bucket: my_log_bucket
  path: my_prefix
  org_id: o-myid123
```

### Step 4: Run CloudTracker

CloudTracker uses boto and assumes it has access to AWS credentials in environment variables, which can be done by using [aws-vault](https://github.com/99designs/aws-vault).

You will need the privilege `arn:aws:iam::aws:policy/AmazonAthenaFullAccess` and also `s3:GetObject` and `s3:ListBucket` for the S3 bucket containing the CloudTrail logs.

Once you're running in an aws-vault environment (or otherwise have your environment variables setup for an AWS session), you can run:

```
cloudtracker --account demo --list users
```

This will perform all of the initial setup which takes about a minute. Subsequent calls will be faster.


Clean-up
--------

CloudTracker does not currently clean up after itself, so query results are left behind in the default bucket `aws-athena-query-results-ACCOUNT_ID-REGION`.  

If you wanted to get rid of all signs of CloudTracker, remove the query results from that bucket and in Athena run `DROP DATABASE cloudtracker CASCADE`


Example usage
=============

Listing actors
--------------
CloudTracker provides command line options to list the users and roles in an account. For example:
```
$ cloudtracker --account demo --list users --start 2018-01-01
  alice
- bob
  charlie
```

In this example, a list of users was obtained from the the IAM information and then from CloudTrail logs it was found that the user "bob" has no record of being used since January 1, 2018, and therefore CloudTracker is advising the user's removal by prefixing the user with a "-".  

Note that not all AWS activities are stored in CloudTrail logs.  Specifically, data level events such as reading and writing S3 objects, putting CloudWatch metrics, and more.  Therefore, it is possible that "bob" has been active but only with actions that are not recorded in CloudTrail.  Note also that you may have users or roles that are inactive that you may still wish to keep around.  For example, you may have a role that is only used once a year during an annual task.  You should therefore use this output as guidance, but not always as instructions.

You can also list roles.

```
$ cloudtracker --account demo --list roles --start 2018-01-01
  admin
```

Listing actions of actors
-------------------------
The main purpose of CloudTracker is to look at the API calls made by actors (users and roles).  Let's assume `alice` has `SecurityAditor` privileges for her user which grants her the ability to `List` and `Describe` metadata for resources, plus the ability to `AsssumeRole` to the `admin` role.  We can see her actions:

```
cloudtracker --account demo --user alice
...
  cloudwatch:describealarmhistory
  cloudwatch:describealarms
- cloudwatch:describealarmsformetric
- cloudwatch:getdashboard
? cloudwatch:getmetricdata
...
+ s3:createbucket
...
```

A lot of actions will be shown, many that are unused, as there are over a thousand AWS APIs, and most people tend to only use a few. In the snippet above, we can see that she has called `DescribeAlarmHistory` and `DescribeAlarms`.  She has never called `DescribeAlarmsForMetric` or `GetDashboard` even though she has those privileges, and it is unknown if she has called `GetMetricData` as that call is not recorded in CloudTrail.  Then further down I notice there is a call to `CreateBucket` that she made, but does not have privileges for.  This can happen if the actor previously had privileges for an action and used them, but those privileges were taken away.  Errors are filtered out, so if the actor made a call but was denied, it would not show up as used.

As there may be a lot of unused or unknown actions, we can filter things down:
```
cloudtracker --account demo --user alice --show-used
Getting info on alice, user created 2017-09-02T18:02:14Z
  cloudwatch:describealarmhistory
  cloudwatch:describealarms
+ s3:createbucket
  sts:assumerole
```

We can do the same thing for roles.  For example:
```
cloudtracker --account demo --role admin --show-used
Getting info for role admin
  s3:createbucket
  iam:createuser
```

### Output explanation
CloudTracker shows a diff of the privileges granted vs used.  The symbols mean the following:

- ` ` No symbol means this privilege is used, so leave it as is.
- `-` A minus sign means the privilege was granted, but not used, so you should remove it.
- `?` A question mark means the privilige was granted, but it is unknown if it was used because it is not recorded in CloudTrail.
- `+` A plus sign means the privilege was not granted, but was used. The only way this is possible is if the privilege was previously granted, used, and then removed, so you may want to add that privilege back.


Advanced functionality (only supported with ElasticSearch currently)
----------------------
This functionality is not yet supported with the Athena configuration of CloudTracker.

You may know that `alice` can assume to the `admin` role, so let's look at what she did there using the `--destrole` argument:
```
cloudtracker --account demo --user alice --destrole admin --show-used
Getting info on alice, user created 2017-09-02T18:02:14Z
Getting info for AssumeRole into admin
  s3:createbucket
  iam:createuser
```

You may also know that `charlie` can assume to the `admin` role, so let's look at what he did there:
```
cloudtracker --account demo --user charlie --destrole admin --show-used
Getting info on charlie, user created 2017-10-01T01:01:01Z
Getting info for AssumeRole into admin
  s3:createbucket
```

In this example we can see that `charlie` has only ever created an S3 bucket as `admin`, so we may want to remove `charlie` from being able to assume this role or create another role that does not have the ability to create IAM users which we saw `alice` use.  This is the key feature of CloudTracker as identifying which users are actually making use of the roles they can assume into, and the actions they are using there, is difficult without a tool like CloudTracker.

### Working with multiple accounts

Amazon has advocated the use of multiple AWS accounts in much of their recent guidance.  This helps reduce the blast radius of incidents, among other benefits.  Once you start using multiple accounts though, you will find you may need to rethink how you are accessing all these accounts.  One way of working with multiple accounts will have users assuming roles into different accounts.  We can analyze the role assumptions of users into a different account the same way we did previously for a single account, except this time you need to ensure that you have CloudTrail logs from both accounts of interest are loaded into ElasticSearch.


```
cloudtracker --account demo --user charlie --destaccount backup --destrole admin --show-used
Getting info on charlie, user created 2017-10-01T01:01:01Z
Getting info for AssumeRole into admin
  s3:createbucket
```

In this example, we used the `--destaccount` option to specify the destination account.


Data files
==========
CloudTracker has two long text files that it uses to know what actions exist.

aws_actions.txt
---------------
This file contains all possible AWS API calls that can be made.  One use of this is for identifying privileges granted by an IAM policy when a regex has been used, such as expanding `s3:*`.

This file was created by running:
```
git clone --depth 1 -b master https://github.com/boto/botocore.git
find botocore/botocore/data -name *.json | xargs cat | jq -r 'select(.operations != null) as $parent | .operations | keys | .[] | $parent.metadata.endpointPrefix +":"+.' | sort | uniq > aws_actions.txt
```

cloudtrail_supported_events.txt
-------------------------------
This file contains the AWS API calls that are recorded in CloudTrail logs.  This is used to identify when the status of a privilege is "unknown" (ie. not known whether it has been used or not).

This file was creating by copying aws_actions.txt and removing events manually based on the CloudTrail user guide (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/awscloudtrail-ug.pdf) in the section "CloudTrail Supported Services" and following the links to the various services and reading through what is and isn't supported.

