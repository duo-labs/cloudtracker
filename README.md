CloudTracker helps you find over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.

Installation
============
CloudTracker requires you to have loaded CloudTrail logs into ElasticSearch.  For instructions on setting up ElasticSearch and ingesting an archive of CloudTrail logs into it see [ElasticSearch installation and ingestion](docs/elasticsearch.md)

### Step 1
Install the Python libraries:
```
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2
Get the IAM data of the account

```
aws iam get-account-authorization-details > my_account_iam.json
```

### Step 3
Edit the `config.yaml`.  You need to specify how to connect to the ElasticSearch cluster, what index the CloudTrail logs are stored in, and information about your AWS account, including the location of the IAM file created in Step 3.

Example `config.yaml` file:
```
elasticsearch:
  host: localhost
  port: 9200
  index: "cloudtrail"
  key_prefix: ""
accounts:
  - name: demo
    id: 123456789012
    iam: demo_iam.json
```

The ElasticSearch configuration section works the same as what is available to the ElasticSearch python library documented here: http://elasticsearch-py.readthedocs.io/en/master/api.html#elasticsearch

Additionally, you can configure:

- `index`: The index you loaded your files at.
- `key_prefix`: Any prefix you have to your CloudTrail records.  For example, if your `eventName` is queryable via `my_cloudtrail_data.eventName`, then the `key_prefix` would be `my_cloudtrail_data`.


Example usage
=======

Listing actors
-------
CloudTracker provides command line options to list the users and roles in an account. For example:
```
$ python cloudtracker.py --account demo --list users --start 2018-01-01
  alice
- bob
  charlie
```

In this example, a list of users was obtained from the the IAM information and then from CloudTrail logs it was found that the user "bob" has no record of being used since January 1, 2018, and therefore CloudTracker is advising the user's removal by prefixing the user with a "-".  

Note that not all AWS activities are stored in CloudTrail logs.  Specificially, data level events such as reading and writing S3 objects, putting CloudWatch metrics, and more.  Therefore, it is possible that "bob" has been active but only with actions that are not recorded in CloudTrail.  Note also that you may have users or roles that are inactive that you may still wish to keep around.  For example, you may have a role that is only used once a year during an annual task.  You should therefore use this output as guidance, but not always as instructions.

You can also list roles.

```
$ python cloudtracker.py --account demo --list roles --start 2018-01-01
  admin
```

Listing actions of actors
-----------
The main purpose of CloudTracker is to look at the API calls made by actors (users and roles).  Let's assume `alice` has `SecurityAditor` privileges for her user which grants her the ability to `List` and `Describe` metadata for resources, plus the ability to `AsssumeRole` to the `admin` role.  We can see her actions:

```
python cloudtracker.py --account demo --user alice
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
python cloudtracker.py --account demo --user alice --show-used
Getting info on alice, user created 2017-09-02T18:02:14Z
  cloudwatch:describealarmhistory
  cloudwatch:describealarms
+ s3:createbucket
  sts:assumerole
```

We can do the same thing for roles.  For example:
```
python cloudtracker.py --account demo --role admin --show-used
Getting info for role admin
  s3:createbucket
  iam:createuser
```


You may know that `alice` can assume to the `admin` role, so let's look at what she did there using the `--destrole` argument:
```
python cloudtracker.py --account demo --user alice --destrole admin --show-used
Getting info on alice, user created 2017-09-02T18:02:14Z
Getting info for AssumeRole into admin
  s3:createbucket
  iam:createuser
```

You may also know that `charlie` can assume to the `admin` role, so let's look at what he did there:
```
python cloudtracker.py --account demo --user charlie --destrole admin --show-used
Getting info on charlie, user created 2017-10-01T01:01:01Z
Getting info for AssumeRole into admin
  s3:createbucket
```

In this example we can see that `charlie` has only ever created an S3 bucket as `admin`, so we may want to remove `charlie` from being able to assume this role or create another role that does not have the ability to create IAM users which we saw `alice` use.  This is the key feature of CloudTracker as identifying which users are actually making use of the roles they can assume into, and the actions they are using there, is difficult without a tool like CloudTracker.

Working with multiple accounts
-----------------
Amazon has advocated the use of multiple AWS accounts in much of their recent guidance.  This helps reduce the blast radius of incidents, among other benefits.  Once you start using multiple accounts though, you will find you may need to rethink how you are accessing all these accounts.  One way of working with multiple accounts will have users assuming roles into different accounts.  We can analyze the role assumptions of users into a different account the same way we did previously for a single account, except this time you need to ensure that you have CloudTrail logs from both accounts of interest are loaded into ElasticSearch.


```
python cloudtracker.py --account demo --user charlie --destaccount backup --destrole admin --show-used
Getting info on charlie, user created 2017-10-01T01:01:01Z
Getting info for AssumeRole into admin
  s3:createbucket
```

In this example, we used the `--destaccount` option to specify the destination account.


Data files
=============
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

