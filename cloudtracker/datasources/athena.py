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

import logging
import boto3
import time
import json
import datetime
from dateutil.relativedelta import relativedelta

from cloudtracker import normalize_api_call

# Much thanks to Alex Smolen (https://twitter.com/alsmola)
# for his post "Partitioning CloudTrail Logs in Athena"
# https://medium.com/@alsmola/partitioning-cloudtrail-logs-in-athena-29add93ee070

# TODO Delete result objects from S3
# TODO Add ability to skip setup
# TODO Add teardown to remove all the athena tables, partitions, and views


NUM_MONTHS_FOR_PARTITIONS = 12

class Athena(object):
    athena = None
    s3 = None
    database = 'cloudtracker'
    output_bucket = 'aws-athena-query-results-ACCOUNT_ID-REGION'
    search_filter = ''
    table_name = ''


    def query_athena(self, query, context={'Database': database}, do_not_wait=False, skip_header=True):
        logging.debug('Making query {}'.format(query))

        # Make query request dependent on whether the context is None or not
        if context is None:
            response = self.athena.start_query_execution(
                QueryString=query,
                ResultConfiguration={'OutputLocation': self.output_bucket}
            )
        else:
            response = self.athena.start_query_execution(
                QueryString=query,
                QueryExecutionContext=context,
                ResultConfiguration={'OutputLocation': self.output_bucket}
            )

        if do_not_wait:
            return response['QueryExecutionId']

        self.wait_for_query_to_complete(response['QueryExecutionId'])

        # Paginate results and combine them
        rows = []
        paginator = self.athena.get_paginator('get_query_results')
        response_iterator = paginator.paginate(QueryExecutionId=response['QueryExecutionId'])
        row_count = 0
        for response in response_iterator:
            for row in response['ResultSet']['Rows']:
                row_count +=1
                if row_count == 1:
                    if skip_header:
                        # Skip header
                        continue
                rows.append(self.extract_response_values(row))
        return rows


    def extract_response_values(self, row):
        result = []
        for column in row['Data']:
            result.append(column.get('VarCharValue', ''))
        return result


    def wait_for_query_to_complete(self, queryExecutionId):
        """
        Returns when the query completes successfully, or raises an exception if it fails or is canceled.
        Waits until the query finishes running.
        """

        while True:
            response = self.athena.get_query_execution(QueryExecutionId=queryExecutionId)
            state = response['QueryExecution']['Status']['State']
            if state == 'SUCCEEDED':
                return True
            if state == 'FAILED' or state == 'CANCELLED':
                raise Exception('Query entered state {state} with reason {reason}'.format(
                    state=state,
                    reason=response['QueryExecution']['Status']['StateChangeReason']))
            logging.debug('Sleeping 1 second while query {} completes'.format(queryExecutionId))
            time.sleep(1)

    def wait_for_query_batch_to_complete(self, queryExecutionIds):
        """
        Returns when the query completes successfully, or raises an exception if it fails or is canceled.
        Waits until the query finishes running.
        """

        while len(queryExecutionIds) > 0:
            response = self.athena.batch_get_query_execution(QueryExecutionIds=list(queryExecutionIds))
            for query_execution in response['QueryExecutions']:
                state = query_execution['Status']['State']
                if state == 'SUCCEEDED':
                    queryExecutionIds.remove(query_execution['QueryExecutionId'])
                if state == 'FAILED' or state == 'CANCELLED':
                    raise Exception('Query entered state {state} with reason {reason}'.format(
                        state=state,
                        reason=response['QueryExecution']['Status']['StateChangeReason']))

                if len(queryExecutionIds) == 0:
                    return
                logging.debug('Sleeping 1 second while {} queries complete'.format(len(queryExecutionIds)))
                time.sleep(1)


    def __init__(self, config, account, start, end, args):
        # Mute boto except errors
        logging.getLogger('botocore').setLevel(logging.WARN)
        logging.info('Source of CloudTrail logs: s3://{bucket}/{path}'.format(
            bucket=config['s3_bucket'],
            path=config['path']))
        
        # Check start date is not older than a year, as we only create partitions for that far back
        if (datetime.datetime.now() - datetime.datetime.strptime(start, '%Y-%m-%d')).days > 365:
            raise Exception("Start date is over a year old. CloudTracker does not create or use partitions over a year old.")

        #
        # Create date filtering
        #
        month_restrictions = set()
        start = start.split('-')
        end = end.split('-')

        if start[0] == end[0]:
            for month in range(int(start[1]), int(end[1]) + 1):
                month_restrictions.add('(year = \'{:0>2}\' and month = \'{:0>2}\')'.format(start[0], month))
        else:
            # Add restrictions for months in start year
            for month in range(int(start[1]), 12 + 1):
                month_restrictions.add('(year = \'{:0>2}\' and month = \'{:0>2}\')'.format(start[0], month))
            # Add restrictions for months in middle years
            for year in range(int(start[0]), int(end[0])):
                for month in (1, 12 + 1):
                    month_restrictions.add('(year = \'{:0>2}\' and month = \'{:0>2}\')'.format(year, month))
            # Add restrictions for months in final year
            for month in range(1, int(end[1]) + 1):
                month_restrictions.add('(year = \'{:0>2}\' and month = \'{:0>2}\')'.format(end[0], month))
        
        # Combine date filters and add error filter
        self.search_filter = '((' + ' or '.join(month_restrictions) + ') and errorcode IS NULL)'

        self.table_name = 'cloudtrail_logs_{}'.format(account['id'])
        
        #
        # Display the AWS identity (doubles as a check that boto creds are setup)
        #
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        logging.info('Using AWS identity: {}'.format(identity['Arn']))
        current_account_id = identity['Account']
        region = boto3.session.Session().region_name

        if 'output_s3_bucket' in config:
            self.output_bucket = config['output_s3_bucket']
        else:
            self.output_bucket = 's3://aws-athena-query-results-{}-{}'.format(current_account_id, region)
        logging.info('Using output bucket: {}'.format(self.output_bucket))
        cloudtrail_log_path = 's3://{bucket}/{path}/AWSLogs/{account_id}/CloudTrail'.format(
            bucket=config['s3_bucket'],
            path=config['path'],
            account_id=account['id'])
        logging.info('Account cloudtrail log path: {}'.format(cloudtrail_log_path))

        # Open connections to needed AWS services
        self.athena = boto3.client('athena')
        self.s3 = boto3.client('s3')

        if args.skip_setup:
            logging.info("Skipping initial table creation")
            return

        # Check we can access the S3 bucket
        resp = self.s3.list_objects_v2(Bucket=config['s3_bucket'], Prefix=config['path'], MaxKeys=1)
        if 'Contents' not in resp or len(resp['Contents']) == 0:
            exit('ERROR: S3 bucket has no contents.  Ensure you have logs at s3://{bucket}/{path}'.format(
                bucket=config['s3_bucket'],
                path=config['path']))

        # Ensure our database exists
        self.query_athena(
            'CREATE DATABASE IF NOT EXISTS {db} {comment}'.format(
                db=self.database,
                comment='COMMENT \'Created by CloudTracker\''),
            context=None)

        #
        # Set up table
        #
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
                table_name=self.table_name,
                cloudtrail_log_path=cloudtrail_log_path)
        self.query_athena(query)

        #
        # Create partitions
        #

        logging.info('Checking if all partitions for the past {} months exist'.format(NUM_MONTHS_FOR_PARTITIONS))

        # Get list of current partitions
        query = 'SHOW PARTITIONS {table_name}'.format(table_name=self.table_name)
        partition_list = self.query_athena(query, skip_header=False)

        partition_set = set()
        for partition in partition_list:
            partition_set.add(partition[0])

        # Get region list. Using ec2 here just because it exists in all regions.
        regions = boto3.session.Session().get_available_regions('ec2')

        queries_to_make = set()

        # Iterate over every month for the past year and build queries to run to create partitions
        for num_months_ago in range(0, NUM_MONTHS_FOR_PARTITIONS):
            date_of_interest = datetime.datetime.now() - relativedelta(months=num_months_ago)
            year = date_of_interest.year
            month = '{:0>2}'.format(date_of_interest.month)

            query = ''

            for region in regions:
                if 'region={region}/year={year}/month={month}'.format(
                        region=region,
                        year=year,
                        month=month
                    ) in partition_set:
                    continue

                query += "PARTITION (region='{region}',year='{year}',month='{month}') location '{cloudtrail_log_path}/{region}/{year}/{month}/'\n".format(
                    region=region,
                    year=year,
                    month=month,
                    cloudtrail_log_path=cloudtrail_log_path)
            if query != '':
                queries_to_make.add('ALTER TABLE {table_name} ADD '.format(table_name=self.table_name) + query)

        # Run the queries
        query_count = len(queries_to_make)
        for query in queries_to_make:
            logging.info('Partition groups remaining to create: {}'.format(query_count))
            self.query_athena(query)
            query_count -= 1


    def get_performed_users(self):
        """
        Returns the users that performed actions within the search filters
        """
        query = 'select distinct userIdentity.userName from {table_name} where {search_filter}'.format(
            table_name=self.table_name,
            search_filter=self.search_filter)
        response = self.query_athena(query)
        
        user_names = {}
        for row in response:
            user_name = row[0]
            if user_name == 'HIDDEN_DUE_TO_SECURITY_REASONS':
                # This happens when a user logs in with the wrong username
                continue
            user_names[user_name] = True
        return user_names


    def get_performed_roles(self):
        """
        Returns the roles that performed actions within the search filters
        """
        query = 'select distinct userIdentity.sessionContext.sessionIssuer.userName from {table_name} where {search_filter}'.format(
            table_name=self.table_name,
            search_filter=self.search_filter)
        response = self.query_athena(query)

        role_names = {}
        for row in response:
            role = row[0]
            role_names[role] = True
        return role_names


    def get_search_query(self):
        # Athena doesn't use this call, but needs to support it being called
        return None


    def get_events_from_search(self, searchresults):
        """
        Given the results of a query for events, return these in a more usable fashion
        """
        event_names = {}

        for event in searchresults:
            event = event[0]
            # event is now a string like "{field0=s3.amazonaws.com, field1=GetBucketAcl}"
            # I parse out the field manually
            # TODO Find a smarter way to parse this data

            # Remove the '{' and '}'
            event = event[1:len(event)-1]

            # Split into 'field0=s3.amazonaws.com' and 'field1=GetBucketAcl'
            event = event.split(", ")
            # Get the eventsource 's3.amazonaws.com'
            service = event[0].split('=')[1]
            # Get the service 's3'
            service = service.split(".")[0]

            # Get the eventname 'GetBucketAcl'
            eventname = event[1].split('=')[1]

            event_names[normalize_api_call(service, eventname)] = True

        return event_names


    def get_performed_event_names_by_user(self, _, user_iam):
        """For a user, return all performed events"""

        query = 'select distinct (eventsource, eventname) from {table_name} where (userIdentity.arn = \'{identity}\') and {search_filter}'.format(
            table_name=self.table_name,
            identity=user_iam['Arn'],
            search_filter=self.search_filter)
        response = self.query_athena(query)
        
        return self.get_events_from_search(response)


    def get_performed_event_names_by_role(self, _, role_iam):
        """For a role, return all performed events"""
        
        query = 'select distinct (eventsource, eventname) from {table_name} where (userIdentity.sessionContext.sessionIssuer.arn = \'{identity}\') and {search_filter}'.format(
            table_name=self.table_name,
            identity=role_iam['Arn'],
            search_filter=self.search_filter)
        response = self.query_athena(query)

        return self.get_events_from_search(response)


    def get_performed_event_names_by_user_in_role(self, searchquery, user_iam, role_iam):
        """For a user that has assumed into another role, return all performed events"""
        raise Exception("Not implemented")
        sessionquery = searchquery.query(self.get_query_match('eventName', 'AssumeRole')) \
            .query(self.get_query_match('userIdentity.arn', user_iam['Arn'])) \
            .query(self.get_query_match('requestParameters.roleArn', role_iam['Arn']))

        event_names = {}
        for roleAssumption in sessionquery.scan():
            sessionKey = roleAssumption.responseElements.credentials.accessKeyId
            # I assume the session key is unique enough to use for identifying role assumptions
            # TODO: I should also be using sharedEventID as explained in:
            # https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/
            # I could also use the timings of these events.
            innerquery = searchquery.query(self.get_query_match('userIdentity.accessKeyId', sessionKey)) \
                .query(self.get_query_match('userIdentity.sessionContext.sessionIssuer.arn', role_iam['Arn']))

            event_names.update(self.get_events_from_search(innerquery))

        return event_names


    def get_performed_event_names_by_role_in_role(self, searchquery, role_iam, dest_role_iam):
        """For a role that has assumed into another role, return all performed events"""
        raise Exception("Not implemented")
        sessionquery = searchquery.query(self.get_query_match('eventName', 'AssumeRole')) \
            .query(self.get_query_match('userIdentity.sessionContext.sessionIssuer.arn', role_iam['Arn'])) \
            .query(self.get_query_match('requestParameters.roleArn', dest_role_iam['Arn']))

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
            innerquery = searchquery.query(self.get_query_match('userIdentity.accessKeyId', sessionKey)) \
                .query(self.get_query_match('userIdentity.sessionContext.sessionIssuer.arn', dest_role_iam['Arn']))

            event_names.update(self.get_events_from_search(innerquery))

        return event_names
