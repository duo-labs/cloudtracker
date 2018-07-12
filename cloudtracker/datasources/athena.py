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

from cloudtracker import normalize_api_call

# Much thanks to Alex Smolen (https://twitter.com/alsmola) 
# for his post "Partitioning CloudTrail Logs in Athena" 
# https://medium.com/@alsmola/partitioning-cloudtrail-logs-in-athena-29add93ee070

# TODO Delete result objects from S3
# TODO Create partitions
# TODO Create views based on unions of partions
# TODO Add ability to skip setup
# TODO Add teardown to remove all the athena tables, partitions, and views
# TODO Use named parameters for string formatting

class Athena(object):
    athena = None
    s3 = None
    database = 'cloudtracker'
    output_bucket = 'aws-athena-query-results-ACCOUNT_ID-REGION'


    def query_athena(self, query, context={'Database': database}):
        # Make query request dependent on whether the context is None or not
        if context is None:
            response = self.athena.start_query_execution(
                QueryString = query,
                ResultConfiguration = {'OutputLocation': self.output_bucket}
                )
        else:
            response = self.athena.start_query_execution(
                QueryString = query,
                QueryExecutionContext = context,
                ResultConfiguration = {'OutputLocation': self.output_bucket}
                )

        self.wait_for_query_to_complete(response['QueryExecutionId'])

        response = self.athena.get_query_results(QueryExecutionId=response['QueryExecutionId'])
        return response['ResultSet']['Rows']


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
                raise Exception('Query entered state {} with reason {}'.format(state, response['QueryExecution']['Status']['StateChangeReason']))
            logging.info('Sleeping 1 second while query {} completes'.format(queryExecutionId))
            time.sleep(1)


    def __init__(self, config, account, start, end):
        # Mute boto except errors
        logging.getLogger('botocore').setLevel(logging.WARN)
        logging.info('Source of CloudTrail logs: s3://{}/{}'.format(config['s3_bucket'], config['path']))

        # Display the AWS identity (doubles as a check that boto creds are setup)
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
        cloudtrail_log_path = 's3://{}/{}/AWSLogs/{}/CloudTrail'.format(config['s3_bucket'], config['path'], account['id'])
        logging.info('Account cloudtrail log path: {}'.format(cloudtrail_log_path))

        # Open connections to needed AWS services
        self.athena = boto3.client('athena')
        self.s3 = boto3.client('s3')

        # Check we can access the S3 bucket
        resp = self.s3.list_objects_v2(Bucket=config['s3_bucket'], Prefix=config['path'], MaxKeys=1)
        if 'Contents' not in resp or len(resp['Contents']) == 0:
            exit('ERROR: S3 bucket has no contents.  Ensure you have logs at s3://{}/{}'.format(config['s3_bucket'], config['path']))
        
        # Ensure our database exists
        self.query_athena('CREATE DATABASE IF NOT EXISTS {} COMMENT \'Created by CloudTracker\''.format(self.database), context=None)

        #
        # Set up table
        #
        table_name = 'cloudtrail_logs_{}'.format(account['id'])
        query = """CREATE EXTERNAL TABLE IF NOT EXISTS `{}` (
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
            PARTITIONED BY (region string, year string, month string, day string)
            ROW FORMAT SERDE 
            'com.amazon.emr.hive.serde.CloudTrailSerde' 
            STORED AS INPUTFORMAT 
            'com.amazon.emr.cloudtrail.CloudTrailInputFormat' 
            OUTPUTFORMAT 
            'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
            LOCATION '{}'""".format(table_name, cloudtrail_log_path)
        self.query_athena(query)

        #
        # Create partitions
        #

        # TODO Should check if table already exists, and if so, then don't create partitions,
        # since this will take a while.  Or alternatively, I could list the partitions and skip if they exist.

        # Get region list. Using ec2 here just because it exists in all regions.
        regions = boto3.session.Session().get_available_regions('ec2')

        # Iterate over every day for the past year

        for num_days_ago in range(0, 10): # TODO Change to 365
            date_of_interest = datetime.datetime.now() - datetime.timedelta(days=num_days_ago)
            year = date_of_interest.year
            month = '%02d' % date_of_interest.month
            day = '%02d' % date_of_interest.day

            for region in regions:
                logging.info('Adding partition for {region} {year}-{month}-{day}'.format(
                    region = region,
                    year = year,
                    month = month,
                    day = day))
                query = """ALTER TABLE {table_name}
                    ADD IF NOT EXISTS PARTITION (region='{region}',year='{year}',month='{month}',day='{day}')
                    location '{cloudtrail_log_path}/{region}/{year}/{month}/{day}'""".format(
                        table_name = table_name,
                        region = region,
                        year = year,
                        month = month,
                        day = day,
                        cloudtrail_log_path = cloudtrail_log_path)
                self.query_athena(query)




        # path = '{}/AWSLogs/{}/CloudTrail'.format(config['path'], account['id'])
        # response = self.s3.list_objects_v2(Bucket=config['s3_bucket'], Prefix=path)
        # print(response['Contents'])
        



        # response = self.query_athena(query)
        # if response == []:
        #     logging.info("Database does not exist, so creating it")
        #     response = self.query_athena('CREATE DATABASE LIKE \'{}\''.format(self.database), context=None)

        #print(json.dumps(response, indent=4, sort_keys=True))

        exit(-1)



        




        # # Filter errors
        # # https://www.elastic.co/guide/en/elasticsearch/reference/2.0/breaking_20_query_dsl_changes.html
        # # http://www.dlxedu.com/askdetail/3/0620e1124992fb281da93c7efe53b97f.html
        # if self.es_version < 2:
        #     error_filter = {'exists': {'field': self.get_field_name('errorCode')}}
        #     self.searchfilter['filter_errors'] = ~Q('filtered', filter=error_filter)
        # else:
        #     self.searchfilter['filter_errors'] = ~Q('exists', field=self.get_field_name('errorCode'))

        # # Filter dates
        # if start:
        #     self.searchfilter['start_date_filter'] = Q('range', **{self.timestamp_field: {'gte': start}})
        # if end:
        #     self.searchfilter['end_date_filter'] = Q('range', **{self.timestamp_field: {'lte': end}})

    def get_query_match(self, field, value):
        raise Exception("Not implemented")
        field = self.get_field_name(field)
        return {'match': {field: value}}

    def get_performed_users(self):
        """
        Returns the users that performed actions within the search filters
        """
        raise Exception("Not implemented")
        search = Search(using=self.es, index=self.index)
        for query in self.searchfilter.values():
            search = search.query(query)

        search.aggs.bucket('user_names', 'terms', field=self.get_field_name('userIdentity.userName'), size=5000)
        response = search.execute()

        user_names = {}
        for user in response.aggregations.user_names.buckets:
            if user.key == 'HIDDEN_DUE_TO_SECURITY_REASONS':
                # This happens when a user logs in with the wrong username
                continue
            user_names[user.key] = True
        return user_names


    def get_performed_roles(self):
        """
        Returns the roles that performed actions within the search filters
        """
        raise Exception("Not implemented")
        search = Search(using=self.es, index=self.index)
        for query in self.searchfilter.values():
            search = search.query(query)

        userName_field = self.get_field_name('userIdentity.sessionContext.sessionIssuer.userName')
        search.aggs.bucket('role_names', 'terms', field=userName_field, size=5000)
        response = search.execute()

        role_names = {}
        for role in response.aggregations.role_names.buckets:
            role_names[role.key] = True
        return role_names


    def get_search_query(self):
        """
        Opens a connection to ElasticSearch and applies the initial filters
        """
        raise Exception("Not implemented")
        search = Search(using=self.es, index=self.index)
        for query in self.searchfilter.values():
            search = search.query(query)

        return search

    def get_events_from_search(self, searchquery):
        """
        Given a started elasticsearch query, apply the remaining search filters, and
        return the API calls that exist for this query.
        s: search query
        """
        raise Exception("Not implemented")
        searchquery.aggs.bucket('event_names', 'terms', field=self.get_field_name('eventName'), size=5000) \
            .bucket('service_names', 'terms', field=self.get_field_name('eventSource'), size=5000)
        response = searchquery.execute()

        event_names = {}

        for event in response.aggregations.event_names.buckets:
            service = event.service_names.buckets[0].key
            service = service.split(".")[0]

            event_names[normalize_api_call(service, event.key)] = True

        return event_names


    def get_performed_event_names_by_user(self, searchquery, user_iam):
        """For a user, return all performed events"""
        raise Exception("Not implemented")
        searchquery = searchquery.query(self.get_query_match('userIdentity.arn', user_iam['Arn']))
        return self.get_events_from_search(searchquery)


    def get_performed_event_names_by_role(self, searchquery, role_iam):
        """For a role, return all performed events"""
        raise Exception("Not implemented")
        field = 'userIdentity.sessionContext.sessionIssuer.arn'
        searchquery = searchquery.query(self.get_query_match(field, role_iam['Arn']))
        return self.get_events_from_search(searchquery)


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
