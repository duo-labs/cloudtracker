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

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
from cloudtracker import normalize_api_call

class ElasticSearch(object):
    es = None
    index = "cloudtrail"
    key_prefix = ""

    # Create search filters
    searchfilter = None


    def __init__(self, config, start, end):
        # Open connection to ElasticSearch
        self.es = Elasticsearch([config], timeout=900)
        self.searchfilter = {}
        self.index = config.get('index', 'cloudtrail')
        self.key_prefix = config.get('key_prefix', '')
        if self.key_prefix != "":
            self.key_prefix += "."
        self.timestamp_field = config.get('timestamp_field', 'eventTime')

        # Used to make elasticsearch query language semantics dynamically based on version
        self.es_version = int(self.es.info()['version']['number'].split('.')[0])

        # Filter errors
        # https://www.elastic.co/guide/en/elasticsearch/reference/2.0/breaking_20_query_dsl_changes.html
        # http://www.dlxedu.com/askdetail/3/0620e1124992fb281da93c7efe53b97f.html
        if self.es_version < 2:
            error_filter = {'exists': {'field': self.get_field_name('errorCode')}}
            self.searchfilter['filter_errors'] = ~Q('filtered', filter=error_filter)
        else:
            self.searchfilter['filter_errors'] = ~Q('exists', field=self.get_field_name('errorCode'))

        # Filter dates
        if start:
            self.searchfilter['start_date_filter'] = Q('range', **{self.timestamp_field: {'gte': start}})
        if end:
            self.searchfilter['end_date_filter'] = Q('range', **{self.timestamp_field: {'lte': end}})

    def get_field_name(self, field):
        return self.key_prefix + field + self.get_field_suffix()

    def get_field_suffix(self):
        # The .keyword and .raw suffix only apply to indices whose names match logstash-*
        # https://discuss.elastic.co/t/no-raw-field/49342/4
        # However, based on our suggested mapping, our fields should have a .keyword suffix

        # https://www.elastic.co/guide/en/logstash/5.0/breaking-changes.html
        if self.es_version < 5:
            return ".raw"
        else:
            return ".keyword"

    def get_query_match(self, field, value):
        field = self.get_field_name(field)
        return {'match': {field: value}}

    def get_performed_users(self):
        """
        Returns the users that performed actions within the search filters
        """
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
        searchquery = searchquery.query(self.get_query_match('userIdentity.arn', user_iam['Arn']))
        return self.get_events_from_search(searchquery)


    def get_performed_event_names_by_role(self, searchquery, role_iam):
        """For a role, return all performed events"""
        field = 'userIdentity.sessionContext.sessionIssuer.arn'
        searchquery = searchquery.query(self.get_query_match(field, role_iam['Arn']))
        return self.get_events_from_search(searchquery)


    def get_performed_event_names_by_user_in_role(self, searchquery, user_iam, role_iam):
        """For a user that has assumed into another role, return all performed events"""
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
