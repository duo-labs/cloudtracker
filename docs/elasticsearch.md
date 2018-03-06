CloudTracker requires you to have an ElasticSearch cluster with CloudTrail logs loaded into it.  This document describes how to accomplish that.

Install ElasticSearch
=====================

You can use an AWS managed ElasticSearch cluster or one that you manage, including one running locally on a VM on your laptop.  However, if your logs exceed a few dozen GBs, or over 100M records, you'll likely run into issues running locally.  You'll also want to install Kibana to look at the loaded logs.

Configure the ElasticSearch mapping
-----------------------------------
Using Kibana and clicking on "Dev Tools" you can send commands to ElasticSearch. You can also do this using `curl`.  Run the following to setup a `cloudtrail` index and increase it's total fields to 5000.  If you don't increase that limit, records will be silently dropped.


The commands to send
```
PUT /cloudtrail
{
    "mappings": {
      "doc": {
        "properties": {
          "@timestamp": {
            "type": "date"
          },
          "@version": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "host": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "message": {
            "properties": {
              "additionalEventData": {
                "properties": {
                  "Note": {
                    "type": "text",
                    "fields": {
                      "keyword": {
                        "type": "keyword",
                        "ignore_above": 256
                      }
                    }
                  }
                }
              },
              "apiVersion": {
                "type": "text"
              }
            }
          }
        }
      }
    }
}
```

You can save the above file as `cloudtrail_mapping.json` and then send it to your ElasticSearch cluster using:

```
curl -X PUT https://YOUR_ES_SERVER/cloudtrail -T cloudtrail_mapping.json  -H "Content-Type: application/json"
```


Do the same for:
```
PUT /cloudtrail/_settings
{
  "index.mapping.total_fields.limit": 5000
}
```

You can save that to a file named `cloudtrail_settings.json` and then run:
```
curl -X PUT https://YOUR_ES_SERVER/cloudtrail/_settings -T cloudtrail_settings.json  -H "Content-Type: application/json"
```


Ingest CloudTrail logs into ElasticSearch using Hindsight
=========================================================

Copy your CloudTrail logs locally and convert them to a single flat file.

```
# Replace YOUR_BUCKET and YOUR_ACCOUNT_ID in the following command
aws s3 sync s3://YOUR_BUCKET/AWSLogs/YOUR_ACCOUNT_ID/CloudTrail/ .
find . -name "*.json.gz" -exec gunzip -c {} \; | jq -cr '.Records[] | del(.responseElements.endpoint)' >> ../cloudtrail.json
```

I'm deleting `.responseElements.endpoint` because different API calls return an object or a string for that value and ElasticSearch can't handle mixed types, so I just ignore that value since it is of little use.


Install Hindsight
-----------------
Hindsight is hard to install as it has a number of dependencies.  The project is at https://github.com/mozilla-services/hindsight

Here are some notes, but you'll still probably run into trouble.  Help in improving the installation of those projects would be good.

For the dependencies:
```
sudo yum install -y libcurl-devel autoconf automake libtool cmake

git clone https://github.com/mozilla-services/lua_sandbox.git
cd lua_sandbox
mkdir release
cd release

cmake -DCMAKE_BUILD_TYPE=release ..
make
sudo make install

cd ../..

git clone https://github.com/mozilla-services/lua_sandbox_extensions.git
cd lua_sandbox_extensions
mkdir release
cd release
# Disable a bunch of extensions when we build this to avoid further dependencies
cmake -DCMAKE_BUILD_TYPE=release -DEXT_aws=off -DEXT_kafka=off -DEXT_parquet=off -DEXT_jose=off -DEXT_postgres=off -DEXT_systemd=off -DEXT_snappy=off -DCPACK_GENERATOR=RPM ..
make
make packages
sudo make install
# In my experience I needed to manually install files, or copy or link them, as you should have files named 
# `rjson.so` and `ltn12.lua` at `/usr/local/lib/luasandbox/io_modules/`.
```

Now install Hindsight from https://github.com/mozilla-services/hindsight


Run a proxy
-----------
This may not be needed, but it's helpful, especially when using an AWS managed ElasticSearch cluster.

```
var http = require('http'),
    httpProxy = require('http-proxy');

var proxy = httpProxy.createProxyServer({});

proxy.on('proxyReq', function(proxyReq, req, res, options) {
  console.log("> Proxying: ", req.url);
  proxyReq.setHeader('content-type', 'application/json');
});

proxy.on('proxyRes', function (proxyRes, req, res) {
  console.log("< ", proxyRes.statusCode);
});

var server = http.createServer(function(req, res) {
  proxy.web(req, res, {
    target: 'https://MY_ES_INSTANCE.us-west-2.es.amazonaws.com', secure: false
  });
});

console.log("listening on port 9201")
server.listen(9201);
```

Here you can see I am ignoring any cert errors when making the TLS connection, so you'll need to decide if that is acceptable for your use case.

Run this with:
```
node proxy.js
```


Configure Hindsight
-------------------
This repo includes a `hindsight/run` directory. Copy the `run` directory to your hindsight repo.

Replace `YOUR_FILE` in `run/input/file.cfg` with the full path to your `cloudtrail.json` file.

Replace `127.0.0.1` and the port `9200` in `run/output/elasticsearch_bulk_api.cfg` if you are not running ElasticSearch on your localhost.


Run hindsight
-------------
To run hindsight use:

```
hindsight_cli hindsight.cfg
```

You will also want to run `rm -rf output/*` in between runs to clear out the cached files.
You may need to modify `hindsight.cfg` to tell it the `io_lua_path` and other paths are in `/usr/local/lib/` not `/usr/lib/`

