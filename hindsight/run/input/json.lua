-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

--[[
# Heka JSON Message Decoder Module
https://wiki.mozilla.org/Firefox/Services/Logging

The above link describes the Heka message format with a JSON schema. The JSON
will be decoded and passed directly to inject_message so it needs to decode into
a Heka message table described here:
https://mozilla-services.github.io/lua_sandbox/heka/message.html

## Decoder Configuration Table
* none

## Functions

### decode

Decode and inject the resulting message

*Arguments*
- data (string) - JSON message with a Heka schema

*Return*
- nil - throws an error on an invalid data type, JSON parse error,
  inject_message failure etc.

--]]

-- Imports
local cjson = require "cjson"

local inject_message = inject_message

local M = {}
setfenv(1, M) -- Remove external access to contain everything in the module

function decode(data)
    inject_message(cjson.decode(data))
end

return M
