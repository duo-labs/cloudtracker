-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

--[[
# Single File Input (new line delimited)
todo: when more than line splitting is needed the file should be read in chunks
and passed to a generic splitter buffer with a token/match specification and a
find function similar to the Heka stream reader.
## Sample Configuration
```lua
filename = "file.lua"
-- Name of the input file (nil for stdin)
-- Default:
-- input_filename = nil
-- Heka message table containing the default header values to use, if they are
-- not populated by the decoder. If 'Fields' is specified it should be in the
-- hashed based format see:  http://mozilla-services.github.io/lua_sandbox/heka/message.html
-- Default:
-- default_headers = nil
-- Specifies a module that will decode the raw data and inject the resulting message.
-- Default:
-- decoder_module = "decoders.payload"
-- Boolean, if true, any decode failure will inject a  message of Type "error",
-- with the Payload containing the error.
-- Default:
-- send_decode_failures = false
```
--]]
require "io"
require "string"

local input_filename  = read_config("input_filename")
local default_headers = read_config("default_headers")
assert(default_headers == nil or type(default_headers) == "table", "invalid default_headers cfg")

local decoder_module  = read_config("decoder_module") or "decoders.payload"
local decode          = require(decoder_module).decode
if not decode then
    error(decoder_module .. " does not provide a decode function")
end
local send_decode_failures  = read_config("send_decode_failures")

local err_msg = {
    Type    = "error",
    Payload = nil,
}

function process_message(checkpoint)
    local fh = io.stdin
    if input_filename then
        fh = assert(io.open(input_filename, "rb")) -- closed on plugin shutdown
        if checkpoint then 
            fh:seek("set", checkpoint)
        else
            checkpoint = 0
        end
    end

    local cnt = 0
    for data in fh:lines() do
        local ok, err = pcall(decode, data, default_headers)
        if (not ok or err) and send_decode_failures then
            err_msg.Payload = err
            pcall(inject_message, err_msg)
        end

        if input_filename then
            checkpoint = checkpoint + #data + 1
            inject_message(nil, checkpoint)
        end
        cnt = cnt + 1
    end
    return 0, string.format("processed %d lines", cnt)
end
