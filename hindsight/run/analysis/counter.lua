require "string"
msgcount = 0

function process_message()
    msgcount = msgcount + 1
    return 0
end

function timer_event()
    inject_payload("txt", "count", string.format("%d message analysed", msgcount))
end
