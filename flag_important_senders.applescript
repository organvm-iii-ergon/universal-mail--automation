set importantSenders to {"boss@company.com", "admissions@university.edu", "familymember@example.com"}

on is_important(theSender, senderList)
    repeat with s in senderList
        if theSender contains s then return true
    end repeat
    return false
end is_important

tell application "Mail"
    set inboxMessages to messages of inbox
    repeat with msg in inboxMessages
        try
            set s to sender of msg
            if my is_important(s, importantSenders) then
                set flagged status of msg to true
            end if
        end try
    end repeat
end tell
