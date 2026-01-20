-- Edit this list based on your report
set bulkDomains to {"mailchimp.com", "substack.com", "newsletter.yourfav.com"}
set bulkMailboxName to "Newsletters" -- create this mailbox in Mail first
set bulkAccountName to "" -- e.g. "iCloud" if needed

on is_bulk_sender(theSender, domainList)
    repeat with d in domainList
        set dom to contents of d
        if theSender contains ("@" & dom) or theSender ends with dom then
            return true
        end if
    end repeat
    return false
end is_bulk_sender

tell application "Mail"
    if bulkAccountName is "" then
        set bulkMailbox to mailbox bulkMailboxName
    else
        set bulkMailbox to mailbox bulkMailboxName of account bulkAccountName
    end if

    set inboxMessages to messages of inbox
    repeat with msg in inboxMessages
        try
            set s to sender of msg
            if my is_bulk_sender(s, bulkDomains) then
                move msg to bulkMailbox
            end if
        end try
    end repeat
end tell
