set days_threshold to 90
set cutoffDate to (current date) - (days_threshold * days)

set targetMailboxName to "Archive" -- change to your desired mailbox name
set targetAccountName to "" -- optional: e.g. "iCloud" or your mail account name; "" to use default account

tell application "Mail"
    set inboxMessages to messages of inbox
    if targetAccountName is "" then
        set targetMailbox to mailbox targetMailboxName
    else
        set targetMailbox to mailbox targetMailboxName of account targetAccountName
    end if

    repeat with msg in inboxMessages
        try
            if date received of msg < cutoffDate then
                move msg to targetMailbox
            end if
        end try
    end repeat
end tell
