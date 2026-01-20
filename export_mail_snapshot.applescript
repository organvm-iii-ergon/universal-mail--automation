set outPath to (POSIX path of (path to home folder)) & "mail_automation/mail_export.tsv"

-- open file for writing
set outFile to open for access (outPath as POSIX file) with write permission
set eof outFile to 0

-- header row
set AppleScript's text item delimiters to tab
write ("mailbox_name" & tab & "message_id" & tab & "sender" & tab & "subject" & tab & "date_received" & tab & "read" & tab & "flagged" & tab & "size_bytes" & linefeed) to outFile

tell application "Mail"
    -- you can change this to {inbox} if you want to limit only to Inbox
    set allMailboxes to mailboxes

    repeat with mbox in allMailboxes
        set boxName to name of mbox

        try
            set msgList to messages of mbox
        on error
            set msgList to {}
        end try

        repeat with msg in msgList
            try
                set senderAddress to sender of msg
                set subjectText to subject of msg
                set dateText to (date received of msg) as string
                set readStatus to read status of msg
                set flaggedStatus to flagged status of msg
                set sizeValue to size of msg

                set rowText to boxName & tab & (message id of msg as string) & tab & senderAddress & tab & subjectText & tab & dateText & tab & (readStatus as string) & tab & (flaggedStatus as string) & tab & (sizeValue as string)

                write (rowText & linefeed) to outFile
            end try
        end repeat
    end repeat
end tell

close access outFile
