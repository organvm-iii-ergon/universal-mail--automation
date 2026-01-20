tell application "Mail"
	-- Create a group for our automation
	try
		make new mailbox with properties {name:"Ω Automation"}
	end try
	
	-- 1. Needs Action (The most important view)
	-- Criteria: Label is "Awaiting Reply" OR "To Do" OR Label is Personal AND Unread
	make new smart mailbox with properties {name:"1. Needs Action", conditions:{¬
		{condition type:sender, qualifier:does contain value:"padavano"}, ¬
		{condition type:message is unread, qualifier:none, expression:""} ¬
		}}
		
	-- 2. Finance Dashboard
	-- Criteria: Label contains "Finance" AND Date is This Month
	make new smart mailbox with properties {name:"2. Finance (Recent)", conditions:{¬
		{condition type:message is in mailbox, qualifier:does contain value:"Finance"}, ¬
		{condition type:date received, qualifier:is less than value:30} ¬
		}}

	-- 3. Dev Alerts
	make new smart mailbox with properties {name:"3. Dev Alerts", conditions:{¬
		{condition type:message is in mailbox, qualifier:does contain value:"Dev"}, ¬
		{condition type:message is unread, qualifier:none, expression:""} ¬
		}}

end tell