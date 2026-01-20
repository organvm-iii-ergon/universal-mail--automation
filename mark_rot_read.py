"""
Mark Rot as Read
Purpose: Mark old (>30 days) emails in low-value categories as READ to clear notification badges.
"""

import logging

import gmail_auth

# Setup
LOG_FILE = "mark_read.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

TARGET_CATEGORIES = [
    "Notification",
    "Marketing",
    "Entertainment",
    "Shopping",
    "Work/Dev/GitHub",
    "Work/Dev/Infrastructure",
    "Misc/Other"
]

def mark_read_loop():
    service = gmail_auth.build_gmail_service()
    
    for category in TARGET_CATEGORIES:
        logger.info(f"--- Clearing Unread: {category} ---")
        
        # Query: Label X + Unread + Older than 7 days
        # We leave recent ones (7 days) unread in case you actually want to see them.
        query = f"label:{category} is:unread older_than:7d"
        
        while True:
            results = service.users().messages().list(
                userId='me', q=query, maxResults=1000
            ).execute()
            
            messages = results.get('messages', [])
            if not messages:
                logger.info(f"   {category}: Clean.")
                break
                
            ids = [m['id'] for m in messages]
            
            body = {
                "ids": ids,
                "removeLabelIds": ['UNREAD']
            }
            
            service.users().messages().batchModify(userId='me', body=body).execute()
            logger.info(f"   Marked {len(ids)} as read...")
            
            if len(ids) < 1000:
                break

if __name__ == "__main__":
    mark_read_loop()
