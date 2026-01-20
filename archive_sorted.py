"""
Archive Sorted Mail
Purpose: Retroactively remove 'INBOX' label from emails that have been successfully categorized.
This implements "Inbox Zero" for organized mail.
"""

import logging

from googleapiclient.errors import HttpError

import gmail_auth

# Setup
LOG_FILE = "archive_sorted.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Categories that should be ARCHIVED (removed from Inbox)
# We assume everything else (Personal, Awaiting Reply) stays.
ARCHIVE_CATEGORIES = [
    "Finance/Banking",
    "Finance/Payments",
    "Tech/Security",
    "Work/Dev/Infrastructure",
    "Work/Dev/GitHub",
    "Work/Dev/Code-Review",
    "Work/RealEstate",
    "Shopping",
    "Travel",
    "Entertainment",
    "Education/Research",
    "Professional/Jobs",
    "Services/Domain",
    "Notification",
    "Marketing",
    "AI/Grok",
    "AI/Services",
    "AI/Data Exports",
    "Misc/Other" # Even Misc should be archived if we are done with it
]

def get_service():
    return gmail_auth.build_gmail_service()

def archive_loop():
    service = get_service()
    
    for category in ARCHIVE_CATEGORIES:
        logger.info(f"--- Archiving {category} ---")
        
        # Query: Has label X AND is in Inbox
        query = f"label:{category} label:INBOX"
        
        while True:
            try:
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
                    "removeLabelIds": ['INBOX']
                }
                
                service.users().messages().batchModify(userId='me', body=body).execute()
                logger.info(f"   Archived {len(ids)} messages...")
                
                # If we processed a full page, loop again to catch more (pagination via fresh query)
                if len(ids) < 1000:
                    break
            except HttpError as e:
                logger.warning(f"API Error: {e}")
                break

if __name__ == "__main__":
    archive_loop()
