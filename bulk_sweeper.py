"""
Bulk Sweeper - High Velocity Labeling
Purpose: Apply changes to thousands of emails via Search Queries (Server-side) 
instead of client-side iteration. drastically reduces API calls.
"""

import logging

import gmail_auth

# Configuration
LOG_FILE = "bulk_sweeper.log"
BATCH_SIZE = 1000

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

SWEEP_RULES = [
    {
        "name": "Notion Cleanup",
        "query": "from:notion.so label:Misc/Other",
        "add": "Work/Dev/Infrastructure",
        "remove": "Misc/Other"
    },
    {
        "name": "Backblaze Cleanup",
        "query": "from:backblaze.com label:Misc/Other",
        "add": "Work/Dev/Infrastructure",
        "remove": "Misc/Other"
    },
    {
        "name": "Dave Banking",
        "query": "from:dave.com label:Misc/Other",
        "add": "Finance/Banking",
        "remove": "Misc/Other"
    },
    {
        "name": "Mission Lane",
        "query": "from:missionlane.com label:Misc/Other",
        "add": "Finance/Banking",
        "remove": "Misc/Other"
    },
    {
        "name": "IBO Education",
        "query": "from:ibo.org label:Misc/Other",
        "add": "Education/Research",
        "remove": "Misc/Other"
    },
    {
        "name": "Real Estate / Majestic",
        "query": "from:majesticbuilds.com label:Misc/Other",
        "add": "Work/RealEstate",
        "remove": "Misc/Other"
    },
    {
        "name": "Termius",
        "query": "from:termius.com label:Misc/Other",
        "add": "Work/Dev/Infrastructure",
        "remove": "Misc/Other"
    }
]

def get_service():
    return gmail_auth.build_gmail_service()

def get_label_id(service, name):
    results = service.users().labels().list(userId='me').execute()
    for l in results['labels']:
        if l['name'].lower() == name.lower():
            return l['id']
    return None

def run_sweep():
    service = get_service()
    
    for rule in SWEEP_RULES:
        logger.info(f"--- Running Sweep: {rule['name']} ---")
        
        # Resolve IDs
        add_id = get_label_id(service, rule['add'])
        remove_id = get_label_id(service, rule['remove'])
        
        if not add_id: 
            logger.warning(f"Label not found: {rule['add']}")
            continue
            
        # Search
        total_moved = 0
        while True:
            results = service.users().messages().list(
                userId='me', 
                q=rule['query'],
                maxResults=BATCH_SIZE
            ).execute()
            
            messages = results.get('messages', [])
            if not messages:
                break
                
            ids = [m['id'] for m in messages]
            
            # Batch Modify
            body = {
                "ids": ids,
                "addLabelIds": [add_id],
                "removeLabelIds": [remove_id] if remove_id else []
            }
            
            service.users().messages().batchModify(userId='me', body=body).execute()
            count = len(ids)
            total_moved += count
            logger.info(f"   Moved {count} messages...")
            
            if "nextPageToken" not in results:
                break
        
        if total_moved > 0:
            logger.info(f"✅ Completed {rule['name']}: Moved {total_moved} total.")
        else:
            logger.info(f"   No messages matched.")

if __name__ == "__main__":
    run_sweep()
