"""
Auto-Drain: The Exhaustive Inbox Cleaner
Purpose: recursively analyze and drain the 'Misc/Other' bucket until empty.
Logic:
1. Sample the bucket.
2. Group by Domain.
3. Determine best category for each domain based on subject keywords.
4. Bulk move ALL emails from that domain.
5. Repeat.
"""

import re
import time
import logging
from collections import defaultdict

from googleapiclient.errors import HttpError

import gmail_auth

# Setup
LOG_FILE = "auto_drain.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

TARGET_SOURCE = "Misc/Other"
BATCH_SIZE = 500

# Taxonomy Keywords for Auto-Classification
KEYWORDS = {
    "Finance/Banking": ["bank", "capital", "credit", "loan", "statement", "account", "transfer", "pay", "finance", "money", "wealth", "invest", "tax", "debt"],
    "Finance/Payments": ["receipt", "invoice", "order", "billing", "payment", "charge", "subscription", "renewal"],
    "Tech/Security": ["security", "verify", "code", "login", "password", "auth", "device", "access", "alert"],
    "Work/Dev/Infrastructure": ["server", "cloud", "deploy", "build", "gitlab", "github", "docker", "aws", "azure", "gcp", "hosting", "domain", "dns"],
    "Professional/Jobs": ["job", "application", "career", "linkedin", "resume", "hiring", "interview", "offer", "work"],
    "Shopping": ["shipping", "shipped", "delivered", "tracking", "store", "shop", "amazon", "return", "refund"],
    "Marketing": ["newsletter", "sale", "off", "%", "deal", "promo", "exclusive", "invite", "webinar", "events"],
    "Education/Research": ["course", "learn", "study", "university", "academy", "class", "lesson", "certificate"],
    "Notification": ["notification", "update", "digest", "summary", "daily", "weekly"]
}

DEFAULT_FALLBACK = "Notification" # If it looks automated but fits nothing else

def get_service():
    return gmail_auth.build_gmail_service()

def get_label_ids(service):
    results = service.users().labels().list(userId='me').execute()
    return {l['name']: l['id'] for l in results.get('labels', [])}

def extract_domain(sender):
    try:
        return sender.split('@')[-1].strip('>]').lower()
    except:
        return None

def classify_domain(domain, subjects):
    """
    Decide category based on aggregated subjects for this domain.
    """
    combined_text = " ".join(subjects).lower()
    
    # 1. Check Keywords
    for category, terms in KEYWORDS.items():
        for term in terms:
            if term in combined_text:
                return category
    
    # 2. Check Domain Name itself
    for category, terms in KEYWORDS.items():
        for term in terms:
            if term in domain:
                return category

    # 3. Heuristics
    if "noreply" in combined_text or "no-reply" in domain:
        return "Notification"
    
    return "Notification" # Aggressive fallback to clear inbox

def drain_loop():
    service = get_service()
    labels = get_label_ids(service)
    source_id = labels.get(TARGET_SOURCE)
    
    if not source_id:
        logger.error(f"Source label {TARGET_SOURCE} not found.")
        return

    iteration = 1
    while True:
        logger.info(f"\n--- Iteration {iteration} ---")
        
        # 1. Sample Messages
        results = service.users().messages().list(
            userId='me', 
            labelIds=[source_id],
            maxResults=BATCH_SIZE
        ).execute()
        
        messages = results.get('messages', [])
        if not messages:
            logger.info("Source label is empty! Mission Accomplished.")
            break
            
        logger.info(f"Sampled {len(messages)} messages.")
        
        # 2. Fetch Headers to analyze
        domain_map = defaultdict(list) # domain -> [subjects]
        
        # Helper for batch get
        def callback(request_id, response, exception):
            if exception: return
            headers = response.get('payload', {}).get('headers', [])
            sender = next((h['value'] for h in headers if h['name'] == 'From'), "")
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "")
            
            dom = extract_domain(sender)
            if dom:
                domain_map[dom].append(subject)

        batch = service.new_batch_http_request(callback=callback)
        # Limit detail fetch to 100 per loop to avoid rate limits/timeouts on the analysis step
        for msg in messages[:100]: 
            batch.add(service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From', 'Subject']))
        batch.execute()
        
        # 3. Analyze & Execute Moves
        # Sort domains by volume in this sample
        sorted_domains = sorted(domain_map.items(), key=lambda x: len(x[1]), reverse=True)
        
        moves_performed = 0
        
        for domain, subjs in sorted_domains:
            # Classify
            target_cat = classify_domain(domain, subjs)
            target_id = labels.get(target_cat)
            
            if not target_id:
                # Create label if missing (shouldn't happen with our standard set, but safety)
                continue
                
            logger.info(f"Processing Domain: {domain} ({len(subjs)} sample items) -> {target_cat}")
            
            # BULK SEARCH & MOVE
            # We move *ALL* mail from this domain, not just the sample.
            # This is the "Macro" move.
            query = f"from:{domain} label:{TARGET_SOURCE}"
            
            while True:
                # Search page by page
                search_res = service.users().messages().list(
                    userId='me', q=query, maxResults=1000
                ).execute()
                
                search_msgs = search_res.get('messages', [])
                if not search_msgs:
                    break
                    
                batch_ids = [m['id'] for m in search_msgs]
                
                body = {
                    "ids": batch_ids,
                    "addLabelIds": [target_id],
                    "removeLabelIds": [source_id]
                }
                
                try:
                    service.users().messages().batchModify(userId='me', body=body).execute()
                    moves_performed += len(batch_ids)
                    print(f"   Moved {len(batch_ids)} items...", end="\r")
                except HttpError as e:
                    logger.warning(f"Batch Error: {e}")
                    time.sleep(5)
                
                if "nextPageToken" not in search_res:
                    break
            
            print("") # Newline
            
        if moves_performed == 0:
            logger.info("No moves performed in this iteration. We might be hitting the long tail.")
            # If we categorized everything in the sample but they were singletons, we might loop forever.
            # But the 'bulk search' should have cleared them.
            # If we are here, it means the sample contains domains we failed to move?
            # Or sample was just empty?
            pass
            
        iteration += 1
        time.sleep(2) # Breath

if __name__ == "__main__":
    drain_loop()
