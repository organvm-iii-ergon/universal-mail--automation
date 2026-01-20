"""
Gmail Archive Labeling Automation v2.1 (Argparse & Robustness)
Author: Comprehensive Email Organization System
Purpose: Exhaustively label all emails in Gmail using Batch APIs and State Persistence.
"""

import os
import re
import time
import json
import logging
import argparse
from collections import defaultdict

from googleapiclient.errors import HttpError

import gmail_auth

# ============================================================================ 
# CONFIGURATION
# ============================================================================ 

# Gmail API scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# State file for resuming interrupted runs
STATE_FILE = "labeler_state.json"
LOG_FILE = "gmail_labeler.log"

# Performance settings
BATCH_GET_SIZE = 20    # Number of 'get' requests per HTTP batch (tuned to reduce rate limits)
BATCH_MODIFY_SIZE = 1000 # Max IDs per batchModify call (API limit is 1000)
LIST_PAGE_SIZE = 500    # Max messages to list per page (API max 500)
BASE_BACKOFF_SECONDS = 10  # Initial delay when backing off rate limits
SYSTEM_LABELS = ["STARRED"]  # System labels we may apply (flags)

# Labels that should also be flagged/starred for priority handling in clients.
PRIORITY_LABELS = {
    "Work/Dev/GitHub",
    "Work/Dev/Code-Review",
    "Work/Dev/Infrastructure",
    "Tech/Security",
    "Finance/Payments",
    "Finance/Banking",
    "Awaiting Reply",
    "Personal",
}

# Labels that should REMAIN in the Inbox (High Priority / Human)
# Everything else will be Archived (removed from INBOX).
KEEP_IN_INBOX = {
    "Personal",
    "Awaiting Reply",
    "To Do",
    "To Respond"
}

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================ 
# LABEL TAXONOMY
# ============================================================================ 

LABEL_RULES = {
    # Work / Development
    "Work/Dev/GitHub": {
        "patterns": [
            r"github\.com",
            r"notifications@github",
            r"@reply\.github\.com",
            r"copilot",
            r"ivi374forivi",
        ],
        "priority": 1,
    },
    "Work/Dev/Code-Review": {
        "patterns": [r"coderabb", r"sourcery", r"qodo", r"codacy", r"copilot", r"llamapre", r"pieces"],
        "priority": 2,
    },
    "Work/Dev/Infrastructure": {
        "patterns": [
            r"cloudflare",
            r"vercel",
            r"netlify",
            r"digitalocean",
            r"railway",
            r"render\\.com",
            r"newrelic",
            r"pieces\\.app",
            r"render",
            r"gitkraken",
            r"notion\\.so",
            r"backblaze",
            r"termius",
        ],
        "priority": 3,
    },
    # Real Estate / Projects (New Cluster)
    "Work/RealEstate": {
        "patterns": [
            r"permit application",
            r"majesticbuilds",
            r"unit s",
            r"elv fr",
            r"tenant",
            r"lease",
        ],
        "priority": 3,
    },
    # AI Services
    "AI/Services": {
        "patterns": [
            r"openai",
            r"anthropic",
            r"claude",
            r"x\.ai",
            r"xai\.com",
            r"xAI LLC",
            r"perplexity",
            r"meta\\.com",
            r"ollama",
        ],
        "priority": 4,
    },
    "AI/Grok": {"patterns": [r"grok", r"x\.ai.*grok"], "priority": 5},
    "AI/Data Exports": {"patterns": [r"data export", r"export is ready", r"download.*data"], "priority": 6},
    # Finance & Payments
    "Finance/Banking": {
        "patterns": [
            r"chase",
            r"capital.?one",
            r"verizon",
            r"gemini",
            r"experian",
            r"chime",
            r"kikoff",
            r"self\\.inc",
            r"nav\.com",
            r"bankofamerica",
            r"wellsfargo",
            r"citi",
            r"usbank",
            r"ally",
            r"marcus",
            r"regions",
            r"pnc",
            r"lendingtree",
            r"trueaccord",
            r"moneylion",
            r"dave\\.com",
            r"nelnet",
            r"studentaid",
            r"loan",
            r"credit score",
            r"credit card",
            r"apr",
            r"refinance",
            r"overdraft",
            r"missionlane",
            r"lenme",
            r"credit report",
            r"collections",
            r"settle",
            r"settlement",
            r"debt",
        ],
        "priority": 7,
    },
    "Finance/Payments": {
        "patterns": [
            r"paypal",
            r"stripe",
            r"kovo",
            r"cash.?app",
            r"true.?finance",
            r"square",
            r"braintree",
            r"plaid",
            r"capitalone",
            r"joingerald",
            r"vola",
            r"venmo",
            r"zelle",
            r"att",
            r"xfinity",
            r"spectrum",
            r"conedison",
            r"discover",
            r"american.?express",
            r"barclaycard",
            r"statement",
            r"invoice",
            r"payment.*due",
            r"floatme",
            r"taxrise",
            r"beem",
            r"onepay",
            r"facebook.*receipt",
            r"meta.*receipt",
            r"ads receipt",
            r"billing issue",
            r"adobe",
            r"past due",
            r"overdue",
            r"declined",
            r"failed payment",
            r"autopay",
            r"renewal",
            r"subscription",
            r"paid",
        ],
        "priority": 8,
    },
    # Subscriptions & Services
    "Tech/Security": {
        "patterns": [
            r"1password",
            r"security.*alert",
            r"login.*detected",
            r"new.*device",
            r"password.*reset",
            r"verification.*code",
            r"dropbox",
            r"todoist",
            r"geico",
            r"facebook",
            r"support\\.facebook\\.com",
            r"business-updates\\.facebook\\.com",
            r"confirming.*login",
            r"google data.*download",
            r"security",
            r"sign in",
            r"unusual activity",
            r"suspicious",
            r"two[- ]factor",
            r"2fa",
        ],
        "priority": 9,
    },
    # Commerce & Shopping
    "Shopping": {
        "patterns": [
            r"uber",
            r"amazon",
            r"ebay",
            r"etsy",
            r"walmart",
            r"target",
            r"deepview",
            r"squarespace",
            r"lafitness",
            r"bestbuy",
            r"costco",
            r"wayfair",
            r"chewy",
            r"zara",
            r"hm\.com",
            r"gap\.com",
            r"oldnavy",
            r"nike",
            r"adidas",
            r"nordstrom",
            r"macys",
            r"uniqlo",
            r"lululemon",
            r"order.*confirm",
            r"shipped",
            r"tracking",
            r"flash sale",
        ],
        "priority": 10,
    },
    # Travel
    "Travel": {
        "patterns": [
            r"united\.com",
            r"aa\.com",
            r"delta\.com",
            r"southwest",
            r"jetblue",
            r"alaskaair",
            r"spirit",
            r"flyfrontier",
            r"marriott",
            r"hilton",
            r"hyatt",
            r"ihg",
            r"airbnb",
            r"vrbo",
            r"booking\.com",
            r"hotels\.com",
            r"expedia",
            r"kayak",
            r"priceline",
            r"orbitz",
            r"hotwire",
            r"itinerary",
            r"boarding.*pass",
            r"flight.*confirm",
        ],
        "priority": 11,
    },
    # Entertainment & Media
    "Entertainment": {"patterns": [r"fandango", r"audible", r"netflix", r"spotify", r"letterboxd", r"popcorn.?frights", r"warprecords", r"pluto", r"rotten.?tomato"], "priority": 12},
    # Education
    "Education/Research": {
        "patterns": [
            r"coursera",
            r"udemy",
            r"skillshare",
            r"edx",
            r"khanacademy",
            r"scholar\.google",
            r"researchgate",
            r"arxiv",
            r"academia\.edu",
            r"learning",
            r"ibo\\.org",
        ],
        "priority": 13,
    },
    # Professional Services
    "Professional/Jobs": {
        "patterns": [
            r"higheredjobs",
            r"indeed",
            r"linkedin.*jobs",
            r"glassdoor",
            r"jobot",
            r"builtin\.com",
            r"ziprecruiter",
            r"monster",
            r"justinwelsh",
            r"training overdue",
            r"compliance",
            r"training",
            r"ppe",
            r"course",
        ],
        "priority": 14,
    },
    # Domain Services
    "Services/Domain": {"patterns": [r"namecheap", r"godaddy", r"domain.*renew", r"dns", r"e\\.godaddy\\.com"], "priority": 15},
    # Notifications (catch-all for services)
    "Notification": {
        "patterns": [
            r"notification",
            r"alert",
            r"reminder",
            r"automatic.?appointment",
            r"udemy.*instructor",
            r"google.*workspace",
            r"trinity-health",
            r"deepview",
            r"todoist",
            r"automatic reply",
            r"auto-reply",
        ],
        "priority": 16,
    },
    # Marketing
    "Marketing": {
        "patterns": [
            r"unsubscribe",
            r"newsletter",
            r"promo",
            r"special.*offer",
            r"offer",
            r"discount",
            r"sale",
            r"hims",
            r"substack",
            r"scaleclients",
            r"collabwriting",
            r"beehiiv",
            r"coursera",
            r"jupitrr",
            r"myhumandesign",
            r"ibo\\.org",
            r"personal loan",
            r"credit card.*waiting",
            r"deal",
            r"last chance",
            r"save",
            r"coupon",
            r"offer ends",
            r"free shipping",
            r"clearance",
        ],
        "priority": 17,
    },
    # Personal
    "Personal": {
        "patterns": [
            r"padavano\.anthony",
            r"a\.j\.?\.?padavano@outlook\.com",
            r"a\.j\.?\.?padavano@icloud\.com",
            r"family",
            r"mom",
            r"dad",
        ],
        "priority": 18,
    },
    # Awaiting Action
    "Awaiting Reply": {"patterns": [r"awaiting.*reply", r"pending.*response"], "priority": 19},
    # Default catch-all routed to a generic folder
    "Misc/Other": {"patterns": [r".*"], "priority": 999},
}

# ============================================================================ 
# UTILITIES
# ============================================================================ 

class StateManager:
    """Handles persistence of the processing state."""
    def __init__(self, filename):
        self.filename = filename
        self.state = self._load()

    def _load(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load state file: {e}")
        return {"next_page_token": None, "total_processed": 0, "history": {}}

    def save(self, page_token, processed_count, history):
        self.state["next_page_token"] = page_token
        self.state["total_processed"] = processed_count
        self.state["history"] = history # Simple label count
        try:
            with open(self.filename, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def get_token(self):
        return self.state.get("next_page_token")

    def get_total(self):
        return self.state.get("total_processed", 0)

    def get_history(self):
        return defaultdict(int, self.state.get("history", {}))

# ============================================================================ 
# CORE ENGINE
# ============================================================================ 

class GmailLabeler:
    def __init__(self, remove_source_label=None):
        self.service = self._authenticate()
        self.state_manager = StateManager(STATE_FILE)
        self.label_cache = {}
        self.stats = self.state_manager.get_history()
        self.total_processed = self.state_manager.get_total()
        self.remove_source_label = remove_source_label
        self._init_labels()

    def _execute_with_backoff(self, func, description, max_retries=5):
        """Execute an API call with exponential backoff on rate limits."""
        delay = BASE_BACKOFF_SECONDS
        for attempt in range(1, max_retries + 1):
            try:
                return func()
            except HttpError as e:
                message = str(e)
                status = getattr(e.resp, "status", None)
                if status in (403, 429) and any(tag in message for tag in ("rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded")):
                    logger.warning(f"{description} rate limited (attempt {attempt}/{max_retries}); sleeping {delay:.1f}s")
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise
        raise RuntimeError(f"{description} failed after {max_retries} retries due to rate limits.")

    def _authenticate(self):
        return gmail_auth.build_gmail_service(scopes=SCOPES)

    def _init_labels(self):
        """Pre-fetch all label IDs to avoid API calls during processing."""
        logger.info("Initializing label cache...")
        results = self.service.users().labels().list(userId="me").execute()
        existing_labels = {l["name"]: l["id"] for l in results.get("labels", [])}

        # User labels required by rules.
        for name in LABEL_RULES.keys():
            if name in existing_labels:
                self.label_cache[name] = existing_labels[name]
            else:
                # Create if missing
                logger.info(f"Creating missing label: {name}")
                label_object = {"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
                created = self.service.users().labels().create(userId="me", body=label_object).execute()
                self.label_cache[name] = created["id"]
        
        # System labels we might apply (e.g., STARRED)
        for sys_name in SYSTEM_LABELS:
            if sys_name in existing_labels:
                self.label_cache[sys_name] = existing_labels[sys_name]
        
        # Ensure Uncategorized exists in cache to enable removal when reassigning.
        if "Uncategorized" not in self.label_cache and "Uncategorized" in existing_labels:
            self.label_cache["Uncategorized"] = existing_labels.get("Uncategorized")
            
        # Ensure the configured remove_source_label exists in cache if provided
        if self.remove_source_label and self.remove_source_label not in self.label_cache:
             if self.remove_source_label in existing_labels:
                 self.label_cache[self.remove_source_label] = existing_labels.get(self.remove_source_label)

    def categorize_message(self, headers):
        """Pure logic: categorize based on headers."""
        sender = ""
        subject = ""
        for h in headers:
            if h['name'].lower() == 'from': sender = h['value']
            if h['name'].lower() == 'subject': subject = h['value']
        
        combined_text = f"{sender} {subject}".lower()
        
        best_match = None
        best_priority = 9999
        
        for label_name, rule in LABEL_RULES.items():
            for pattern in rule["patterns"]:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    if rule["priority"] < best_priority:
                        best_match = label_name
                        best_priority = rule["priority"]
                        break
        return best_match or "Misc/Other"

    def process_batch(self, messages):
        """
        1. Fetch details (Batch Get)
        2. Categorize
        3. Apply changes (Batch Modify)
        """
        # 1. Prepare Batch Get
        batch_results = {}
        
        # Chunk the 'get' requests because batch limits exist (safe at 100)
        # However, we only have 500 max messages here. We can do 5 batches of 100.
        
        message_chunks = [messages[i:i + BATCH_GET_SIZE] for i in range(0, len(messages), BATCH_GET_SIZE)]
        
        for chunk in message_chunks:
            failed_ids = []
            def callback(request_id, response, exception):
                if exception:
                    failed_ids.append(request_id)
                    logger.warning(f"Error fetching message {request_id}: {exception}")
                else:
                    batch_results[request_id] = response

            batch_get = self.service.new_batch_http_request(callback=callback)
            for msg in chunk:
                batch_get.add(
                    self.service.users().messages().get(
                        userId="me", id=msg['id'], format="metadata", metadataHeaders=['From', 'Subject']
                    ),
                    request_id=msg['id']
                )
            self._execute_with_backoff(batch_get.execute, "batch get")
            time.sleep(2.0)

            # Retry failed fetches one-by-one with backoff.
            if failed_ids:
                logger.warning(f"Retrying {len(failed_ids)} messages after rate limits")
                for msg_id in failed_ids:
                    try:
                        resp = self._execute_with_backoff(
                            lambda: self.service.users().messages().get(
                                userId="me", id=msg_id, format="metadata", metadataHeaders=['From', 'Subject']
                            ).execute(),
                            f"retry get {msg_id}"
                        )
                        batch_results[msg_id] = resp
                        time.sleep(0.2)
                    except HttpError as e:
                        logger.error(f"Retry failed for message {msg_id}: {e}")
                time.sleep(1.0)

        # 2. Categorize & Group Modifications
        # Map: (add_label_id, remove_label_id) -> [msg_ids]
        modifications = defaultdict(list)
        uncategorized_id = self.label_cache.get("Uncategorized")
        
        # Get ID for dynamic removal if configured
        remove_source_id = None
        if self.remove_source_label:
            remove_source_id = self.label_cache.get(self.remove_source_label)

        for msg_id, data in batch_results.items():
            if not data: continue
            
            headers = data.get('payload', {}).get('headers', [])
            label_name = self.categorize_message(headers)
            
            # Update stats
            self.stats[label_name] += 1
            
            # Determine Action
            target_label_id = self.label_cache.get(label_name)
            
            # If we don't have a label or it categorized to the "Misc/Other" (fallback),
            # and we are *processing* Misc/Other, we probably don't want to add Misc/Other again?
            # Actually, if it falls back to Misc/Other, we might as well leave it alone if it's already there.
            if not target_label_id:
                continue

            add_list = [target_label_id]
            # Add system priority labels (e.g., STARRED) for selected categories.
            if label_name in PRIORITY_LABELS:
                star_id = self.label_cache.get("STARRED")
                if star_id:
                    add_list.append(star_id)

            remove_list = []
            
            # Logic: If putting into specific category, remove 'Uncategorized' if present
            if uncategorized_id and label_name != "Uncategorized":
                remove_list.append(uncategorized_id)
            
            # Logic: If user specified a source label to remove (e.g. Misc/Other), remove it
            # BUT only if we found a match that is NOT the source label.
            if remove_source_id and label_name != self.remove_source_label:
                remove_list.append(remove_source_id)

            # Logic: ARCHIVE (Remove INBOX) if not in retention list
            # We assume 'INBOX' is the ID for the Inbox label (standard Gmail behavior)
            if label_name not in KEEP_IN_INBOX:
                remove_list.append('INBOX')
            
            add_ids = tuple(add_list)
            remove_ids = tuple(remove_list)
            
            modifications[(add_ids, remove_ids)].append(msg_id)

        # 3. Batch Modify
        # Process modifications in chunks of 1000
        ops_count = 0
        for (add, remove), msg_ids in modifications.items():
            # Chunk ids
            id_chunks = [msg_ids[i:i + BATCH_MODIFY_SIZE] for i in range(0, len(msg_ids), BATCH_MODIFY_SIZE)]
            
            for id_chunk in id_chunks:
                body = {
                    "ids": id_chunk,
                    "addLabelIds": list(add),
                    "removeLabelIds": list(remove)
                }
                try:
                    self._execute_with_backoff(
                        lambda: self.service.users().messages().batchModify(userId="me", body=body).execute(),
                        "batch modify"
                    )
                    ops_count += len(id_chunk)
                except HttpError as e:
                    logger.error(f"Batch modify failed: {e}")
                time.sleep(0.5)
        
        return len(batch_results)

    def run(self, query="has:nouserlabels"):
        logger.info(f"Starting run. Query: {query}")
        
        # Note on Page Tokens: 
        # When processing a queue (e.g., removing labels so they no longer match the query),
        # using page tokens is unreliable because the result set shifts.
        # In this specific case, we prefer to keep asking for the first page if we expect items to disappear.
        # However, to be safe against infinite loops on items we *can't* process, 
        # using a page token is safer, provided we accept we might miss some due to shift.
        # A good hybrid: use page token, but if we process < limit, we might be done?
        # Actually, if we are draining a label (Misc/Other), items WILL be removed.
        # So page tokens are dangerous.
        # We will use page tokens from state ONLY if query is default. 
        # If custom query, we start fresh.
        
        page_token = None
        if query == "has:nouserlabels":
            page_token = self.state_manager.get_token()
        
        start_time = time.time()
        
        try:
            while True:
                # List messages
                results = self._execute_with_backoff(
                    lambda: self.service.users().messages().list(
                        userId="me", 
                        q=query, 
                        maxResults=LIST_PAGE_SIZE, 
                        pageToken=page_token
                    ).execute(),
                    "list messages"
                )
                
                messages = results.get("messages", [])
                
                if not messages:
                    logger.info("No more messages found matching query.")
                    if query == "has:nouserlabels":
                        self.state_manager.save(None, self.total_processed, self.stats)
                    break
                
                count = self.process_batch(messages)
                self.total_processed += count
                
                # Stats & State
                elapsed = time.time() - start_time
                rate = self.total_processed / elapsed if elapsed > 0 else 0
                logger.info(f"Processed batch of {count}. Total: {self.total_processed} (Rate: {rate:.1f} msg/s)")
                
                page_token = results.get("nextPageToken")
                
                if query == "has:nouserlabels":
                    self.state_manager.save(page_token, self.total_processed, self.stats)
                
                # Throttle to respect per-user query limits.
                time.sleep(2.0)
                
                if not page_token:
                    break

        except KeyboardInterrupt:
            logger.warning("Interrupted by user. Saving state...")
            self.state_manager.save(page_token, self.total_processed, self.stats)
        except Exception as e:
            logger.critical(f"Fatal error: {e}", exc_info=True)
            self.state_manager.save(page_token, self.total_processed, self.stats)
        finally:
            logger.info("Run finished.")
            self._print_final_stats()

    def _print_final_stats(self):
        print("\n" + "="*50)
        print("SESSION STATISTICS")
        print("="*50)
        print(f"Total Processed: {self.total_processed}")
        print("Distribution:")
        # Sort by count
        sorted_stats = sorted(self.stats.items(), key=lambda x: x[1], reverse=True)
        for label, count in sorted_stats:
            if count > 0:
                print(f"  {label:<25}: {count}")
        print("="*50 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gmail Labeling Automation")
    parser.add_argument("--query", type=str, default="has:nouserlabels", help="Gmail query to filter messages (default: has:nouserlabels)")
    parser.add_argument("--remove-label", type=str, help="Label to remove if a new category is found (e.g., 'Misc/Other')")
    
    args = parser.parse_args()
    
    app = GmailLabeler(remove_source_label=args.remove_label)
    app.run(query=args.query)
