"""
Inbox Strategic Value Analyzer
Purpose: transform 'Misc/Other' from a list of emails into a dataset for strategic decision making.
Performs:
1. Sender Domain Clustering (Who is filling the space?)
2. Subject Line Tokenization (What are they talking about?)
3. Value Heuristic Scoring (Signal vs. Noise)
"""

import re
import email.utils
from collections import Counter
import statistics

import gmail_auth

# Configuration
SAMPLE_SIZE = 2000  # Statistically significant sample size
TARGET_LABEL = "Misc/Other"

def get_service():
    return gmail_auth.build_gmail_service()

def extract_domain(email_addr):
    """Extract root domain from email address."""
    if not email_addr: return "unknown"
    try:
        domain = email_addr.split('@')[-1].lower()
        # Basic stripping of > or ] if present
        domain = domain.strip('>]')
        return domain
    except:
        return "unknown"

def calculate_value_score(sender, subject):
    """
    Heuristic to score potential strategic value (0-100).
    High Score = Likely Human/Important
    Low Score = Likely Automated/Noise
    """
    score = 50
    subject_lower = subject.lower()
    sender_lower = sender.lower()
    
    # Penalties (Noise)
    if any(x in sender_lower for x in ['no-reply', 'noreply', 'donotreply', 'info', 'marketing', 'news', 'update']):
        score -= 20
    if any(x in subject_lower for x in ['digest', 'summary', 'log', 'alert', 'notification', 'receipt', 'order', 'off', '%']):
        score -= 20
    
    # Bonuses (Signal)
    if "re:" in subject_lower: # Reply indicates conversation
        score += 30
    if "fwd:" in subject_lower:
        score += 10
    if "verify" in subject_lower or "security" in subject_lower: # Security is high value (even if auto)
        score += 10
    
    # Domain Authority
    domain = extract_domain(sender)
    if domain in ['gmail.com', 'outlook.com', 'icloud.com', 'yahoo.com', 'hotmail.com']:
        # Personal domains are higher probability of human contact (unless spam)
        score += 15
        
    return max(0, min(100, score))

def analyze_dataset(messages, service, label_id):
    print(f"Mining metadata from {len(messages)} messages...")
    
    senders = []
    domains = []
    subjects = []
    value_scores = []
    dates = []
    
    # Batch fetching for speed
    batch = service.new_batch_http_request()
    
    msg_data = []
    
    def callback(request_id, response, exception):
        if exception:
            return
        headers = response.get('payload', {}).get('headers', [])
        sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown")
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "(No Subject)")
        date_str = next((h['value'] for h in headers if h['name'] == 'Date'), "")
        
        msg_data.append({
            'sender': sender,
            'subject': subject,
            'date': date_str
        })

    # Limit to sample size
    # Chunk the requests because Gmail Batch API limit is 100
    CHUNK_SIZE = 50
    chunks = [messages[i:i + CHUNK_SIZE] for i in range(0, min(len(messages), SAMPLE_SIZE), CHUNK_SIZE)]
    
    for chunk in chunks:
        batch = service.new_batch_http_request(callback=callback)
        for msg in chunk:
            batch.add(service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From', 'Subject', 'Date']), callback=callback)
        batch.execute()
    
    # Process Data
    print("Processing Insights...")
    for m in msg_data:
        # Sender/Domain
        email_addr = email.utils.parseaddr(m['sender'])[1]
        domain = extract_domain(email_addr)
        
        senders.append(email_addr)
        domains.append(domain)
        
        # Subject Tokenization (Bigrams for context)
        # Simple cleanup
        clean_subj = re.sub(r'[^a-zA-Z\s]', '', m['subject'].lower())
        words = clean_subj.split()
        if len(words) >= 2:
            for i in range(len(words)-1):
                subjects.append(f"{words[i]} {words[i+1]}")
        
        # Scoring
        value_scores.append(calculate_value_score(m['sender'], m['subject']))

    # --- REPORT GENERATION ---
    print("\n" + "="*60)
    print("🚀 STRATEGIC INBOX INTELLIGENCE REPORT (MACRO LEVEL)")
    print("="*60)
    
    # 1. DOMAIN CLUSTERS (The "Who")
    print(f"\n📊 TOP SENDER DOMAINS (Volume vs. Strategic Presence)")
    domain_counts = Counter(domains).most_common(15)
    for domain, count in domain_counts:
        pct = (count / len(msg_data)) * 100
        print(f"   {pct:4.1f}% | {domain:<30} ({count} msgs)")

    # 2. TOPIC CLUSTERS (The "What" - Top Bigrams)
    print(f"\n🗣️  DOMINANT CONVERSATION CLUSTERS (Recurring Topics)")
    topic_counts = Counter(subjects).most_common(10)
    for topic, count in topic_counts:
        print(f"   - '{topic}' ({count} occurrences)")

    # 3. VALUE DISTRIBUTION (The "Why")
    avg_score = statistics.mean(value_scores)
    print(f"\n💎 STRATEGIC VALUE ANALYSIS")
    print(f"   Average Signal Score: {avg_score:.1f}/100")
    
    high_value_count = sum(1 for s in value_scores if s > 70)
    print(f"   High Value Items (Potential Human/Critical): {high_value_count} ({high_value_count/len(msg_data)*100:.1f}%)")
    print(f"   Low Value Items (Likely Rot/Noise): {sum(1 for s in value_scores if s < 30)} ({sum(1 for s in value_scores if s < 30)/len(msg_data)*100:.1f}%)")

    # 4. RECOMMENDATIONS
    print(f"\n💡 STRATEGIC RECOMMENDATIONS")
    
    # Recommend bulk actions based on top low-value domains
    top_domains = [d[0] for d in domain_counts]
    print("   Immediate Action: Create 'Bulk-Route' rules for high-volume corporate domains:")
    print(f"   -> {', '.join(top_domains[:5])}")

def main():
    service = get_service()
    
    # Find Label ID
    results = service.users().labels().list(userId='me').execute()
    label_id = next((l['id'] for l in results['labels'] if l['name'] == TARGET_LABEL), None)
    
    if not label_id:
        print(f"Label {TARGET_LABEL} not found.")
        return

    # Fetch List
    print(f"Fetching message list for {TARGET_LABEL}...")
    results = service.users().messages().list(userId='me', labelIds=[label_id], maxResults=SAMPLE_SIZE).execute()
    messages = results.get('messages', [])
    
    if not messages:
        print("No messages found.")
        return
        
    analyze_dataset(messages, service, label_id)

if __name__ == '__main__':
    main()
