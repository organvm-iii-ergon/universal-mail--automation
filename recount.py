import gmail_auth

def recount():
    service = gmail_auth.build_gmail_service()
    results = service.users().labels().list(userId='me').execute()
    labels = results.get('labels', [])
    
    print(f"\n{'LABEL':<40} | {'MESSAGES':>10}")
    print("-" * 55)
    
    # Filter for our taxonomy
    relevant_labels = [l for l in labels if l['type'] == 'user' or l['id'] in ['INBOX', 'TRASH', 'UNREAD']]
    
    # Fetch details for relevant labels
    detailed_labels = []
    print("Fetching label statistics...")
    
    # Batch request for speed
    batch = service.new_batch_http_request()
    
    def cb(request_id, response, exception):
        if not exception:
            detailed_labels.append(response)

    for l in relevant_labels:
        batch.add(service.users().labels().get(userId='me', id=l['id']), callback=cb)
    
    batch.execute()
    
    sorted_labels = sorted(detailed_labels, key=lambda x: x.get('messagesTotal', 0), reverse=True)
    
    total_archived = 0
    
    for l in sorted_labels:
        # Skip chat/system noise unless useful
        if l['name'].startswith('Category/'): continue 
        
        count = l.get('messagesTotal', 0)
        print(f"{l['name']:<40} | {count:>10,}")
        
        if l['name'] != 'INBOX' and l['name'] != 'TRASH':
            total_archived += count

    print("-" * 55)
    print(f"{'TOTAL ORGANIZED ARCHIVE':<40} | {total_archived:>10,}")

if __name__ == "__main__":
    recount()
