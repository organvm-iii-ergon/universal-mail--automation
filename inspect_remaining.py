import gmail_auth

def inspect():
    service = gmail_auth.build_gmail_service()
    
    # Get Label ID for Misc/Other
    results = service.users().labels().list(userId='me').execute()
    label_id = next((l['id'] for l in results['labels'] if l['name'] == 'Misc/Other'), None)
    
    if not label_id:
        print("Label not found")
        return

    # List messages
    results = service.users().messages().list(userId='me', labelIds=[label_id], maxResults=10).execute()
    messages = results.get('messages', [])
    
    print(f"Remaining Items Sample (Total: {results.get('resultSizeEstimate', 'Unknown')}):")
    
    batch = service.new_batch_http_request()
    
    def cb(request_id, response, exception):
        if exception:
            print(f"Error: {exception}")
        else:
            headers = response['payload']['headers']
            subj = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), '(Unknown)')
            print(f"- {sender}: {subj}")

    for m in messages:
        batch.add(service.users().messages().get(userId='me', id=m['id'], format='metadata'), callback=cb)
    
    batch.execute()

if __name__ == "__main__":
    inspect()
