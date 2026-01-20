"""
Inbox Health Check
Purpose: Deep dive into the metadata that matters: Storage, Unread Counts per Category, and Spam volume.
"""

import gmail_auth

def check_health():
    service = gmail_auth.build_gmail_service()
    
    # 1. Profile & Storage
    profile = service.users().getProfile(userId='me').execute()
    total_msgs = profile['messagesTotal']
    
    # 2. Label Details (Unread Counts)
    results = service.users().labels().list(userId='me').execute()
    labels = results.get('labels', [])
    
    print("\n🏥 INBOX HEALTH REPORT")
    print("=" * 40)
    print(f"📧 Total Email Count: {total_msgs:,}")
    print(f"📨 Email Address: {profile['emailAddress']}")
    # Note: quotas are often in History/Profile but simple API gives total messages. 
    # Real storage quota is via specific other calls or inferred.
    
    print("\n🔴 UNREAD LOAD (Visual Stress)")
    print("-" * 40)
    
    batch = service.new_batch_http_request()
    label_stats = {}
    
    def cb(id, resp, exc):
        if not exc:
            label_stats[resp['name']] = resp
            
    for l in labels:
        if l['type'] == 'user' or l['id'] in ['INBOX', 'SPAM', 'TRASH', 'UNREAD']:
            batch.add(service.users().labels().get(userId='me', id=l['id']), callback=cb)
            
    batch.execute()
    
    # Sort by Unread
    sorted_unread = sorted(label_stats.values(), key=lambda x: x.get('messagesUnread', 0), reverse=True)
    
    for l in sorted_unread:
        unread = l.get('messagesUnread', 0)
        if unread > 0:
            print(f"{l['name']:<30} : {unread:>6,} unread")

    print("\n💡 RECOMMENDATIONS")
    print("=" * 40)
    
    unread_notifications = label_stats.get('Notification', {}).get('messagesUnread', 0)
    unread_marketing = label_stats.get('Marketing', {}).get('messagesUnread', 0)
    
    if unread_notifications > 1000 or unread_marketing > 1000:
        print(f"⚠️  You have {unread_notifications + unread_marketing:,} unread alerts/promos.")
        print("   Action: Run 'mark_rot_read.py' to clear red badges on low-value folders.")

if __name__ == "__main__":
    check_health()
