import imaplib
import email
import time
import os
import threading
import traceback
from datetime import datetime
from email.policy import default

# We import the scoring logic directly from main.py
from api.main import score_email_v1, ScorePayload

def load_env():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    env = {}
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env

class ImapListener(threading.Thread):
    def __init__(self, interval=30):
        super().__init__(daemon=True)
        self.interval = interval
        self.running = False
        
        env = load_env()
        self.imap_server = env.get("IMAP_SERVER")
        self.imap_email = env.get("IMAP_EMAIL")
        self.imap_password = env.get("IMAP_PASSWORD")
        
        # If placeholder values are found, we don't crash, we just pause.
        if not self.imap_password or "your_app_password_here" in self.imap_password:
            self.configured = False
            print("[IMAP] Credentials missing or default. Live email scanning is paused.")
        else:
            self.configured = True

    def run(self):
        self.running = True
        
        while self.running:
            if not self.configured:
                # Re-check env every interval in case the user updated it
                env = load_env()
                self.imap_server = env.get("IMAP_SERVER")
                self.imap_email = env.get("IMAP_EMAIL")
                self.imap_password = env.get("IMAP_PASSWORD")
                if self.imap_password and "your_app_password_here" not in self.imap_password:
                    self.configured = True
                    print(f"[IMAP] Configuration detected! Starting live polling for {self.imap_email}")
                else:
                    time.sleep(self.interval)
                    continue

            try:
                # Connect and login
                mail = imaplib.IMAP4_SSL(self.imap_server)
                mail.login(self.imap_email, self.imap_password)
                mail.select("inbox")
                
                # Search for unread emails
                status, messages = mail.search(None, "UNSEEN")
                if status == "OK":
                    msg_nums = messages[0].split()
                    for num in msg_nums:
                        res, msg_data = mail.fetch(num, "(RFC822)")
                        if res == "OK":
                            raw_email_bytes = msg_data[0][1]
                            raw_email_str = raw_email_bytes.decode('utf-8', errors='replace')
                            
                            print(f"[IMAP] Fetched UNSEEN email id={num.decode()}. Passing to APDS...")
                            
                            # Parse headers minimally just to extract recipient for the payload
                            msg = email.message_from_bytes(raw_email_bytes, policy=default)
                            recipient = msg.get("To", self.imap_email)
                            
                            # Send to Fusion Engine & DB
                            payload = ScorePayload(
                                raw_email=raw_email_str,
                                recipient_group="Default",
                                recipient=recipient
                            )
                            result = score_email_v1(payload)
                            
                            verdict = result.get("fusion_result", {}).get("verdict", "unknown")
                            print(f"[IMAP] Email scored: {verdict.upper()}. Added to alerts database.")
                            
                mail.logout()
            except Exception as e:
                print(f"[IMAP Error] Failed to fetch or process emails: {e}")
                traceback.print_exc()

            time.sleep(self.interval)

def start_imap_listener():
    listener = ImapListener(interval=15)
    listener.start()
    return listener
