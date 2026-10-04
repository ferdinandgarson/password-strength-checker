"""
Task 3 - Phishing Email Detection Model (Scikit-learn)
Run:  python phishing_detector.py                      (uses built-in sample dataset)
      python phishing_detector.py --csv emails.csv     (CSV with columns: text,label ; label = Phishing/Safe)
Then it trains, shows accuracy + confusion matrix, and lets you test your own email.
Real datasets: Kaggle "Phishing Email Dataset" / Enron+Nazario corpora.
"""
import argparse, re, sys
import numpy as np, pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split

PHISH = [
 "URGENT: Your account has been suspended. Verify your password now at http://secure-paypa1-login.xyz/verify",
 "Dear customer, unusual activity detected. Click here immediately to confirm your bank details http://192.168.4.7/bank",
 "Congratulations! You won a $1000 gift card. Claim now: http://bit.ly/claim-prize-now",
 "Your Netflix payment failed. Update your credit card information within 24 hours http://netflix-billing.top/update",
 "Security alert: your Microsoft password expires today. Login here to keep access http://m1crosoft-support.info/login",
 "Final notice: your package could not be delivered. Pay the customs fee http://dhl-track.click/pay",
 "Dear user, your mailbox is full. Click the link to verify your email account or it will be deleted http://mail-verify.work",
 "You have been selected for a free iPhone. Enter your SSN and card number to claim http://free-iphone.win",
 "Your Apple ID was locked. Confirm your identity immediately http://appleid-unlock.cc/confirm",
 "Action required: Tax refund pending. Submit your bank account details here http://irs-refund.online/form",
 "Your account will be closed! Verify now to avoid suspension http://bank-secure.tk/login",
 "Dear beneficiary, you inherited $5,000,000. Send your details and a processing fee to claim",
 "Invoice overdue. Open the attached file and enable macros to view payment details http://invoice-docs.xyz",
 "Unauthorized login attempt. Reset your password immediately http://goog1e-security.top/reset",
 "Limited time offer!!! Click now to claim your reward before it expires http://rewards-win.club",
 "IT Helpdesk: confirm your username and password to avoid account deactivation http://helpdesk-portal.link",
]
SAFE = [
 "Hi team, the meeting is moved to 3 PM tomorrow in the conference room. Please bring the project report.",
 "Thanks for your help with the assignment. I have attached the notes from today's lecture.",
 "Reminder: the lab submission is due Friday. Let me know if you have any questions.",
 "Your order #48213 has shipped and will arrive on Tuesday. Track it from your account page.",
 "Happy birthday! Hope you have a wonderful day. Let's catch up over lunch this weekend.",
 "Please find the minutes of yesterday's meeting attached. Action items are listed at the bottom.",
 "Can you review my pull request when you get a chance? I updated the README and unit tests.",
 "The seminar on machine learning will be held in Hall B at 10 AM. Registration is free.",
 "Hi Mom, I reached the hostel safely. Will call you in the evening after class.",
 "Your monthly statement is ready. Log in through the official app to view it.",
 "Attached is the draft of the internship report. Kindly share your feedback by Monday.",
 "Thank you for attending the workshop. Slides are available on the course portal.",
 "Lunch at 1 PM? The new canteen has opened near the library.",
 "Please submit your timesheet by end of day. Contact HR if you have any issues.",
 "The project demo went really well. Great work everyone, see you at the retrospective.",
 "Your library book is due next week. You can renew it at the front desk.",
]

def url_features(t):
    urls = re.findall(r"https?://\S+", t)
    kw = ["urgent", "verify", "password", "suspend", "click", "immediately", "bank", "ssn", "confirm", "winner", "claim"]
    return [len(urls),
            int(any(re.search(r"https?://\d+\.\d+\.\d+\.\d+", u) for u in urls)),
            int(any(re.search(r"\.(xyz|top|tk|click|win|info|work|cc|link|club|online)\b", u) for u in urls)),
            int(any(re.search(r"bit\.ly|tinyurl", u) for u in urls)),
            sum(k in t.lower() for k in kw),
            t.count("!"),
            sum(c.isupper() for c in t) / max(1, len(t))]

def feats(texts, vec, fit=False):
    X = vec.fit_transform(texts) if fit else vec.transform(texts)
    return hstack([X, csr_matrix(np.array([url_features(t) for t in texts]))]).tocsr()

def load(csv):
    if csv:
        df = pd.read_csv(csv)
        cols = {c.lower().strip(): c for c in df.columns}
        # auto-detect text column(s) and label column (works with most Kaggle phishing datasets)
        text_cols = [cols[k] for k in ("subject", "body", "text", "email text", "email_text", "message") if k in cols]
        label_col = next((cols[k] for k in ("label", "email type", "email_type", "class", "type", "target") if k in cols), None)
        if not text_cols or label_col is None:
            sys.exit(f"Could not find text/label columns. Columns found: {list(df.columns)}")
        df = df.dropna(subset=[label_col]).copy()
        df["_text"] = df[text_cols].fillna("").astype(str).agg(" ".join, axis=1)
        def to_bin(v):
            v = str(v).strip().lower()
            return 1 if ("phish" in v or "spam" in v or v in ("1", "1.0")) else 0
        y = df[label_col].map(to_bin).tolist()
        print(f"Loaded {len(df)} emails from {csv} (text={text_cols}, label='{label_col}')")
        if len(set(y)) < 2: sys.exit("Only one class found - check the label column.")
        return df["_text"].tolist(), y
    return PHISH + SAFE, [1] * len(PHISH) + [0] * len(SAFE)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--csv"); ap.add_argument("--no-input", action="store_true")
    a = ap.parse_args()
    texts, y = load(a.csv)
    Xtr, Xte, ytr, yte = train_test_split(texts, y, test_size=0.3, random_state=42, stratify=y)
    vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), lowercase=True, max_features=50000)
    model = LogisticRegression(max_iter=1000, C=5)
    model.fit(feats(Xtr, vec, fit=True), ytr)
    pred = model.predict(feats(Xte, vec))
    print(f"Dataset size: {len(texts)}  (train {len(Xtr)}, test {len(Xte)})")
    print(f"\nAccuracy: {accuracy_score(yte, pred) * 100:.2f}%")
    print("\nConfusion Matrix (rows=actual, cols=predicted)\n            Safe  Phishing")
    cm = confusion_matrix(yte, pred, labels=[0, 1])
    print(f"Safe        {cm[0][0]:>4}  {cm[0][1]:>8}\nPhishing    {cm[1][0]:>4}  {cm[1][1]:>8}")
    print("\n", classification_report(yte, pred, target_names=["Safe", "Phishing"], zero_division=0))
    samples = ["Your account is suspended! Verify your password now http://secure-bank-login.xyz",
               "Hi, attaching the notes from today's class. See you tomorrow."]
    for s in samples:
        p = model.predict(feats([s], vec))[0]; pr = model.predict_proba(feats([s], vec))[0][1]
        print(f'"{s[:60]}..." -> {"Phishing" if p else "Safe"} ({pr:.0%} phishing)')
    if not a.no_input and sys.stdin.isatty():
        while True:
            s = input("\nPaste an email (blank to quit): ").strip()
            if not s: break
            p = model.predict_proba(feats([s], vec))[0][1]
            print("->", "Phishing" if p > .5 else "Safe", f"({p:.0%} phishing)")

if __name__ == "__main__":
    main()