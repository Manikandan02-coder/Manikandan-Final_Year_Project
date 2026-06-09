import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Path config: works on both Windows and Linux/Docker ───────────────────────
if os.name == 'nt':  # Windows
    LOG_DIR = r"C:\Users\mages\Downloads\Periscope-main\Periscope-main\Network Traffic Classifier\data3"
else:                # Linux / Docker
    LOG_DIR = "/app/data3"

os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "alert.log")
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def send_email(subject, body):
    sender_email   = 'psrn2005@gmail.com'
    receiver_email = 'm54321mnw@gmail.com'
    smtp_server    = 'smtp.gmail.com'
    smtp_port      = 587
    smtp_username  = 'psrn2005@gmail.com'
    smtp_password  = 'zyxt ooyj uajt mxwa'  # App Password

    msg = MIMEMultipart()
    msg['From']    = sender_email
    msg['To']      = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            logging.info("Alert email sent successfully.")
            print("Email sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        print(f"Email sending failed: {e}")


def mainalert(anomalies, threshold, uc):
    if anomalies > threshold:
        alert_message = f"ALERT: Number of anomalies ({anomalies}) exceeds 25% of unique connections ({uc})."
        logging.error(alert_message)
        print(alert_message)

        subject = "Alert !! An Intrusion is detected"
        body    = f"ALERT: Number of anomalies ({anomalies}) exceeds 25% of unique connections ({uc}). Please check."
        send_email(subject, body)  # ← was missing, email never sent

    else:
        logging.info("No anomalies detected. System normal.")
        print("No alert triggered.")