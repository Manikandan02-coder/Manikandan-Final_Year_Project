import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Ensure log directory exists
log_dir = r"C:\Users\mages\Downloads\Periscope-main\Periscope-main\Network Traffic Classifier\data3"
os.makedirs(log_dir, exist_ok=True)

# Configure logging
logging.basicConfig(
    filename=os.path.join(log_dir, "alert.log"),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def send_email(subject, body):
    sender_email = 'psrn2005@gmail.com'
    receiver_email = 'm54321mnw@gmail.com'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'psrn2005@gmail.com'
    smtp_password = 'wzfl vzsw vipb jboi'  # App Password

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
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

def main():
    logging.error("Alert! An Attack has been detected.")

    subject = "Alert: Attack Detected"
    body = "The Network Traffic Classifier System has detected an Attack. Please check."
    send_email(subject, body)  # ← was commented out, now fixed

if __name__ == "__main__":
    main()