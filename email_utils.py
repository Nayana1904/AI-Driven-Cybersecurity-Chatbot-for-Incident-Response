import smtplib
from email.message import EmailMessage

def send_alert_email(to_email, subject, message):
        from_email = "nnayana444@gmail.com"
        password = "iexs flmt vrws stiu"  # Use App Password for Gmail

        msg = EmailMessage()
        msg.set_content(message)
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(from_email, password)
                server.send_message(msg)
        except Exception as e:
            print("Email failed:", e)
