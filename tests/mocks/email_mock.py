# Função mock de envio de email para testes

sent_emails = []

def send_email_mock(to_email: str, subject: str, body: str):
    print(f"[MOCK EMAIL] To: {to_email} | Subject: {subject} | Body: {body}")
    return True

def mock_send_email(to_email, subject, body):
    sent_emails.append({
        "to": to_email,
        "subject": subject,
        "body": body
    })
    return True

def clear_sent_emails():
    sent_emails.clear()
