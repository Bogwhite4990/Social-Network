from flask import Flask
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'cloneinstaclone@gmail.com'
app.config['MAIL_PASSWORD'] = 'Test123Test!'

mail = Mail(app)

@app.route('/send_email')
def send_email():
    msg = Message('Test Email', recipients=['dontkill143@gmail.com'])
    msg.body = 'This is a test email.'
    mail.send(msg)
    return 'Email sent'

if __name__ == '__main__':
    app.run(debug=True)
