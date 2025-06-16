from flask import Flask, render_template, request, redirect, session, jsonify
from email_utils import send_alert_email
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from chatbot import get_bot_reply
from virustotal import scan_file_virustotal, scan_url_virustotal

app = Flask(__name__)
app.secret_key = '89b9acf55b65487b4731abe24506f437'

# Store hashed password
users = {
    "nayana": generate_password_hash("nayana@123")
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip = request.remote_addr
        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if username not in users or not check_password_hash(users[username], password):
            subject = "\u26a0\ufe0f Failed Login Attempt"
            message = f"""
            Failed login attempt detected:
            - Username: {username}
            - IP Address: {ip}
            - Time: {time}
            """
            send_alert_email("your_email@gmail.com", subject, message)
            return "Login failed. Alert sent."

        session['user'] = username
        return redirect('/dashboard')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    return redirect('/login')

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message', '')
    reply = get_bot_reply(user_message)
    return jsonify({'reply': reply})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/scan_file', methods=['POST'])
def scan_file():
    file = request.files['file']
    result = scan_file_virustotal(file)
    return f"<h2>Scan Result</h2><pre>{result}</pre><a href='/dashboard'>Back</a>"

@app.route('/scan_url', methods=['POST'])
def scan_url():
    url = request.form['url']
    result = scan_url_virustotal(url)
    return f"<h2>Scan Result</h2><pre>{result}</pre><a href='/dashboard'>Back</a>"

if __name__ == "__main__":
    app.run(debug=True)
