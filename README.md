# 🤖 AI-Driven Cybersecurity Chatbot for Incident Response

A smart, interactive web-based chatbot that assists in identifying and responding to cybersecurity incidents using AI, threat intelligence, and real-time tools like VirusTotal.

---

## 🔐 Overview

In the rapidly evolving landscape of cybersecurity threats, timely detection and response are critical. This project presents an AI-powered chatbot that:

- Answers cybersecurity-related queries
- Scans files, URLs, and IPs using VirusTotal API
- Detects suspicious login activities
- Logs chat history and user activities securely

---

## 🚀 Features

- 🧠 AI chatbot powered by OpenAI (or local NLP model)
- 🦠 VirusTotal integration for URL/file/IP scanning
- 📚 MongoDB chat history and user login logging
- 🗣️ Voice-to-text input (Web Speech API)
- ⚠️ IP tracking and suspicious login detection
- 🧾 Export chat history to `.txt`
- 🛡️ Google/Facebook OAuth login
- 💬 Typing indicator and responsive UI

---

## 🧰 Tech Stack

| Layer              | Technology            |
|-------------------|------------------------|
| Backend           | Python (Flask)         |
| AI Integration    | OpenAI API             |
| Threat Analysis   | VirusTotal API         |
| Frontend          | HTML, CSS, JavaScript  |
| Database          | MongoDB (via PyMongo)  |
| Auth              | Flask-Login, OAuthlib  |
| Voice Input       | Web Speech API         |

---

## 📁 Folder Structure

cyber-chatbot/
├── app.py # Main Flask app
├── chatbot.py # AI response logic
├── virustotal.py # VirusTotal scanning functions
├── logger.py # IP & login logger
├── templates/
│ ├── index.html # Frontend dashboard
│ └── login.html
├── static/
│ └── style.css
├── requirements.txt
└── README.md


