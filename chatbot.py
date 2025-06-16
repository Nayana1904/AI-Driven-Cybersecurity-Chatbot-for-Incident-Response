def get_bot_reply(message):
    message_lower = message.lower()
    general_responses = {
        "hi": "Hello! How can I assist you today?",
        "hello": "Hi there! What can I help you with?",
        "hey": "Hey! Need help with something?",
        "thank you": "You're welcome! Stay safe online.",
        "thanks": "No problem! Let me know if you have more questions.",
        "bye": "Goodbye! Have a secure day.",
        "good morning": "Good morning! How can I help you?",
        "good evening": "Good evening! Need any cybersecurity advice?",
        "good night": "Good night! Don't forget to lock your digital doors 😊.",
        "what is your name":"I am a securi_chatbot",
         "what is virustotal":"VirusTotal is a free online service that analyzes files and URLs for viruses, worms, trojans, and other malicious content.",
        "how to scan a file": "You can upload your file on VirusTotal or use our chatbot to scan it.",
        "how long does scanning take": "Scanning usually takes a few seconds, but retrieving detailed reports may take longer.",
        "what is a false positive": "When a security tool flags a safe file or URL as malicious by mistake.",
        "how to reset my password": "Usually, you can reset your password by clicking 'Forgot Password' on the login page and following the instructions sent to your email.",
        "what is wifi": "Wi-Fi is a technology that allows devices to connect to the internet wirelessly within a certain range.",
        "how does the internet work": "The internet is a global network of computers that communicate via protocols like TCP/IP to share data.",
        "what is a browser": "A browser is a software application like Chrome or Firefox used to access websites on the internet.",
        "how to improve computer speed": "Try closing unnecessary programs, deleting temporary files, and restarting your computer regularly.",
        "what is cloud computing": "Cloud computing allows you to use computing resources like storage and servers over the internet instead of locally.",
        "how to protect privacy online": "Use strong passwords, enable two-factor authentication, and be cautious about sharing personal info.",
        "what is artificial intelligence": "AI is a field of computer science that enables machines to mimic human intelligence and learn from data.",
        "can you tell me a joke": "Why do programmers prefer dark mode? Because light attracts bugs!",
        "what is cybersecurity": "Cybersecurity means protecting computers and networks from digital attacks or unauthorized access.",
        "how to stay safe on social media": "Don't share sensitive info publicly, adjust privacy settings, and be wary of suspicious links or messages.",
        "what is malware": "Malware is malicious software designed to harm or exploit computers and networks.",
        "how to backup data": "Regularly save copies of important files to external drives or cloud storage to prevent data loss.",
        "what is encryption": "Encryption scrambles data so only authorized parties with a key can read it.",
        "how to spot fake news": "Check the source, look for supporting evidence, and be cautious of sensational headlines.",
        "what is two-factor authentication": "It's an extra security step requiring two forms of ID before you can log in.",
        "how to delete browser history": "Usually, you can delete it from the settings or preferences menu in your web browser.",
        "what is a VPN": "A VPN encrypts your internet connection and hides your IP to protect privacy online.",
        "how to stay productive wrking from home": "Set a routine, create a dedicated workspace, and minimize distractions.",
        "how to learn programming": "Start with beginner-friendly languages like Python, practice regularly, and use online resources or courses.",

    }

    # Cybersecurity knowledge base
    knowledge_base = {
        "phishing": {
            "definition": "Phishing is a deceptive attempt to obtain sensitive information by disguising as a trustworthy entity.",
            "advice": "Phishing attacks often involve fake emails or messages that trick users into revealing credentials or clicking malicious links.",
            "mitigation": "Do not click on suspicious links. Verify sender addresses, use spam filters, and report phishing attempts."
        },
        "malware": {
            "definition": "Malware is malicious software designed to disrupt, damage, or gain unauthorized access to systems.",
            "advice": "Malware spreads via infected downloads, email attachments, or compromised websites.",
            "mitigation": "Use antivirus software, update regularly, scan suspicious files, and avoid untrusted sources."
        },
        "ransomware": {
            "definition": "Ransomware is malware that encrypts files and demands payment to restore access.",
            "advice": "Ransomware typically spreads through email attachments or unsafe downloads.",
            "mitigation": "Disconnect from the network, avoid paying the ransom, and restore from backups if available."
        },
        "spyware": {
            "definition": "Spyware is software that secretly monitors and collects user activity and data.",
            "advice": "It may log keystrokes, track browsing, and send data to third parties.",
            "mitigation": "Use antispyware tools, check app permissions, and avoid suspicious software installations."
        },

        "brute force": {
            "definition": "A brute force attack is a trial-and-error method used to decode encrypted data such as passwords.",
            "advice": "It works by systematically trying all possible combinations until the correct one is found.",
            "mitigation": "Use strong passwords, limit login attempts, and enable CAPTCHA or MFA."
        },


        "firewall": {
            "definition": "A firewall is a security system that controls incoming and outgoing network traffic based on rules.",
            "explanation": "It blocks unauthorized access while permitting legitimate communication.",
            "advice": "Enable firewalls on all devices and regularly update firewall rules."
        },
        "ddos attack": {
            "definition": "Distributed Denial of Service attack overwhelms a network or server with excessive traffic.",
            "explanation": "Multiple compromised systems flood the target to make it inaccessible.",
            "advice": "Use traffic filtering, rate limiting, and have an incident response plan."
        },
        "zero-day": {
            "definition": "A zero-day vulnerability is a security flaw unknown to software vendors.",
            "explanation": "Attackers exploit these before patches are released.",
            "advice": "Keep software updated and use intrusion detection systems."
        },
        "two-factor authentication": {
            "definition": "2FA requires two forms of identity verification to increase account security.",
            "explanation": "Usually combines password plus a temporary code from phone or app.",
            "advice": "Enable 2FA wherever possible."
        },
        "botnet": {
            "definition": "A botnet is a network of infected devices controlled by attackers.",
            "explanation": "Used for spam, DDoS, or stealing data.",
            "advice": "Use antivirus and avoid suspicious downloads."
        },
        "social engineering": {
            "definition": "Manipulating people to divulge confidential info.",
            "explanation": "Attackers pretend to be trustworthy contacts or officials.",
            "advice": "Verify requests and never share passwords."
        },
        "encryption": {
            "definition": "Converting data into unreadable form to protect confidentiality.",
            "explanation": "Only those with the key can read the data.",
            "advice": "Use strong encryption for sensitive data."
        },
        "vpn": {
            "definition": "VPN creates a secure, encrypted tunnel for internet traffic.",
            "explanation": "Masks your IP and encrypts data to enhance privacy.",
            "advice": "Use VPN on public Wi-Fi and for privacy."
        },
        "sql injection": {
            "definition": "An attack inserting malicious SQL queries via input fields.",
            "explanation": "Allows attackers to access or modify database data.",
            "advice": "Sanitize inputs and use parameterized queries."
        }
    }
# General small talk detection
    for phrase in general_responses:
        if phrase in message:
            return {"response": general_responses[phrase]}

    # Cybersecurity keyword detection
    for keyword, content in knowledge_base.items():
        if keyword in message:
            if any(q in message for q in ["what is", "define", "definition", "explain"]):
                return {"response": content["definition"]}
            elif any(q in message for q in ["how", "why", "explanation"]):
                return {"response": content["advice"]}
            elif any(q in message for q in ["what to do", "how to", "prevent", "mitigation", "steps", "action"]):
                return {"response": content["mitigation"]}
            else:
                return {
                    "definition": content["definition"],
                    "advice": content["advice"],
                    "mitigation": content["mitigation"]
                }

    # Default fallback
    return {
        "response": "I'm here to help with cybersecurity and general questions. Try asking things like:\n- What is malware?\n- How does phishing work?\n- What to do if ransomware hits?\nOr just say hi!"
    }

