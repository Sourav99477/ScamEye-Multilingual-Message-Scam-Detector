# ScamEye – Multilingual Scam Message Detector

ScamEye is a web application that detects potential scam and phishing messages using Google Gemini.

It can analyze text messages and screenshots and provides a risk level, scam category, warning signs, and safety recommendations.

## Features

- Scam detection for text messages
- Screenshot-based message analysis
- Multilingual analysis and translations
- Scam category detection
- Risk level classification
- Detection of common scam signals such as:
  - OTP and password requests
  - Payment requests
  - Suspicious links
  - Urgent threats
  - Prize and lottery scams
  - Impersonation attempts
- Explanation of why a message was flagged
- Responsive web interface

## How It Works

User Message / Screenshot
        ↓
Input Processing
        ↓
Rule-Based Scam Signals
        ↓
Gemini AI Analysis
        ↓
Risk Assessment
        ↓
Warning Signs + Explanation
        ↓
Safety Recommendation

ScamEye combines rule-based checks with Gemini's contextual analysis instead of relying only on a single AI response.

## Tech Stack

- Python
- Flask
- Google Gemini API
- HTML
- CSS
- JavaScript

## Run Locally

Install the required packages:

pip install -r requirements.txt

Create a .env file and add your Gemini API key:

GEMINI_API_KEY=your_api_key
GEMINI_MODEL=gemini-3.1-flash-lite

Run the application:

python app.py

Open the application at:

http://localhost:5000

## Project Structure

ScamEye/
├── app.py
├── requirements.txt
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── script.js

## Limitations

ScamEye is a safety-assistance tool and does not guarantee that a message is safe or fraudulent. Important requests should always be verified through official channels.

## Future Improvements

- Database for scan history
- User authentication
- Evaluation using a labeled scam-message dataset
- ML-based classification
- URL and domain reputation checks
- Analytics dashboard