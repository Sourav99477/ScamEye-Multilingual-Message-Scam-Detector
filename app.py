import json
import os
import re
from typing import Any

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from google import genai
from google.genai import types

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 MB request limit

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
MAX_MESSAGE_LENGTH = 8000
MAX_IMAGE_BYTES = 6 * 1024 * 1024

if GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)
else:
    client = None

ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}

# These signals are intentionally transparent and conservative. They are not a
# replacement for the AI analysis; they provide deterministic evidence that can
# be explained to an interviewer and used when the model is uncertain.
SCAM_RULES = [
    (
        "Urgency or pressure",
        re.compile(
            r"\b(urgent|immediately|act now|within \d+ (?:minutes?|hours?)|expires? today|last warning|final notice|right now)\b",
            re.I,
        ),
        15,
    ),
    (
        "Credential or OTP request",
        re.compile(
            r"\b(otp|one[- ]time password|password|pin|cvv|verification code|security code|login details|passcode)\b",
            re.I,
        ),
        25,
    ),
    (
        "Payment or money request",
        re.compile(
            r"\b(pay|payment|transfer|send money|refund fee|processing fee|upi|bank transfer|wire|gift card|crypto(?:currency)?|deposit)\b",
            re.I,
        ),
        20,
    ),
    (
        "Threat of account or service loss",
        re.compile(
            r"\b(account|card|wallet|sim|service|subscription).{0,60}\b(blocked|suspended|closed|deactivated|terminated|locked)\b",
            re.I,
        ),
        15,
    ),
    (
        "Prize or unexpected reward",
        re.compile(
            r"\b(congratulations|you(?:'|’)ve won|winner|prize|lottery|cash reward|lucky draw|claim your reward|free gift)\b",
            re.I,
        ),
        18,
    ),
    (
        "Sensitive personal information request",
        re.compile(
            r"\b(aadhaar|pan card|social security|date of birth|dob|mother'?s maiden name|full card number|bank details|account number)\b",
            re.I,
        ),
        22,
    ),
    (
        "Suspicious link",
        re.compile(
            r"(?:https?://|www\.)\S+|\b(?:bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly)/\S*",
            re.I,
        ),
        18,
    ),
    (
        "Impersonation language",
        re.compile(
            r"\b(bank|rbi|government|income tax|police|customs|courier|delivery|amazon|flipkart|google|microsoft|support|customer care|hr|recruiter)\b",
            re.I,
        ),
        8,
    ),
]


def get_rule_signals(message: str) -> tuple[list[str], int]:
    """Return human-readable deterministic signals and a capped heuristic score."""
    signals: list[str] = []
    score = 0

    for label, pattern, weight in SCAM_RULES:
        if pattern.search(message):
            signals.append(label)
            score += weight

    # Multiple URLs are an additional signal, but do not let this dominate.
    urls = re.findall(r"https?://\S+|www\.\S+", message, flags=re.I)
    if len(urls) >= 2:
        signals.append("Multiple links in one message")
        score += 8

    return signals, min(score, 100)


def risk_from_scores(ai_level: str, rule_score: int) -> str:
    """Combine the model's semantic assessment with deterministic rule evidence."""
    level = ai_level.strip().title()

    # Strong rule evidence should not be ignored, but rules alone should not
    # automatically label a message as a scam.
    if rule_score >= 65:
        return "High"
    if rule_score >= 40 and level in {"High", "Medium"}:
        return "High"
    if rule_score >= 25 and level == "High":
        return "High"
    if level in {"High", "Medium"}:
        return level
    if rule_score >= 25:
        return "Medium"
    if level == "Low":
        return "Low"
    return "Unclear"


def clean_json_response(text: str) -> dict[str, Any]:
    """Parse model JSON while tolerating accidental markdown fences."""
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.I)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    data = json.loads(cleaned)
    if not isinstance(data, dict):
        raise ValueError("Model response was not a JSON object.")
    return data


def require_client():
    if client is None:
        raise RuntimeError("GEMINI_API_KEY is not configured.")


def build_analysis_prompt(message: str, language: str, rule_signals: list[str]) -> str:
    translation = (
        f"Also provide natural, simple translations for every user-facing text field in {language}."
        if language
        else "Do not include translations."
    )

    return f"""
You are the analysis engine for ScamEye, a consumer safety tool that reviews suspicious messages.

Analyze the message for evidence of phishing, fraud, impersonation, payment scams, credential theft,
job scams, delivery scams, prize scams, account takeover attempts, or other social-engineering patterns.

Important rules:
- Do not assume a message is a scam just because it contains a link, urgency, a company name, or a payment reference.
- Distinguish suspicious signals from proof of fraud.
- If the evidence is insufficient, use "Unclear".
- Never tell the user to click a link, call a phone number in the message, or send money.
- Keep explanations short and understandable to a non-technical user.
- The deterministic scanner found these signals (they may be false positives): {json.dumps(rule_signals)}
- {translation}

Return ONLY valid JSON with exactly these keys:
{{
  "danger_level": "High | Medium | Low | Unclear",
  "scam_type": "short category or Not enough evidence",
  "explanation": "2-4 sentence explanation",
  "action": "safest next step",
  "warning_signs": ["short sign", "short sign"],
  "is_scam": true,
  "confidence": "High | Medium | Low"
}}

If translations were requested, additionally include:
"danger_level_translation", "scam_type_translation", "explanation_translation",
"action_translation", and "warning_signs_translations".

MESSAGE:
{message}
"""


def normalize_analysis(data: dict[str, Any], rule_signals: list[str], rule_score: int) -> dict[str, Any]:
    danger = str(data.get("danger_level", "Unclear")).title()
    if danger not in {"High", "Medium", "Low", "Unclear"}:
        danger = "Unclear"

    final_level = risk_from_scores(danger, rule_score)
    warning_signs = data.get("warning_signs", [])
    if not isinstance(warning_signs, list):
        warning_signs = []

    # Keep the response bounded so a model cannot produce a huge UI payload.
    warning_signs = [str(item).strip() for item in warning_signs if str(item).strip()][:6]

    combined_signals = list(dict.fromkeys(rule_signals + warning_signs))[:8]

    result: dict[str, Any] = {
        "danger_level": final_level,
        "scam_type": str(data.get("scam_type", "Unclear"))[:180],
        "explanation": str(data.get("explanation", "The message could not be assessed clearly."))[:1200],
        "action": str(data.get("action", "Do not share sensitive information. Verify independently using an official source."))[:600],
        "warning_signs": combined_signals,
        "is_scam": final_level == "High",
        "confidence": str(data.get("confidence", "Low")).title(),
        "rule_score": rule_score,
    }

    if result["confidence"] not in {"High", "Medium", "Low"}:
        result["confidence"] = "Low"

    translation_keys = [
        "danger_level_translation",
        "scam_type_translation",
        "explanation_translation",
        "action_translation",
        "warning_signs_translations",
    ]
    for key in translation_keys:
        if key in data:
            result[key] = data[key]

    return result


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "The uploaded file is too large. Maximum request size is 8 MB."}), 413


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_configured": client is not None})


@app.route("/analyze", methods=["POST"])
def analyze():
    if not request.is_json:
        return jsonify({"error": "Request must contain JSON."}), 415

    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    language = str(data.get("language", "")).strip()

    if not message:
        return jsonify({"error": "Please enter a message to analyze."}), 400
    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": f"Message is too long. Maximum length is {MAX_MESSAGE_LENGTH} characters."}), 400

    if language not in {"", "Hindi", "Malayalam", "Tamil"}:
        return jsonify({"error": "Unsupported translation language."}), 400

    rule_signals, rule_score = get_rule_signals(message)

    try:
        require_client()
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=build_analysis_prompt(message, language, rule_signals),
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.1,
            ),
        )
        analysis = clean_json_response(response.text)
        return jsonify(normalize_analysis(analysis, rule_signals, rule_score))

    except json.JSONDecodeError:
        app.logger.exception("Gemini returned invalid JSON")
        return jsonify({"error": "The analysis service returned an invalid result. Please try again."}), 502
    except Exception:
        app.logger.exception("Message analysis failed")
        return jsonify({"error": "The analysis service is temporarily unavailable. Please try again."}), 502


@app.route("/scan-image", methods=["POST"])
def scan_image():
    if "image" not in request.files:
        return jsonify({"error": "No image was uploaded."}), 400

    image = request.files["image"]
    if not image.filename:
        return jsonify({"error": "No image was selected."}), 400

    if image.mimetype not in ALLOWED_IMAGE_TYPES:
        return jsonify({"error": "Please upload a JPG, PNG, or WebP image."}), 415

    image_bytes = image.read(MAX_IMAGE_BYTES + 1)
    if len(image_bytes) > MAX_IMAGE_BYTES:
        return jsonify({"error": "Image is too large. Maximum image size is 6 MB."}), 413

    try:
        require_client()
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=[
                types.Part.from_bytes(data=image_bytes, mime_type=image.mimetype),
                """
Extract only the message text visible in this screenshot.

Ignore app buttons, timestamps, notification icons, status bars, profile names,
and other interface elements unless they are clearly part of the message itself.
Preserve the original language and wording as closely as possible.
If no message text is readable, return exactly: NO_TEXT_FOUND
Return only the extracted message text.
""",
            ],
            config=types.GenerateContentConfig(temperature=0),
        )

        extracted_text = response.text.strip()
        if not extracted_text or extracted_text == "NO_TEXT_FOUND":
            return jsonify({"error": "No readable message text was found in the image."}), 400

        return jsonify({"extracted_text": extracted_text[:MAX_MESSAGE_LENGTH]})

    except Exception:
        app.logger.exception("Image scan failed")
        return jsonify({"error": "The image scanning service is temporarily unavailable."}), 502


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=debug)
