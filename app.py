import os
import json

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

app = Flask(__name__)
CORS(app)

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    message = data.get("message", "").strip()
    language = data.get("language", "").strip()

    if not message:
        return jsonify({
            "error": "No message was provided."
        }), 400

    if language:
        translation_instruction = f"""
The user selected {language} as their secondary language.

For every English text field, also provide a natural and easy-to-understand
{language} translation.

Use simple language suitable for an elderly person.

Return ONLY valid JSON in exactly this format:

{{
    "danger_level": "High, Medium, Low, or Unclear",
    "danger_level_translation": "Translated danger level",
    "scam_type": "Short English scam type",
    "scam_type_translation": "Translated scam type",
    "explanation": "Simple English explanation",
    "explanation_translation": "Translated explanation",
    "action": "Safest action in English",
    "action_translation": "Translated action",
    "warning_signs": ["English warning sign"],
    "warning_signs_translations": ["Translated warning sign"]
}}
"""
    else:
        translation_instruction = """
The user selected English only.

Return ONLY valid JSON in exactly this format:

{
    "danger_level": "High, Medium, Low, or Unclear",
    "scam_type": "Short English scam type",
    "explanation": "Simple English explanation",
    "action": "Safest action in English",
    "warning_signs": ["English warning sign"]
}
"""

    prompt = f"""
Analyze the following message for signs of a scam.

Explain the result simply enough for an elderly person to understand.

Do not claim certainty when the evidence is unclear.

{translation_instruction}

MESSAGE:
{message}
"""

    response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents=prompt,
    config=types.GenerateContentConfig(
        response_mime_type="application/json"
    )
)

    analysis = json.loads(response.text)

    return jsonify(analysis)

@app.route("/scan-image", methods=["POST"])
def scan_image():
    if "image" not in request.files:
        return jsonify({
            "error": "No image was uploaded."
        }), 400

    image = request.files["image"]

    if image.filename == "":
        return jsonify({
            "error": "No image was selected."
        }), 400

    image_bytes = image.read()

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=[
            types.Part.from_bytes(
                data=image_bytes,
                mime_type=image.mimetype
            ),
            """
Extract only the message text visible in this image.

Ignore app buttons, timestamps, notification icons, status bars,
profile names, and other interface elements unless they are clearly
part of the message itself.

Preserve the original language and wording.

Return only the extracted message text.
Do not explain anything.
"""
        ]
    )

    extracted_text = response.text.strip()

    if not extracted_text:
        return jsonify({
            "error": "No readable message text was found."
        }), 400

    return jsonify({
        "extracted_text": extracted_text
    })

if __name__ == "__main__":
    app.run(debug=True)
