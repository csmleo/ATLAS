from flask import Flask, request, jsonify
from email_parser import analyze_eml
from risk_engine import analyze_email

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "module": "AI Risk Scoring"
    })


@app.route("/risk-score", methods=["POST"])
def risk_score():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No email security data provided"
        }), 400

    try:

        result = analyze_email(data)

        return jsonify(result)

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


@app.route("/analyze-email", methods=["POST"])
def analyze_email_file():
    """Analyze an uploaded RFC 5322 .eml email without changing JSON endpoints."""
    uploaded_file = request.files.get("file")
    if uploaded_file is None or not uploaded_file.filename:
        return jsonify({"error": "No .eml file uploaded"}), 400
    if not uploaded_file.filename.lower().endswith(".eml"):
        return jsonify({"error": "Uploaded file must have a .eml extension"}), 400
    try:
        return jsonify(analyze_eml(uploaded_file.read()))
    except Exception as error:
        return jsonify({"error": str(error)}), 500


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
