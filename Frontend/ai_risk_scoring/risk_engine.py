import json
from functools import lru_cache
from pathlib import Path

import joblib

# ATLAS combines explainable email evidence with a model that estimates the
# phishing probability of URLs only. It does not classify complete emails.
MODEL_PATH = Path(__file__).resolve().parent / "url_model.pkl"
FEATURES = [
    "spf_failed", "dkim_failed", "dmarc_failed", "sender_mismatch",
    "suspicious_url", "malicious_ip", "suspicious_domain",
    "attachment_suspicious", "urgent_language", "reply_to_mismatch",
    "new_sender", "url_count",
]
WEIGHTS = {
    "malicious_ip": 25, "suspicious_url": 20, "suspicious_domain": 15,
    "dmarc_failed": 15, "spf_failed": 10, "dkim_failed": 10,
    "sender_mismatch": 10, "attachment_suspicious": 15,
    "reply_to_mismatch": 8, "urgent_language": 5, "new_sender": 3,
}

# When the URL model has actually evaluated a URL, probability is the primary
# signal. This small fixed amount preserves an explainable URL reason without
# substantially counting the same signal twice.
MODEL_BACKED_SUSPICIOUS_URL_WEIGHT = 5
HIGH_CONFIDENCE_URL_THRESHOLD = 0.85
REASONS = {
    "malicious_ip": "Malicious IP detected", "suspicious_url": "Suspicious URL detected",
    "suspicious_domain": "Suspicious domain detected", "dmarc_failed": "DMARC authentication failed",
    "spf_failed": "SPF authentication failed", "dkim_failed": "DKIM authentication failed",
    "sender_mismatch": "Sender identity mismatch", "attachment_suspicious": "Suspicious attachment detected",
    "reply_to_mismatch": "Reply-To address mismatch",
    "urgent_language": "Urgent or social-engineering language detected",
    "new_sender": "Sender is new or previously unseen",
}

COMBINATION_REASONS = {
    "multiple_authentication_failures": "Multiple email authentication failures",
    "authentication_sender_mismatch": "Authentication failure combined with sender mismatch",
    "authentication_suspicious_domain": "Authentication failure combined with suspicious domain",
    "authentication_high_confidence_url": "Authentication failure combined with a high-confidence phishing URL",
}


def normalize_evidence(data):
    """Normalize legacy evidence fields and accept urls: ["https://..."]."""
    result = {}
    for feature in (feature for feature in FEATURES if feature != "url_count"):
        value = data.get(feature, False)
        if isinstance(value, str):
            value = value.lower() in {"true", "yes", "1", "failed", "fail", "malicious", "suspicious"}
        result[feature] = bool(value)

    raw_urls = data.get("urls", [])
    if isinstance(raw_urls, str):
        raw_urls = [raw_urls]
    if not isinstance(raw_urls, (list, tuple)):
        raw_urls = []
    result["urls"] = [url.strip() for url in raw_urls if isinstance(url, str) and url.strip()]
    try:
        supplied_count = max(0, int(data.get("url_count", 0)))
    except (ValueError, TypeError):
        supplied_count = 0
    result["url_count"] = len(result["urls"]) if result["urls"] else supplied_count
    return result


def calculate_evidence_score(features):
    score, reasons = 0, []
    for feature, weight in WEIGHTS.items():
        if features.get(feature, False):
            if feature == "suspicious_url" and features.get("url_model_prediction_available", False):
                weight = MODEL_BACKED_SUSPICIOUS_URL_WEIGHT
            score += weight
            reasons.append({"feature": feature, "reason": REASONS[feature], "points": weight})
    if features.get("url_count", 0) > 1:
        extra_points = min((features["url_count"] - 1) * 2, 8)
        score += extra_points
        reasons.append({"feature": "url_count", "reason": f"{features['url_count']} URLs found", "points": extra_points})

    auth_failure_count = sum(
        bool(features.get(feature, False))
        for feature in ("spf_failed", "dkim_failed", "dmarc_failed")
    )
    if auth_failure_count >= 3:
        score += 10
        reasons.append({
            "feature": "multiple_authentication_failures",
            "reason": COMBINATION_REASONS["multiple_authentication_failures"],
            "points": 10,
        })
    elif auth_failure_count == 2:
        score += 5
        reasons.append({
            "feature": "multiple_authentication_failures",
            "reason": COMBINATION_REASONS["multiple_authentication_failures"],
            "points": 5,
        })

    # These additions represent correlated signals that are materially more
    # concerning together than independently, while retaining explicit reasons.
    if auth_failure_count and features.get("sender_mismatch", False):
        score += 10
        reasons.append({
            "feature": "authentication_sender_mismatch",
            "reason": COMBINATION_REASONS["authentication_sender_mismatch"],
            "points": 10,
        })
    if auth_failure_count and features.get("suspicious_domain", False):
        score += 10
        reasons.append({
            "feature": "authentication_suspicious_domain",
            "reason": COMBINATION_REASONS["authentication_suspicious_domain"],
            "points": 10,
        })
    if auth_failure_count and features.get("url_phishing_probability", 0.0) >= HIGH_CONFIDENCE_URL_THRESHOLD:
        score += 15
        reasons.append({
            "feature": "authentication_high_confidence_url",
            "reason": COMBINATION_REASONS["authentication_high_confidence_url"],
            "points": 15,
        })
    return min(score, 100), reasons


def get_risk_level(score):
    return "LOW" if score <= 24 else "MEDIUM" if score <= 49 else "HIGH" if score <= 74 else "CRITICAL"


def get_recommendation(score):
    if score <= 24:
        return "Allow with normal monitoring."
    if score <= 49:
        return "Review the email before taking action."
    if score <= 74:
        return "Quarantine and investigate the email."
    return "Block or quarantine immediately and investigate."


@lru_cache(maxsize=1)
def load_url_model():
    """Load the trained URL model once; work safely before the first training run."""
    return joblib.load(MODEL_PATH) if MODEL_PATH.is_file() else None


def get_url_phishing_probabilities(urls):
    """Return URL phishing probabilities, never a complete-email prediction."""
    model = load_url_model()
    if not urls or model is None:
        return []
    phishing_index = list(model.classes_).index(1)
    return [float(value) for value in model.predict_proba(urls)[:, phishing_index]]


def analyze_email(evidence):
    features = normalize_evidence(evidence)
    url_probabilities = get_url_phishing_probabilities(features["urls"])
    highest_url_probability = max(url_probabilities, default=0.0)
    features["url_phishing_probability"] = round(highest_url_probability, 4)
    features["url_model_available"] = MODEL_PATH.is_file()
    features["url_model_prediction_available"] = bool(url_probabilities)

    # The trained URL model augments, but does not replace, existing evidence.
    if highest_url_probability >= 0.5:
        features["suspicious_url"] = True
    evidence_score, reasons = calculate_evidence_score(features)
    if url_probabilities:
        reasons.append({
            "feature": "url_phishing_probability",
            "reason": "Highest URL phishing probability from the URL model",
            "points": 0,
        })

    # Hybrid score: explainable email evidence plus highest URL-only probability.
    final_score = round(max(0, min(100, evidence_score * 0.65 + highest_url_probability * 100 * 0.35)))
    return {
        "risk_score": final_score,
        "risk_level": get_risk_level(final_score),
        "ai_threat_probability": round(highest_url_probability, 4),
        "evidence_score": evidence_score,
        "reasons": reasons,
        "recommendation": get_recommendation(final_score),
        "features": features,
    }


if __name__ == "__main__":
    with open(Path(__file__).resolve().parent / "sample_data.json", encoding="utf-8") as file:
        print(json.dumps(analyze_email(json.load(file)), indent=2))
