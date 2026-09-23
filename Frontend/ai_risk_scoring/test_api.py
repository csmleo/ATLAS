"""End-to-end Flask API validation for the ATLAS AI + Risk Scoring module."""

import unittest
from pathlib import Path

from api import app


REQUIRED_FIELDS = {
    "risk_score",
    "risk_level",
    "ai_threat_probability",
    "evidence_score",
    "reasons",
    "recommendation",
    "features",
}


CASES = {
    "clean_email": {
        "spf_failed": False,
        "dkim_failed": False,
        "dmarc_failed": False,
        "sender_mismatch": False,
        "suspicious_url": False,
        "malicious_ip": False,
        "suspicious_domain": False,
        "attachment_suspicious": False,
        "urgent_language": False,
        "reply_to_mismatch": False,
        "new_sender": False,
        "urls": [],
    },
    "suspicious_url_email": {
        "spf_failed": False,
        "dkim_failed": False,
        "dmarc_failed": False,
        "sender_mismatch": False,
        "attachment_suspicious": False,
        "urgent_language": False,
        "new_sender": False,
        # A URL labeled as phishing in the public UCI PhiUSIIL data.
        "urls": ["https://www.o-i.ch"],
    },
    "authentication_failure": {
        "spf_failed": True,
        "dkim_failed": True,
        "dmarc_failed": True,
        "sender_mismatch": False,
        "suspicious_url": False,
        "attachment_suspicious": False,
        "urgent_language": False,
        "new_sender": False,
        "urls": [],
    },
    "multiple_risk_email": {
        "spf_failed": True,
        "dkim_failed": True,
        "dmarc_failed": True,
        "sender_mismatch": True,
        "suspicious_domain": True,
        "suspicious_url": True,
        "urgent_language": True,
        "new_sender": True,
        "attachment_suspicious": False,
        "urls": ["https://www.o-i.ch"],
    },
}


class AtlasApiEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def post_case(self, payload):
        response = self.client.post("/risk-score", json=payload)
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(set(result), REQUIRED_FIELDS)
        return result

    def test_end_to_end_cases(self):
        results = {name: self.post_case(payload) for name, payload in CASES.items()}
        # A. Clean email
        self.assertLessEqual(results["clean_email"]["risk_score"], 24)
        # D. High-confidence phishing URL only
        self.assertGreater(results["suspicious_url_email"]["risk_score"], results["clean_email"]["risk_score"])
        self.assertIn(results["suspicious_url_email"]["risk_level"], {"MEDIUM", "HIGH", "CRITICAL"})
        # C. SPF + DKIM + DMARC failure is at least MEDIUM.
        self.assertIn(results["authentication_failure"]["risk_level"], {"MEDIUM", "HIGH", "CRITICAL"})
        # F. Multiple threats are CRITICAL or very high risk.
        self.assertGreater(results["multiple_risk_email"]["risk_score"], results["suspicious_url_email"]["risk_score"])
        self.assertGreaterEqual(results["multiple_risk_email"]["risk_score"], 75)
        self.assertGreater(results["suspicious_url_email"]["ai_threat_probability"], 0.5)

    def test_single_authentication_failure_and_url_auth_combination(self):
        # B. One SPF failure alone must remain LOW or MEDIUM.
        single_spf = self.post_case({"spf_failed": True})
        self.assertIn(single_spf["risk_level"], {"LOW", "MEDIUM"})

        # E. A high-confidence phishing URL plus an authentication failure is HIGH+.
        url_and_auth = self.post_case({
            "spf_failed": True,
            "urls": ["https://www.o-i.ch"],
        })
        self.assertIn(url_and_auth["risk_level"], {"HIGH", "CRITICAL"})
        reason_features = {reason["feature"] for reason in url_and_auth["reasons"]}
        self.assertIn("authentication_high_confidence_url", reason_features)

    def test_legacy_payload_is_accepted(self):
        result = self.post_case({"spf_failed": True, "url_count": 2})
        self.assertEqual(result["features"]["url_count"], 2)
        self.assertEqual(result["ai_threat_probability"], 0.0)

    def test_analyze_email_clean_eml(self):
        response = self._upload_eml("clean_email.eml")
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["extracted_email"]["from_address"], "alice@example.com")
        self.assertEqual(result["extracted_email"]["urls"], [])
        self.assertEqual(result["risk"]["risk_level"], "LOW")

    def test_analyze_email_suspicious_url_eml(self):
        response = self._upload_eml("suspicious_url_email.eml")
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["extracted_email"]["urls"], ["https://www.o-i.ch"])
        self.assertGreater(result["risk"]["ai_threat_probability"], 0.5)
        self.assertGreater(result["risk"]["risk_score"], 0)

    def test_analyze_email_upload_validation(self):
        self.assertEqual(self.client.post("/analyze-email").status_code, 400)
        response = self.client.post(
            "/analyze-email",
            data={"file": (b"not an eml", "message.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def _upload_eml(self, filename):
        fixture = Path(__file__).parent / "test_data" / filename
        with fixture.open("rb") as email_file:
            return self.client.post(
                "/analyze-email",
                data={"file": (email_file, filename)},
                content_type="multipart/form-data",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
