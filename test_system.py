import unittest
import json
import uuid
import mysql.connector
from app import app, safe_variance, safe_mean, SESSION_STATE, get_db_connection

class ZeroTrustPlatformTestSuite(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.test_session_id = f"test-sess-{uuid.uuid4()}"

    # -------------------------------------------------------------------------
    # 1. Biometric Math & safe_variance Unit Tests
    # -------------------------------------------------------------------------
    def test_safe_variance_sparse_data(self):
        self.assertEqual(safe_variance([]), 0.0, "Empty list should return 0 variance")
        self.assertEqual(safe_variance([120.0]), 0.0, "Single sample should return 0 variance without crashing")

    def test_safe_variance_known_distribution(self):
        data = [10.0, 20.0, 30.0]
        # Mean = 20, var = ((10-20)^2 + (20-20)^2 + (30-20)^2)/3 = 200/3 ≈ 66.6667
        var = safe_variance(data)
        self.assertAlmostEqual(var, 200.0 / 3.0, places=4)

    # -------------------------------------------------------------------------
    # 2. Database Schema & 6 Tables Check
    # -------------------------------------------------------------------------
    def test_database_tables_exist(self):
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SHOW TABLES;")
        tables = [t[0] for t in cursor.fetchall()]
        cursor.close()
        db.close()

        expected_tables = [
            "students",
            "survey_responses",
            "behavioral_analytics",
            "facial_detections",
            "keystroke_telemetry",
            "correlated_threat_events"
        ]
        for tbl in expected_tables:
            self.assertIn(tbl, tables, f"Database table '{tbl}' must exist in schema")

    # -------------------------------------------------------------------------
    # 3. Negative Testing: Telemetry Endpoint Robustness (Phase 6)
    # -------------------------------------------------------------------------
    def test_telemetry_missing_json(self):
        res = self.client.post("/api/telemetry", data="not json", content_type="text/plain")
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.json["status"])

    def test_telemetry_missing_required_fields(self):
        res = self.client.post("/api/telemetry", json={"session_id": "abc"})
        self.assertEqual(res.status_code, 400)

        res = self.client.post("/api/telemetry", json={"source": "keystroke"})
        self.assertEqual(res.status_code, 400)

    def test_telemetry_invalid_source(self):
        res = self.client.post("/api/telemetry", json={"session_id": "abc", "source": "bluetooth_spoof"})
        self.assertEqual(res.status_code, 400)

    def test_telemetry_invalid_types(self):
        res = self.client.post("/api/telemetry", json={
            "session_id": "abc",
            "source": "keystroke",
            "dwell_time": "invalid_string",
            "flight_time": 50
        })
        self.assertEqual(res.status_code, 400)

        res = self.client.post("/api/telemetry", json={
            "session_id": "abc",
            "source": "camera",
            "face_count": "two_faces"
        })
        self.assertEqual(res.status_code, 400)

    # -------------------------------------------------------------------------
    # 4. Correlation Rule 3 (MEDIUM): Shoulder Surfing
    # -------------------------------------------------------------------------
    def test_rule_shoulder_surfing_medium(self):
        sess = f"test-med-{uuid.uuid4()}"
        res = self.client.post("/api/telemetry", json={
            "session_id": sess,
            "source": "camera",
            "face_count": 2
        })
        self.assertEqual(res.status_code, 200)
        threat = res.json.get("threat")
        self.assertIsNotNone(threat, "Shoulder surfing rule should fire")
        self.assertEqual(threat["level"], "MEDIUM")
        self.assertEqual(threat["label"], "Shoulder Surfing")
        self.assertEqual(threat["action"], "BLUR_SCREEN")

    # -------------------------------------------------------------------------
    # 5. Correlation Rule 2 (HIGH): Session Hijacking
    # -------------------------------------------------------------------------
    def test_rule_session_hijacking_high(self):
        sess = f"test-high-{uuid.uuid4()}"
        # 1. Record failed vishing
        res = self.client.post("/api/telemetry", json={
            "session_id": sess,
            "source": "vishing",
            "passed": False
        })
        self.assertEqual(res.status_code, 200)

        # 2. Inject keystrokes with high flight variance (> 4000.0)
        flight_samples = [50.0, 5000.0, 100.0, 4800.0]
        for f in flight_samples:
            res = self.client.post("/api/telemetry", json={
                "session_id": sess,
                "source": "keystroke",
                "dwell_time": 100.0,
                "flight_time": f,
                "key_code": "KeyA"
            })
            self.assertEqual(res.status_code, 200)

        threat = res.json.get("threat")
        self.assertIsNotNone(threat, "Session hijacking rule should fire")
        self.assertEqual(threat["level"], "HIGH")
        self.assertEqual(threat["label"], "Session Hijacking")
        self.assertEqual(threat["action"], "REVOKE_SESSION")

    # -------------------------------------------------------------------------
    # 6. Correlation Rule 1 (CRITICAL): Coerced Session Breach
    # -------------------------------------------------------------------------
    def test_rule_coerced_session_breach_critical(self):
        sess = f"test-crit-{uuid.uuid4()}"
        # 1. Inject high dwell variance (> 2500.0)
        dwell_samples = [40.0, 1200.0, 60.0, 1100.0]
        for d in dwell_samples:
            self.client.post("/api/telemetry", json={
                "session_id": sess,
                "source": "keystroke",
                "dwell_time": d,
                "flight_time": 100.0,
                "key_code": "KeyK"
            })

        # 2. Inject multiple faces
        res = self.client.post("/api/telemetry", json={
            "session_id": sess,
            "source": "camera",
            "face_count": 2
        })
        self.assertEqual(res.status_code, 200)

        threat = res.json.get("threat")
        self.assertIsNotNone(threat, "Coerced session breach rule should fire")
        self.assertEqual(threat["level"], "CRITICAL")
        self.assertEqual(threat["label"], "Coerced Session Breach")
        self.assertEqual(threat["action"], "ROUTE_TO_HONEYPOT")

    # -------------------------------------------------------------------------
    # 7. Concurrency & Session State Isolation (Phase 6)
    # -------------------------------------------------------------------------
    def test_concurrency_session_isolation(self):
        sess_a = f"test-sess-A-{uuid.uuid4()}"
        sess_b = f"test-sess-B-{uuid.uuid4()}"

        # Session A: normal typing, 1 face
        self.client.post("/api/telemetry", json={
            "session_id": sess_a, "source": "camera", "face_count": 1
        })
        res_a = self.client.post("/api/telemetry", json={
            "session_id": sess_a, "source": "keystroke", "dwell_time": 90.0, "flight_time": 110.0
        })

        # Session B: 2 faces (triggers shoulder surfing)
        res_b = self.client.post("/api/telemetry", json={
            "session_id": sess_b, "source": "camera", "face_count": 2
        })

        self.assertIsNone(res_a.json.get("threat"), "Session A should remain clean")
        self.assertIsNotNone(res_b.json.get("threat"), "Session B should detect threat")
        self.assertEqual(res_b.json["threat"]["level"], "MEDIUM")
        self.assertNotEqual(SESSION_STATE[sess_a]["face_counts"], SESSION_STATE[sess_b]["face_counts"])

    # -------------------------------------------------------------------------
    # 8. Submit Route & Referential Integrity Cascade
    # -------------------------------------------------------------------------
    def test_submit_and_cascade_delete(self):
        test_email = f"pytest_{uuid.uuid4().hex[:8]}@vit.edu"
        res = self.client.post("/submit", data={
            "session_id": self.test_session_id,
            "email": test_email,
            "branch": "Computer Engineering",
            "year": "3",
            "device": "Laptop",
            "uses_2fa": "1",
            "update_freq": "Always",
            "vishing_choice": "report"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertEqual(data["status"], "success")
        student_id = data["student_id"]

        # Verify DB rows
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT student_id, oauth_email FROM students WHERE student_id = %s", (student_id,))
        student_row = cursor.fetchone()
        self.assertIsNotNone(student_row)
        self.assertEqual(student_row[1], test_email)

        cursor.execute("SELECT response_id, uses_2fa FROM survey_responses WHERE student_id = %s", (student_id,))
        survey_row = cursor.fetchone()
        self.assertIsNotNone(survey_row)

        # Test ON DELETE CASCADE
        cursor.execute("DELETE FROM students WHERE student_id = %s", (student_id,))
        db.commit()

        cursor.execute("SELECT response_id FROM survey_responses WHERE student_id = %s", (student_id,))
        orphaned_survey = cursor.fetchone()
        self.assertIsNone(orphaned_survey, "Cascading delete must remove related survey_responses")

        cursor.close()
        db.close()

if __name__ == "__main__":
    unittest.main()
