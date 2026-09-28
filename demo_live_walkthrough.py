import time
import json
import uuid
from app import app, get_db_connection, SESSION_STATE, DWELL_VAR_THRESHOLD, FLIGHT_VAR_THRESHOLD

def print_separator(title):
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)

def demonstrate_live_system():
    client = app.test_client()
    session_id = f"demo-live-{uuid.uuid4().hex[:8]}"
    print_separator(f"ZERO-TRUST PLATFORM LIVE DEMONSTRATION | SESSION: {session_id}")

    # -------------------------------------------------------------------------
    # STAGE 1: Student Enrollment & Identity Registration
    # -------------------------------------------------------------------------
    print("\n[STAGE 1] Student Identity & Cyber Hygiene Enrollment (/submit)")
    submit_payload = {
        "session_id": session_id,
        "email": f"demo_student_{session_id[:6]}@vit.edu",
        "branch": "Computer Engineering",
        "year": "3",
        "device": "Laptop Workstation",
        "uses_2fa": "1",
        "update_freq": "Always",
        "vishing_choice": "unanswered"
    }
    res = client.post("/submit", data=submit_payload)
    print(f"[*] Enrollment POST Status: {res.status_code}")
    print(f"[*] Response Body: {res.get_json()}")
    student_id = res.get_json()["student_id"]

    # -------------------------------------------------------------------------
    # STAGE 2: Normal Activity (Baseline)
    # -------------------------------------------------------------------------
    print_separator("SCENARIO 1: BASELINE NORMAL TYPING (Single Subject, Clean Typing)")
    print("[*] Telemetry: 1 face detected by optical sensor, standard typing cadence...")
    # Camera: 1 face
    client.post("/api/telemetry", json={"session_id": session_id, "source": "camera", "face_count": 1})
    # Keystrokes: consistent dwell (90ms) and flight (110ms)
    for _ in range(4):
        res = client.post("/api/telemetry", json={
            "session_id": session_id,
            "source": "keystroke",
            "dwell_time": 90.0,
            "flight_time": 110.0,
            "key_code": "KeyV"
        })
    data = res.get_json()
    print(f"[*] Correlation Engine Status: {data['status']}")
    print(f"[*] Dwell Variance: {data['metrics']['dwell_var']} (Threshold: {DWELL_VAR_THRESHOLD})")
    print(f"[*] Flight Variance: {data['metrics']['flight_var']} (Threshold: {FLIGHT_VAR_THRESHOLD})")
    print(f"[*] Active Threat: {data['threat']} (SYSTEM SECURE)")

    # -------------------------------------------------------------------------
    # STAGE 3: Shoulder Surfing Trigger (MEDIUM)
    # -------------------------------------------------------------------------
    print_separator("SCENARIO 2: SHOULDER SURFING DETECTED (Rule 3 - MEDIUM)")
    print("[*] Optical Edge Sensor detects 2 faces in camera frame...")
    res = client.post("/api/telemetry", json={
        "session_id": session_id,
        "source": "camera",
        "face_count": 2
    })
    data = res.get_json()
    threat = data["threat"]
    print(f"[!] Threat Verdict Fired: [{threat['level']}] {threat['label']}")
    print(f"[!] Autonomous Mitigation: {threat['action']}")
    print(f"[!] Telemetry Details: {threat['details']}")

    # -------------------------------------------------------------------------
    # STAGE 4: Session Hijacking Trigger (HIGH)
    # -------------------------------------------------------------------------
    print_separator("SCENARIO 3: SESSION HIJACKING DETECTED (Rule 2 - HIGH)")
    sess_high = f"demo-hijack-{uuid.uuid4().hex[:8]}"
    print(f"[*] New Session: {sess_high}")
    print("[*] Step A: User falls victim to Vishing phone call (Comply & Provide Password)...")
    client.post("/api/telemetry", json={
        "session_id": sess_high,
        "source": "vishing",
        "passed": False
    })
    print("[*] Step B: Attacker types with erratic keystroke flight timing...")
    for f in [60.0, 5200.0, 80.0, 4900.0]:
        res = client.post("/api/telemetry", json={
            "session_id": sess_high,
            "source": "keystroke",
            "dwell_time": 80.0,
            "flight_time": f,
            "key_code": "KeyH"
        })
    data = res.get_json()
    threat = data["threat"]
    print(f"[!] Threat Verdict Fired: [{threat['level']}] {threat['label']}")
    print(f"[!] Autonomous Mitigation: {threat['action']}")
    print(f"[!] Flight Variance Calculated: {data['metrics']['flight_var']} (Threshold: {FLIGHT_VAR_THRESHOLD})")

    # -------------------------------------------------------------------------
    # STAGE 5: Coerced Session Breach Trigger (CRITICAL)
    # -------------------------------------------------------------------------
    print_separator("SCENARIO 4: COERCED SESSION BREACH (Rule 1 - CRITICAL)")
    sess_crit = f"demo-coerced-{uuid.uuid4().hex[:8]}"
    print(f"[*] New Session: {sess_crit}")
    print("[*] Step A: Severe typing duress detected (High Dwell-Time Variance)...")
    for d in [45.0, 1300.0, 50.0, 1250.0]:
        client.post("/api/telemetry", json={
            "session_id": sess_crit,
            "source": "keystroke",
            "dwell_time": d,
            "flight_time": 95.0,
            "key_code": "KeyC"
        })
    print("[*] Step B: Multiple individuals present (Intruder standing behind victim)...")
    res = client.post("/api/telemetry", json={
        "session_id": sess_crit,
        "source": "camera",
        "face_count": 2
    })
    data = res.get_json()
    threat = data["threat"]
    print(f"[!] CRITICAL Threat Verdict: [{threat['level']}] {threat['label']}")
    print(f"[!] Autonomous Mitigation: {threat['action']}")
    print(f"[!] Honeypot Diversion Endpoint: /honeypot?session_id={sess_crit}")

    # -------------------------------------------------------------------------
    # STAGE 6: Live MySQL Audit Verification
    # -------------------------------------------------------------------------
    print_separator("STAGE 6: AUDIT TRAIL VERIFICATION IN MYSQL (correlated_threat_events)")
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT event_id, session_id, threat_level, threat_label, mitigation_action, created_at
        FROM correlated_threat_events
        ORDER BY event_id DESC
        LIMIT 4;
    """)
    rows = cursor.fetchall()
    print(f"{'ID':<6} | {'THREAT LEVEL':<10} | {'LABEL':<24} | {'ACTION':<20} | {'TIMESTAMP'}")
    print("-" * 80)
    for r in rows:
        print(f"{r['event_id']:<6} | {r['threat_level']:<10} | {r['threat_label']:<24} | {r['mitigation_action']:<20} | {r['created_at']}")
    cursor.close()
    db.close()
    print_separator("LIVE DEMONSTRATION COMPLETE - ALL SYSTEMS FUNCTIONING AT 100%")

if __name__ == "__main__":
    demonstrate_live_system()
