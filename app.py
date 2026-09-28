import os
import uuid
import logging
from typing import Dict, Any, List, Optional
import mysql.connector
from mysql.connector import Error as MySQLError
from flask import Flask, request, render_template, jsonify, redirect, url_for
from dotenv import load_dotenv

load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("zero_trust_platform")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "zero-trust-secret-key-default-2026")

# Variance thresholds for keystroke dynamics (configurable via .env)
DWELL_VAR_THRESHOLD = float(os.getenv("DWELL_VAR_THRESHOLD", 2500.0))
FLIGHT_VAR_THRESHOLD = float(os.getenv("FLIGHT_VAR_THRESHOLD", 4000.0))

# -----------------------------------------------------------------------------
# Database Helper
# -----------------------------------------------------------------------------
def get_db_connection():
    """
    Establishes and returns a MySQL database connection using credentials from .env.
    """
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "vit_cyber_project"),
        autocommit=False
    )

# -----------------------------------------------------------------------------
# In-Memory Session State
# Structure:
# {
#   session_id: {
#       "dwell_times": List[float],
#       "flight_times": List[float],
#       "face_counts": List[int],
#       "vishing_passed": Optional[bool],
#       "student_id": Optional[int],
#       "active_threat": Optional[Dict[str, Any]],
#       "last_active": float
#   }
# }
# -----------------------------------------------------------------------------
SESSION_STATE: Dict[str, Dict[str, Any]] = {}
LATEST_ACTIVE_SESSION: Optional[str] = None

def get_or_create_session(session_id: str) -> Dict[str, Any]:
    global LATEST_ACTIVE_SESSION
    if session_id not in SESSION_STATE:
        SESSION_STATE[session_id] = {
            "dwell_times": [],
            "flight_times": [],
            "face_counts": [],
            "vishing_passed": None,
            "student_id": None,
            "active_threat": None
        }
    LATEST_ACTIVE_SESSION = session_id
    return SESSION_STATE[session_id]

# -----------------------------------------------------------------------------
# Biometrics & Statistical Engine
# -----------------------------------------------------------------------------
def safe_variance(data: List[float]) -> float:
    """
    Calculates population variance: (1/N) * sum((x - mean)^2).
    Returns 0.0 for < 2 samples so the correlation engine never crashes
    on sparse data early in a session.
    """
    n = len(data)
    if n < 2:
        return 0.0
    mean_val = sum(data) / n
    return sum((x - mean_val) ** 2 for x in data) / n

def safe_mean(data: List[float]) -> float:
    return (sum(data) / len(data)) if data else 0.0

# -----------------------------------------------------------------------------
# Real-Time Correlation Rule Matrix (Strict Severity Order)
# -----------------------------------------------------------------------------
def evaluate_correlation(session_id: str) -> Optional[Dict[str, Any]]:
    """
    Evaluates the 3-rule matrix in strict severity order:
    1. CRITICAL: High dwell-time variance + multiple faces => Coerced Session Breach (ROUTE_TO_HONEYPOT)
    2. HIGH:     High flight-time variance + failed vishing => Session Hijacking (REVOKE_SESSION)
    3. MEDIUM:   Multiple faces detected (alone)           => Shoulder Surfing (BLUR_SCREEN)

    Only the worst active threat is returned per evaluation.
    """
    if session_id not in SESSION_STATE:
        return None

    state = SESSION_STATE[session_id]
    dwell_times = state["dwell_times"]
    flight_times = state["flight_times"]
    face_counts = state["face_counts"]
    vishing_passed = state["vishing_passed"]

    dwell_var = safe_variance(dwell_times)
    flight_var = safe_variance(flight_times)

    # Multi-face condition: checked on recent frames (last 3 samples)
    recent_faces = face_counts[-3:] if face_counts else []
    multiple_faces = any(f >= 2 for f in recent_faces)

    # Dwell variance condition (requires at least 3 samples for statistical validity)
    high_dwell_variance = len(dwell_times) >= 3 and dwell_var > DWELL_VAR_THRESHOLD

    # Flight variance condition (requires at least 3 samples)
    high_flight_variance = len(flight_times) >= 3 and flight_var > FLIGHT_VAR_THRESHOLD

    # Vishing condition: explicitly failed
    vishing_failed = (vishing_passed is False)

    # 1. CRITICAL RULE: Coerced Session Breach
    if high_dwell_variance and multiple_faces:
        return {
            "label": "Coerced Session Breach",
            "level": "CRITICAL",
            "action": "ROUTE_TO_HONEYPOT",
            "details": f"Multiple faces present ({face_counts[-1]} detected) with high dwell variance ({dwell_var:.1f} > {DWELL_VAR_THRESHOLD}). Possible forced coercion."
        }

    # 2. HIGH RULE: Session Hijacking
    if high_flight_variance and vishing_failed:
        return {
            "label": "Session Hijacking",
            "level": "HIGH",
            "action": "REVOKE_SESSION",
            "details": f"Failed vishing challenge accompanied by high flight variance ({flight_var:.1f} > {FLIGHT_VAR_THRESHOLD}). Suspected unauthorized takeover."
        }

    # 3. MEDIUM RULE: Shoulder Surfing
    if multiple_faces:
        return {
            "label": "Shoulder Surfing",
            "level": "MEDIUM",
            "action": "BLUR_SCREEN",
            "details": f"Multiple faces detected in camera frame ({face_counts[-1]} faces). Potential observer shoulder surfing."
        }

    # 4. Standalone Biometric Keystroke Anomaly (High Variance Detection)
    if high_dwell_variance or high_flight_variance:
        flagged = "Dwell-time" if high_dwell_variance else "Flight-time"
        val = dwell_var if high_dwell_variance else flight_var
        thresh = DWELL_VAR_THRESHOLD if high_dwell_variance else FLIGHT_VAR_THRESHOLD
        return {
            "label": "Keystroke Biometric Anomaly",
            "level": "HIGH",
            "action": "REVOKE_SESSION",
            "details": f"{flagged} variance exceeded threshold ({val:.1f} > {thresh}). Neuromuscular timing anomaly detected."
        }

    return None

def persist_threat_event(session_id: str, threat: Dict[str, Any], metrics: Dict[str, Any]):
    """
    Inserts a row into correlated_threat_events whenever a rule fires.
    Never lets a DB persistence failure crash the request; logs and continues.
    """
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()

        student_id = SESSION_STATE.get(session_id, {}).get("student_id")
        sql = """
            INSERT INTO correlated_threat_events
            (session_id, student_id, threat_label, threat_level, mitigation_action, 
             dwell_var, flight_var, face_count, vishing_passed, threat_details)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (
            session_id,
            student_id,
            threat["label"],
            threat["level"],
            threat["action"],
            float(metrics.get("dwell_var", 0.0)),
            float(metrics.get("flight_var", 0.0)),
            int(metrics.get("face_count", 0)),
            1 if metrics.get("vishing_passed") is True else (0 if metrics.get("vishing_passed") is False else None),
            threat.get("details", "")
        ))
        db.commit()
        logger.info(f"Threat persisted to DB: [{threat['level']}] {threat['label']} for session {session_id}")
    except MySQLError as err:
        logger.error(f"Failed to persist threat event to MySQL: {err}")
        if db:
            db.rollback()
    except Exception as ex:
        logger.error(f"Unexpected error persisting threat event: {ex}")
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()

def update_behavioral_analytics(session_id: str, student_id: Optional[int], avg_dwell: float, dwell_var: float, avg_flight: float, flight_var: float, count: int):
    """
    Maintains rolling summary statistics in behavioral_analytics table.
    """
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        # Check if record for this session exists
        cursor.execute("SELECT analytics_id FROM behavioral_analytics WHERE session_id = %s LIMIT 1", (session_id,))
        row = cursor.fetchone()
        
        if row:
            cursor.execute("""
                UPDATE behavioral_analytics
                SET avg_dwell_time = %s, dwell_time_var = %s,
                    avg_flight_time = %s, flight_time_var = %s,
                    sample_count = %s, student_id = COALESCE(%s, student_id)
                WHERE session_id = %s
            """, (avg_dwell, dwell_var, avg_flight, flight_var, count, student_id, session_id))
        else:
            cursor.execute("""
                INSERT INTO behavioral_analytics
                (session_id, student_id, avg_dwell_time, dwell_time_var, avg_flight_time, flight_time_var, sample_count)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (session_id, student_id, avg_dwell, dwell_var, avg_flight, flight_var, count))
            
        db.commit()
    except MySQLError as err:
        logger.error(f"Error updating behavioral_analytics: {err}")
        if db:
            db.rollback()
    except Exception as ex:
        logger.error(f"Unexpected error in update_behavioral_analytics: {ex}")
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.route("/")
def index():
    """
    Generates a UUID session_id, initializes session state, and renders the SOC dashboard.
    """
    session_id = str(uuid.uuid4())
    get_or_create_session(session_id)
    return render_template(
        "index.html",
        session_id=session_id,
        dwell_threshold=DWELL_VAR_THRESHOLD,
        flight_threshold=FLIGHT_VAR_THRESHOLD
    )

@app.route("/submit", methods=["POST"])
def submit():
    """
    Accepts student info + survey answers + vishing result.
    Uses ON DUPLICATE KEY UPDATE keyed on oauth_email.
    Inserts survey row and links referential integrity.
    """
    db = None
    cursor = None
    try:
        session_id = request.form.get("session_id") or str(uuid.uuid4())
        email = request.form.get("email")
        branch = request.form.get("branch")
        year_str = request.form.get("year", "1")
        device = request.form.get("device", "Laptop")
        uses_2fa = 1 if request.form.get("uses_2fa") in ["1", "yes", "true", "True"] else 0
        update_freq = request.form.get("update_freq", "Always")
        experienced_crime = 1 if request.form.get("experienced_crime") in ["1", "yes", "true", "True"] else 0
        crime_type = request.form.get("crime_type", "None")
        pwd_score_str = request.form.get("password_score", "75")
        try:
            pwd_score = int(pwd_score_str)
        except ValueError:
            pwd_score = 75

        # Compute dynamic risk score (0-100)
        risk_score = 100 - (pwd_score // 2)
        if not uses_2fa:
            risk_score += 20
        if update_freq in ["Rarely", "Never"]:
            risk_score += 15
        if experienced_crime:
            risk_score += 10
        risk_score = max(0, min(risk_score, 100))

        vishing_choice = request.form.get("vishing_choice", "unanswered")
        vishing_passed = (1 if vishing_choice == "report" else 0) if vishing_choice != "unanswered" else None

        if not email or not branch:
            return jsonify({"status": "error", "message": "Email and branch are required."}), 400

        try:
            year = int(year_str)
        except ValueError:
            year = 1

        db = get_db_connection()
        cursor = db.cursor()

        # 1. Insert or update student (keyed on unique oauth_email)
        cursor.execute("""
            INSERT INTO students (oauth_email, branch, year_of_study, primary_device, session_id, data_source)
            VALUES (%s, %s, %s, %s, %s, 'live')
            ON DUPLICATE KEY UPDATE
                branch = VALUES(branch),
                year_of_study = VALUES(year_of_study),
                primary_device = VALUES(primary_device),
                session_id = VALUES(session_id)
        """, (email, branch, year, device, session_id))

        # Retrieve student_id
        cursor.execute("SELECT student_id FROM students WHERE oauth_email = %s", (email,))
        student_row = cursor.fetchone()
        student_id = student_row[0] if student_row else cursor.lastrowid

        # Update in-memory session state
        state = get_or_create_session(session_id)
        state["student_id"] = student_id
        if vishing_passed is not None:
            state["vishing_passed"] = (vishing_passed == 1)

        # 2. Insert survey response
        cursor.execute("""
            INSERT INTO survey_responses
            (student_id, password_strength_score, uses_2fa, software_update_freq, 
             experienced_cybercrime, cybercrime_type, overall_risk_score, vishing_choice, vishing_passed)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (student_id, pwd_score, uses_2fa, update_freq, experienced_crime, crime_type, risk_score, vishing_choice, vishing_passed))

        db.commit()

        # Also link student_id to existing keystroke / behavioral records for this session
        update_behavioral_analytics(
            session_id,
            student_id,
            safe_mean(state["dwell_times"]),
            safe_variance(state["dwell_times"]),
            safe_mean(state["flight_times"]),
            safe_variance(state["flight_times"]),
            len(state["dwell_times"])
        )

        return jsonify({
            "status": "success",
            "message": "Student profile, survey answers, and biometric telemetry recorded successfully.",
            "student_id": student_id,
            "session_id": session_id
        }), 200

    except MySQLError as err:
        logger.error(f"MySQL error during /submit: {err}")
        if db:
            db.rollback()
        return jsonify({"status": "error", "message": f"Database error: {str(err)}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error during /submit: {e}")
        if db:
            db.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()

@app.route("/api/telemetry", methods=["POST"])
def telemetry():
    """
    Ingests JSON telemetry packets from keystroke listener, camera sensor, or vishing test.
    Evaluates correlation rule matrix, triggers mitigations, persists threat events.
    """
    if not request.is_json:
        return jsonify({"status": "error", "message": "Payload must be JSON."}), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Invalid JSON body."}), 400

    session_id = data.get("session_id")
    source = data.get("source")

    if not session_id or not source:
        return jsonify({"status": "error", "message": "Missing required fields: session_id and source."}), 400

    state = get_or_create_session(session_id)
    student_id = state.get("student_id")

    db = None
    cursor = None

    try:
        # -----------------------------------------------------------------
        # Branch 1: Keystroke Telemetry
        # -----------------------------------------------------------------
        if source == "keystroke":
            try:
                dwell_time = float(data.get("dwell_time", 0.0))
                flight_time = float(data.get("flight_time", 0.0))
            except (ValueError, TypeError):
                return jsonify({"status": "error", "message": "dwell_time and flight_time must be numeric."}), 400

            key_code = str(data.get("key_code", ""))[:50]

            # Append to rolling in-memory window
            state["dwell_times"].append(dwell_time)
            state["flight_times"].append(flight_time)

            # Keep rolling window to latest 100 samples to prevent unbounded memory growth
            if len(state["dwell_times"]) > 100:
                state["dwell_times"] = state["dwell_times"][-100:]
            if len(state["flight_times"]) > 100:
                state["flight_times"] = state["flight_times"][-100:]

            # Persist raw keystroke event to MySQL
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute("""
                INSERT INTO keystroke_telemetry (session_id, student_id, key_code, dwell_time, flight_time)
                VALUES (%s, %s, %s, %s, %s)
            """, (session_id, student_id, key_code, dwell_time, flight_time))
            db.commit()

            # Update rolling summary stats in behavioral_analytics
            avg_dwell = safe_mean(state["dwell_times"])
            dwell_var = safe_variance(state["dwell_times"])
            avg_flight = safe_mean(state["flight_times"])
            flight_var = safe_variance(state["flight_times"])
            update_behavioral_analytics(
                session_id, student_id, avg_dwell, dwell_var, avg_flight, flight_var, len(state["dwell_times"])
            )

        # -----------------------------------------------------------------
        # Branch 2: Camera Edge Sensor
        # -----------------------------------------------------------------
        elif source == "camera":
            try:
                face_count = int(data.get("face_count", 0))
            except (ValueError, TypeError):
                return jsonify({"status": "error", "message": "face_count must be an integer."}), 400

            confidence = float(data.get("confidence", 1.0))

            state["face_counts"].append(face_count)
            if len(state["face_counts"]) > 50:
                state["face_counts"] = state["face_counts"][-50:]

            # Persist raw camera detection to MySQL
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute("""
                INSERT INTO facial_detections (session_id, face_count, confidence)
                VALUES (%s, %s, %s)
            """, (session_id, face_count, confidence))
            db.commit()

        # -----------------------------------------------------------------
        # Branch 3: Vishing Simulation Choice
        # -----------------------------------------------------------------
        elif source == "vishing":
            vishing_choice = data.get("vishing_choice")
            passed = data.get("passed")
            if passed is not None:
                state["vishing_passed"] = bool(passed)
            elif vishing_choice:
                state["vishing_passed"] = (vishing_choice == "report")
            else:
                return jsonify({"status": "error", "message": "vishing requires 'passed' or 'vishing_choice'."}), 400

        else:
            return jsonify({"status": "error", "message": f"Unsupported telemetry source: '{source}'."}), 400

    except MySQLError as err:
        logger.error(f"MySQL error inserting telemetry: {err}")
        if db:
            db.rollback()
    except Exception as e:
        logger.error(f"Error handling telemetry packet: {e}")
        if db:
            db.rollback()
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()

    # -----------------------------------------------------------------
    # Threat Evaluation
    # -----------------------------------------------------------------
    threat = evaluate_correlation(session_id)
    state["active_threat"] = threat

    dwell_var = safe_variance(state["dwell_times"])
    flight_var = safe_variance(state["flight_times"])
    latest_face = state["face_counts"][-1] if state["face_counts"] else 0

    metrics = {
        "dwell_var": round(dwell_var, 2),
        "flight_var": round(flight_var, 2),
        "avg_dwell": round(safe_mean(state["dwell_times"]), 2),
        "avg_flight": round(safe_mean(state["flight_times"]), 2),
        "keystroke_count": len(state["dwell_times"]),
        "face_count": latest_face,
        "vishing_passed": state.get("vishing_passed")
    }

    if threat:
        persist_threat_event(session_id, threat, metrics)

    return jsonify({
        "status": "threat_detected" if threat else "ok",
        "threat": threat,
        "metrics": metrics
    }), 200

@app.route("/api/active_session")
def active_session():
    """
    Returns the most recently initialized active session ID.
    Used by camera_sensor.py for automatic discovery.
    """
    return jsonify({
        "session_id": LATEST_ACTIVE_SESSION,
        "active_sessions_count": len(SESSION_STATE)
    })

@app.route("/api/session/<session_id>")
def session_details(session_id: str):
    """
    Returns the real-time in-memory status of an active session.
    """
    if session_id not in SESSION_STATE:
        return jsonify({"status": "not_found", "message": "Session not found."}), 404

    state = SESSION_STATE[session_id]
    threat = evaluate_correlation(session_id)

    return jsonify({
        "session_id": session_id,
        "student_id": state.get("student_id"),
        "keystroke_samples": len(state["dwell_times"]),
        "dwell_variance": safe_variance(state["dwell_times"]),
        "flight_variance": safe_variance(state["flight_times"]),
        "face_samples": len(state["face_counts"]),
        "latest_face_count": state["face_counts"][-1] if state["face_counts"] else 0,
        "vishing_passed": state.get("vishing_passed"),
        "active_threat": threat
    })

@app.route("/honeypot")
def honeypot():
    """
    Decoy honeypot terminal environment rendered when ROUTE_TO_HONEYPOT mitigation fires.
    """
    session_id = request.args.get("session_id", "unspecified")
    return render_template("honeypot.html", session_id=session_id)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "True").lower() in ("true", "1", "t")
    print(f"============================================================")
    print(f"Zero-Trust CTI & Incident Correlation Platform Running")
    print(f"Listening on: http://127.0.0.1:{port}")
    print(f"Correlation Engine Thresholds: Dwell Var > {DWELL_VAR_THRESHOLD}, Flight Var > {FLIGHT_VAR_THRESHOLD}")
    print(f"============================================================")
    app.run(host="0.0.0.0", port=port, debug=debug)