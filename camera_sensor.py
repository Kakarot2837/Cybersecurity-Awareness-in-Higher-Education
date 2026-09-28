import os
import sys
import time
import argparse
import queue
import threading
import requests
import cv2
import numpy as np

# -----------------------------------------------------------------------------
# CLI Arguments & Session Resolution
# -----------------------------------------------------------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Zero-Trust Optical Edge Sensor: Real-Time Face Counting & Telemetry Dispatcher"
    )
    parser.add_argument(
        "--session-id",
        type=str,
        default=None,
        help="Target Flask session UUID. If omitted, attempts auto-discovery from /api/active_session."
    )
    parser.add_argument(
        "--server",
        type=str,
        default="http://127.0.0.1:5000",
        help="Base URL of the Zero-Trust Flask server (default: http://127.0.0.1:5000)"
    )
    parser.add_argument(
        "--camera",
        type=int,
        default=0,
        help="OpenCV VideoCapture camera device index (default: 0)"
    )
    return parser.parse_args()

def resolve_target_session(server_url: str, explicit_session_id: str = None) -> str:
    if explicit_session_id:
        return explicit_session_id

    print(f"[*] Discovering active session from {server_url}/api/active_session...")
    try:
        resp = requests.get(f"{server_url}/api/active_session", timeout=3)
        if resp.status_code == 200:
            active_id = resp.json().get("session_id")
            if active_id:
                print(f"[+] Auto-discovered active target session: {active_id}")
                return active_id
    except Exception as e:
        print(f"[!] Could not auto-discover session: {e}")

    fallback_id = "demo-session-default"
    print(f"[!] Falling back to session ID: '{fallback_id}'")
    return fallback_id

# -----------------------------------------------------------------------------
# Background Producer-Consumer Telemetry Worker (1 POST / sec)
# -----------------------------------------------------------------------------
def telemetry_worker(telemetry_queue: queue.Queue, stop_event: threading.Event, server_url: str, session_id: str):
    """
    Consumes face counts from queue and POSTs once per second to /api/telemetry.
    Prevents HTTP packet flooding of the backend while maintaining fresh telemetry.
    """
    endpoint = f"{server_url}/api/telemetry"
    last_sent_time = 0.0

    while not stop_event.is_set():
        try:
            # Drain queue to only get the latest detected face count
            latest_count = None
            while not telemetry_queue.empty():
                try:
                    latest_count = telemetry_queue.get_nowait()
                except queue.Empty:
                    break

            now = time.time()
            if latest_count is not None and (now - last_sent_time >= 1.0):
                payload = {
                    "session_id": session_id,
                    "source": "camera",
                    "face_count": latest_count,
                    "confidence": 1.0
                }
                try:
                    res = requests.post(endpoint, json=payload, timeout=2)
                    if res.status_code == 200:
                        data = res.json()
                        threat = data.get("threat")
                        if threat:
                            print(f"[ALARM] Threat Triggered: [{threat['level']}] {threat['label']} -> {threat['action']}")
                        else:
                            print(f"[OK] Telemetry posted: {latest_count} face(s) for session {session_id[:8]}...")
                    else:
                        print(f"[!] Server returned status {res.status_code}: {res.text}")
                except requests.RequestException as req_err:
                    print(f"[!] Network error sending telemetry: {req_err}")

                last_sent_time = now

            time.sleep(0.05)
        except Exception as e:
            print(f"[!] Telemetry worker exception: {e}")
            time.sleep(0.2)

# -----------------------------------------------------------------------------
# Main Sensor Pipeline
# -----------------------------------------------------------------------------
def run_sensor():
    args = parse_arguments()
    session_id = resolve_target_session(args.server, args.session_id)

    # 1. Load Haar Cascade
    cascade_path = os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_default.xml")
    if not os.path.exists(cascade_path):
        print(f"[FATAL] Haar cascade file not found at: {cascade_path}")
        sys.exit(1)

    face_cascade = cv2.CascadeClassifier(cascade_path)
    if face_cascade.empty():
        print("[FATAL] Failed to initialize Haar cascade classifier.")
        sys.exit(1)

    print(f"[+] Loaded Haar Cascade from: {cascade_path}")

    # 2. Start Background Telemetry Thread
    telemetry_q = queue.Queue()
    stop_event = threading.Event()
    worker_thread = threading.Thread(
        target=telemetry_worker,
        args=(telemetry_q, stop_event, args.server, session_id),
        daemon=True
    )
    worker_thread.start()

    # 3. Initialize Video Stream
    print(f"[*] Initializing camera device {args.camera}...")
    cap = cv2.VideoCapture(args.camera)
    camera_available = cap.isOpened()

    if not camera_available:
        print(f"[WARN] Camera {args.camera} could not be opened (may be in use or no webcam attached).")
        print("[*] Launching Sensor Fallback GUI Simulator...")
        print("[*] Use keyboard in GUI window: '0'=0 faces, '1'=1 face, '2'=2 faces (shoulder surfing), 'q'=Quit")

    window_name = "Zero-Trust Optical Edge Sensor"
    cv2.namedWindow(window_name, cv2.WINDOW_AUTOSIZE)

    simulated_face_count = 1

    try:
        while True:
            if camera_available:
                ret, frame = cap.read()
                if not ret:
                    print("[!] Failed to grab frame from camera.")
                    time.sleep(0.1)
                    continue

                # Mirror frame for natural preview
                frame = cv2.flip(frame, 1)
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

                # Detect faces
                faces = face_cascade.detectMultiScale(
                    gray,
                    scaleFactor=1.1,
                    minNeighbors=5,
                    minSize=(40, 40)
                )

                face_count = len(faces)

                # Draw bounding boxes
                for (x, y, w, h) in faces:
                    color = (0, 255, 0) if face_count == 1 else (0, 0, 255)
                    cv2.rectangle(frame, (x, y), (x + w, y + h), color, 2)
                    cv2.putText(frame, "SUBJECT", (x, y - 8), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)

                # Push to rate-limited queue
                telemetry_q.put(face_count)

            else:
                # Fallback canvas
                frame = np.zeros((480, 640, 3), dtype=np.uint8)
                face_count = simulated_face_count
                telemetry_q.put(face_count)

                # Simulated subjects
                if face_count >= 1:
                    cv2.rectangle(frame, (180, 160), (320, 320), (0, 255, 0), 2)
                    cv2.putText(frame, "SUBJECT #1 (PRIMARY)", (170, 150), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)
                if face_count >= 2:
                    cv2.rectangle(frame, (380, 180), (500, 320), (0, 0, 255), 2)
                    cv2.putText(frame, "SUBJECT #2 (SHOULDER SURFER)", (340, 170), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 1)

            # Draw HUD Overlays
            hud_bg_color = (20, 20, 20)
            cv2.rectangle(frame, (0, 0), (640, 75), hud_bg_color, -1)
            cv2.line(frame, (0, 75), (640, 75), (0, 120, 255), 2)

            title_text = "ZERO-TRUST CTI OPTICAL SENSOR"
            cv2.putText(frame, title_text, (15, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 200, 255), 2)

            status_color = (0, 255, 0) if face_count == 1 else ((0, 0, 255) if face_count > 1 else (150, 150, 150))
            face_text = f"FACES DETECTED: {face_count}"
            if face_count > 1:
                face_text += " [SHOULDER SURFING ALERT]"
            cv2.putText(frame, face_text, (15, 52), cv2.FONT_HERSHEY_SIMPLEX, 0.65, status_color, 2)

            sess_text = f"Target Session: {session_id[:16]}..."
            cv2.putText(frame, sess_text, (360, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (200, 200, 200), 1)

            rate_text = "Stream: 1 POST/sec | 'q': Exit"
            cv2.putText(frame, rate_text, (360, 52), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (180, 180, 180), 1)

            cv2.imshow(window_name, frame)

            # Key controls
            key = cv2.waitKey(30) & 0xFF
            if key == ord('q') or key == 27:
                print("\n[+] Exiting camera sensor gracefully...")
                break
            elif key == ord('0'):
                simulated_face_count = 0
                print("[*] Simulated face count set to 0")
            elif key == ord('1'):
                simulated_face_count = 1
                print("[*] Simulated face count set to 1")
            elif key == ord('2'):
                simulated_face_count = 2
                print("[*] Simulated face count set to 2 (Shoulder Surfing)")
            elif key == ord('3'):
                simulated_face_count = 3
                print("[*] Simulated face count set to 3")

    except KeyboardInterrupt:
        print("\n[+] Interrupted by operator.")
    finally:
        stop_event.set()
        if cap and cap.isOpened():
            cap.release()
        cv2.destroyAllWindows()
        worker_thread.join(timeout=1.0)
        print("[+] Sensor process terminated.")

if __name__ == "__main__":
    run_sensor()
