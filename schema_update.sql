-- =====================================================================
-- Zero-Trust CTI & Incident Correlation Platform Schema
-- Database: vit_cyber_project
-- Normalization: 6 Tables enforcing referential integrity & audit logs
-- =====================================================================

CREATE DATABASE IF NOT EXISTS vit_cyber_project;
USE vit_cyber_project;

-- ---------------------------------------------------------------------
-- Table 1: students
-- Holds user identity, demographics, and session token.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS students (
    student_id INT AUTO_INCREMENT PRIMARY KEY,
    oauth_email VARCHAR(255) NOT NULL,
    branch VARCHAR(100) NOT NULL,
    year_of_study INT NOT NULL,
    primary_device VARCHAR(50) NOT NULL,
    session_id VARCHAR(100) NULL,
    data_source VARCHAR(50) DEFAULT 'live',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_oauth_email (oauth_email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------
-- Table 2: survey_responses
-- Cyber hygiene questions linked to a student (1-to-many relationship).
-- Deleting a student cascades to their survey rows.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS survey_responses (
    response_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    password_strength_score INT DEFAULT NULL,
    uses_2fa TINYINT(1) DEFAULT NULL,
    software_update_freq VARCHAR(50) DEFAULT NULL,
    experienced_cybercrime TINYINT(1) DEFAULT NULL,
    cybercrime_type VARCHAR(100) DEFAULT NULL,
    overall_risk_score INT DEFAULT NULL,
    vishing_choice VARCHAR(50) DEFAULT NULL,
    vishing_passed TINYINT(1) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_survey_student
        FOREIGN KEY (student_id) REFERENCES students(student_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------
-- Table 3: behavioral_analytics
-- Rolling summary statistics (avg & variance) recomputed per session.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS behavioral_analytics (
    analytics_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NULL,
    session_id VARCHAR(100) NULL,
    browser_vulnerable TINYINT(1) DEFAULT 0,
    trap_emails_sent_at DATETIME DEFAULT NULL,
    clicked_safe_link TINYINT(1) DEFAULT 0,
    clicked_trap_link TINYINT(1) DEFAULT 0,
    reaction_time_seconds INT DEFAULT NULL,
    avg_dwell_time FLOAT DEFAULT 0.0,
    dwell_time_var FLOAT DEFAULT 0.0,
    avg_flight_time FLOAT DEFAULT 0.0,
    flight_time_var FLOAT DEFAULT 0.0,
    sample_count INT DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_behavioral_session (session_id),
    CONSTRAINT fk_behavioral_student
        FOREIGN KEY (student_id) REFERENCES students(student_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------
-- Table 4: facial_detections
-- Raw per-frame face-count telemetry stream from the edge camera sensor.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS facial_detections (
    detection_id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    face_count INT NOT NULL,
    confidence FLOAT DEFAULT 1.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_facial_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------
-- Table 5: keystroke_telemetry
-- Raw per-keystroke telemetry (dwell & flight) for audit and re-analysis.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS keystroke_telemetry (
    keystroke_id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    student_id INT NULL,
    key_code VARCHAR(50) DEFAULT NULL,
    dwell_time FLOAT NOT NULL,
    flight_time FLOAT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_keystroke_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------
-- Table 6: correlated_threat_events
-- Output of real-time correlation engine whenever a rule fires.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlated_threat_events (
    event_id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    student_id INT NULL,
    threat_label VARCHAR(100) NOT NULL,
    threat_level VARCHAR(20) NOT NULL,
    mitigation_action VARCHAR(100) NOT NULL,
    dwell_var FLOAT DEFAULT 0.0,
    flight_var FLOAT DEFAULT 0.0,
    face_count INT DEFAULT 0,
    vishing_passed TINYINT(1) DEFAULT NULL,
    threat_details TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_threat_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
