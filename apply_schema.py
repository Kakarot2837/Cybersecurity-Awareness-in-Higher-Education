import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

def apply_schema():
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "vit_cyber_project")
    )
    cursor = conn.cursor()
    print("Connected to MySQL database:", os.getenv("DB_NAME"))

    with open("schema_update.sql", "r", encoding="utf-8") as f:
        sql_commands = f.read()

    # Split by statements
    statements = [stmt.strip() for stmt in sql_commands.split(";") if stmt.strip()]

    for stmt in statements:
        if stmt.upper().startswith("USE ") or stmt.upper().startswith("CREATE DATABASE"):
            continue
        try:
            cursor.execute(stmt)
            conn.commit()
            print(f"Executed: {stmt[:50]}...")
        except mysql.connector.Error as err:
            print(f"Notice on stmt ({stmt[:40]}...): {err}")

    # Now verify and add columns/constraints to existing tables if needed
    column_checks = [
        ("students", "session_id", "ALTER TABLE students ADD COLUMN session_id VARCHAR(100) NULL AFTER primary_device"),
        ("survey_responses", "vishing_choice", "ALTER TABLE survey_responses ADD COLUMN vishing_choice VARCHAR(50) NULL"),
        ("survey_responses", "vishing_passed", "ALTER TABLE survey_responses ADD COLUMN vishing_passed TINYINT(1) NULL"),
        ("survey_responses", "created_at", "ALTER TABLE survey_responses ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("behavioral_analytics", "session_id", "ALTER TABLE behavioral_analytics ADD COLUMN session_id VARCHAR(100) NULL AFTER student_id"),
        ("behavioral_analytics", "dwell_time_var", "ALTER TABLE behavioral_analytics ADD COLUMN dwell_time_var FLOAT DEFAULT 0.0"),
        ("behavioral_analytics", "flight_time_var", "ALTER TABLE behavioral_analytics ADD COLUMN flight_time_var FLOAT DEFAULT 0.0"),
        ("behavioral_analytics", "sample_count", "ALTER TABLE behavioral_analytics ADD COLUMN sample_count INT DEFAULT 0"),
        ("behavioral_analytics", "updated_at", "ALTER TABLE behavioral_analytics ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
    ]

    for table, col, alter_sql in column_checks:
        try:
            cursor.execute(f"SHOW COLUMNS FROM {table} LIKE '{col}';")
            result = cursor.fetchone()
            if not result:
                cursor.execute(alter_sql)
                conn.commit()
                print(f"Added column {col} to {table}")
        except Exception as e:
            print(f"Notice adding {col} to {table}: {e}")

    # Ensure unique constraint on students(oauth_email)
    try:
        cursor.execute("SHOW INDEX FROM students WHERE Key_name = 'unique_oauth_email';")
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE students ADD UNIQUE KEY unique_oauth_email (oauth_email);")
            conn.commit()
            print("Added unique index unique_oauth_email to students")
    except Exception as e:
        print("Notice adding unique index:", e)

    # Check foreign keys
    try:
        cursor.execute("""
            SELECT CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS 
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'survey_responses' AND CONSTRAINT_TYPE = 'FOREIGN KEY';
        """)
        if not cursor.fetchone():
            cursor.execute("""
                ALTER TABLE survey_responses 
                ADD CONSTRAINT fk_survey_student 
                FOREIGN KEY (student_id) REFERENCES students(student_id) 
                ON DELETE CASCADE ON UPDATE CASCADE;
            """)
            conn.commit()
            print("Added fk_survey_student with ON DELETE CASCADE")
    except Exception as e:
        print("Notice adding fk_survey_student:", e)

    # Verify tables
    cursor.execute("SHOW TABLES;")
    tables = [t[0] for t in cursor.fetchall()]
    print("\nVerified Tables in vit_cyber_project:")
    for t in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {t}")
        cnt = cursor.fetchone()[0]
        print(f"  - {t}: {cnt} rows")

    cursor.close()
    conn.close()
    print("\nDatabase schema setup complete!")

if __name__ == "__main__":
    apply_schema()
