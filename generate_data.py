import os
import mysql.connector
import random
from datetime import datetime, timedelta
from dotenv import load_dotenv

# ==========================================
# LOAD ENVIRONMENT VARIABLES
# ==========================================

load_dotenv()

# ==========================================
# CONNECT TO MYSQL DATABASE
# ==========================================

try:
    db = mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

    cursor = db.cursor()

    print("Connected to database successfully!")
    print("Generating 500 students...")

    # ==========================================
    # RANDOM DATA OPTIONS
    # ==========================================

    branches = [
        "Computer Engineering",
        "IT",
        "AI & Data Science",
        "EnTC",
        "Mechanical"
    ]

    devices = [
        "Laptop",
        "Smartphone",
        "Tablet"
    ]

    update_frequencies = [
        "Always",
        "Sometimes",
        "Rarely",
        "Never"
    ]

    crime_types = [
        "UPI Fraud",
        "Social Media Cloned",
        "Fake Internship Offer",
        "Phishing Link"
    ]

    # ==========================================
    # GENERATE 500 STUDENTS
    # ==========================================

    for i in range(1, 501):

        # ======================================
        # TABLE 1: STUDENTS
        # ======================================

        email = f"student_{i}_{random.randint(1000, 9999)}@vit.edu"

        branch = random.choice(branches)

        year = random.randint(1, 4)

        device = random.choice(devices)

        sql_student = """
        INSERT INTO students
        (
            oauth_email,
            branch,
            year_of_study,
            primary_device,
            data_source
        )
        VALUES (%s, %s, %s, %s, %s)
        """

        cursor.execute(
            sql_student,
            (
                email,
                branch,
                year,
                device,
                "simulated"
            )
        )

        # Get automatically generated student ID
        student_id = cursor.lastrowid

        # ======================================
        # TABLE 2: SURVEY RESPONSES
        # ======================================

        password_score = random.randint(20, 100)

        uses_2fa = random.choice([True, False])

        update_freq = random.choice(update_frequencies)

        experienced_crime = random.choices(
            [True, False],
            weights=[0.25, 0.75]
        )[0]

        if experienced_crime:
            crime = random.choice(crime_types)
        else:
            crime = "None"

        # Calculate risk score
        risk_score = 100 - (password_score // 2)

        if not uses_2fa:
            risk_score += 20

        if update_freq in ["Rarely", "Never"]:
            risk_score += 15

        if experienced_crime:
            risk_score += 10

        # Keep risk score between 0 and 100
        risk_score = max(0, min(risk_score, 100))

        sql_survey = """
        INSERT INTO survey_responses
        (
            student_id,
            password_strength_score,
            uses_2fa,
            software_update_freq,
            experienced_cybercrime,
            cybercrime_type,
            overall_risk_score
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        cursor.execute(
            sql_survey,
            (
                student_id,
                password_score,
                uses_2fa,
                update_freq,
                experienced_crime,
                crime,
                risk_score
            )
        )

        # ======================================
        # TABLE 3: BEHAVIORAL ANALYTICS
        # ======================================

        browser_vulnerable = random.choices(
            [True, False],
            weights=[0.40, 0.60]
        )[0]

        days_ago = random.randint(1, 60)

        sent_at = datetime.now() - timedelta(
            days=days_ago
        )

        clicked_safe = random.choices(
            [True, False],
            weights=[0.80, 0.20]
        )[0]

        # High-risk students have a higher
        # probability of clicking the trap link
        if risk_score > 75:
            trap_weight = 0.60
        else:
            trap_weight = 0.15

        clicked_trap = random.choices(
            [True, False],
            weights=[
                trap_weight,
                1 - trap_weight
            ]
        )[0]

        # Reaction time only exists if trap was clicked
        if clicked_trap:
            reaction_time = random.randint(5, 45)
        else:
            reaction_time = None

        sql_behavior = """
        INSERT INTO behavioral_analytics
        (
            student_id,
            browser_vulnerable,
            trap_emails_sent_at,
            clicked_safe_link,
            clicked_trap_link,
            reaction_time_seconds
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        """

        cursor.execute(
            sql_behavior,
            (
                student_id,
                browser_vulnerable,
                sent_at,
                clicked_safe,
                clicked_trap,
                reaction_time
            )
        )

        # ======================================
        # SHOW PROGRESS
        # ======================================

        if i % 50 == 0:
            print(f"{i} students generated...")

    # ==========================================
    # SAVE ALL DATA
    # ==========================================

    db.commit()

    print("------------------------------------------")
    print("SUCCESS!")
    print("500 students inserted successfully.")
    print("500 survey responses inserted.")
    print("500 behavioral analytics records inserted.")
    print("------------------------------------------")


except mysql.connector.Error as err:

    print("Database Error:")
    print(err)

except Exception as err:

    print("Error:")
    print(err)

finally:

    if "db" in locals() and db.is_connected():
        cursor.close()
        db.close()
        print("Database connection closed.")