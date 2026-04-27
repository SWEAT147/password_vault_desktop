import sqlite3

# התחברות למסד הנתונים של הפרויקט
db_path = "vault_server.db"
email_to_change = "guyshalom147258@gmail.com"  # <--- שנה את זה לאימייל שאיתו נרשמת


def make_me_admin():
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # עדכון התפקיד ל-admin עבור המשתמש שלך
        cursor.execute("UPDATE users SET role = 'admin' WHERE email = ?", (email_to_change,))

        if cursor.rowcount == 0:
            print(f"שגיאה: לא נמצא משתמש עם האימייל {email_to_change}")
        else:
            conn.commit()
            print(f"הצלחה! המשתמש {email_to_change} הוא כעת admin.")

        conn.close()
    except Exception as e:
        print(f"קרתה שגיאה: {e}")


if __name__ == "__main__":
    make_me_admin()