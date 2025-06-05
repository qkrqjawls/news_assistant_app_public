import os
import datetime
import mysql.connector
from flask import Flask, request, jsonify
from bcrypt import hashpw, gensalt, checkpw
import jwt

app = Flask(__name__)

# 환경변수로부터 설정 읽기 (Cloud Run 배포 시 환경변수로 세팅)
DB_USER     = os.environ.get("DB_USER", "appuser")
DB_PASS     = os.environ.get("DB_PASS", "secure_app_password")
DB_NAME     = os.environ.get("DB_NAME", "myappdb")
DB_SOCKET   = os.environ.get("DB_SOCKET")   # ex) "/cloudsql/project:region:instance"
SECRET_KEY  = os.environ.get("JWT_SECRET", "change_this_in_prod")
JWT_ALGO    = "HS256"

import sys
import traceback

@app.route("/test-db")
def test_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT NOW()")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return jsonify({"db_time": str(result[0])})
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

def get_db_connection():
    try:
        if DB_SOCKET:
            return mysql.connector.connect(
                user=DB_USER,
                password=DB_PASS,
                database=DB_NAME,
                unix_socket=DB_SOCKET,
            )
        else:
            return mysql.connector.connect(
                user=DB_USER,
                password=DB_PASS,
                database=DB_NAME,
                host="127.0.0.1",
                port=3306
            )
    except mysql.connector.Error as err:
        print("(!) DB 연결 실패", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        raise

def generate_jwt(user_id, username, role):
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)
    return token

@app.route("/register", methods=["POST"])
def register():
    """
    JSON body: { "username": "...", "password": "...", "email": "..." }
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    email    = data.get("email")

    if not username or not password or not email:
        return jsonify({"error": "username, password, email 모두 필요합니다."}), 400

    # 비밀번호 해시
    pw_hash = hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (%s, %s, %s)",
            (username, pw_hash, email)
        )
        conn.commit()
        new_id = cursor.lastrowid
    except mysql.connector.errors.IntegrityError as e:
        # username이나 email이 중복된 경우 예외 발생
        conn.rollback()
        return jsonify({"error": "이미 존재하는 username 또는 email입니다."}), 409
    finally:
        cursor.close()
        conn.close()

    return jsonify({"message": "회원가입 성공", "user_id": new_id}), 201

@app.route("/login", methods=["POST"])
def login():
    """
    JSON body: { "username": "...", "password": "..." }
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username과 password가 필요합니다."}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({"error": "유저 정보를 찾을 수 없습니다."}), 404

    # 비밀번호 검증
    if not checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        return jsonify({"error": "비밀번호가 일치하지 않습니다."}), 401

    # JWT 발급
    token = generate_jwt(user_id=user["id"], username=user["username"], role=user["role"])
    return jsonify({"message": "로그인 성공", "access_token": token}), 200

@app.route("/profile", methods=["GET"])
def profile():
    """
    예시: Authorization: Bearer <JWT>
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "헤더에 Bearer 토큰이 필요합니다."}), 401

    token = auth_header.split(" ")[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
        # 예시 리턴: 사용자 정보
        return jsonify({
            "user_id": decoded["sub"],
            "username": decoded["username"],
            "role": decoded["role"]
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "토큰이 만료되었습니다."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "유효하지 않은 토큰입니다."}), 401

if __name__ == "__main__":
    # 로컬 테스트용
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
