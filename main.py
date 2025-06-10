import os
import datetime
import mysql.connector
import traceback
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from bcrypt import hashpw, gensalt, checkpw
import jwt

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["https://newsassistantsasa.com", "http://localhost:8080"])

# 환경변수 설정
DB_USER   = os.environ.get("DB_USER", "appuser")
DB_PASS   = os.environ.get("DB_PASS", "secure_app_password")
DB_NAME   = os.environ.get("DB_NAME", "myappdb")
DB_SOCKET = os.environ.get("DB_SOCKET")  # ex: "/cloudsql/project:region:instance"
SECRET_KEY = os.environ.get("JWT_SECRET", "change_this_in_prod")
JWT_ALGO   = "HS256"

# DB 연결 함수
def get_db_connection():
    try:
        if DB_SOCKET:
            return mysql.connector.connect(
                user=DB_USER, password=DB_PASS,
                database=DB_NAME, unix_socket=DB_SOCKET
            )
        return mysql.connector.connect(
            user=DB_USER, password=DB_PASS,
            database=DB_NAME, host="127.0.0.1", port=3306
        )
    except mysql.connector.Error:
        traceback.print_exc()
        raise

# JWT 생성 함수
def generate_jwt(user_id, username, role):
    payload = {
        "sub": str(user_id),
        "username": str(username),
        "role": str(role),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)

# 테스트 DB 연결
@app.route("/test-db")
def test_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT NOW()")
        now = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return jsonify({"db_time": str(now)})
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

# 회원가입
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    email    = data.get("email")
    categories = data.get("categories", [])
    if not username or not password or not email:
        return jsonify({"error": "username, password, email 모두 필요합니다."}), 400

    pw_hash = hashpw(password.encode(), gensalt()).decode()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (%s, %s, %s)",
            (username, pw_hash, email)
        )
        conn.commit()
        user_id = cursor.lastrowid
        for cat in categories:
            cursor.execute(
                "INSERT INTO user_categories (user_id, category) VALUES (%s, %s)",
                (user_id, cat)
            )
        conn.commit()
    except mysql.connector.errors.IntegrityError:
        conn.rollback()
        return jsonify({"error": "이미 존재하는 username 또는 email입니다."}), 409
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
    return jsonify({"message": "회원가입 성공", "user_id": user_id}), 201

# 로그인
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "username과 password가 필요합니다."}), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username=%s",
            (username,)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if not user:
            return jsonify({"error": "유저 정보를 찾을 수 없습니다."}), 404
        if not checkpw(password.encode(), user['password_hash'].encode()):
            return jsonify({"error": "비밀번호가 일치하지 않습니다."}), 401
        token = generate_jwt(user['id'], user['username'], user['role'])
        resp = make_response(jsonify({"message": "로그인 성공"}), 200)
        resp.set_cookie("access_token", token,
                        max_age=2*3600, httponly=True,
                        secure=True, samesite="None", path="/")
        return resp
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

# 로그아웃
@app.route("/logout", methods=["POST"])
def logout():
    resp = make_response(jsonify({"message": "로그아웃 성공"}), 200)
    resp.set_cookie("access_token", "", max_age=0, httponly=True,
                secure=True, samesite="None", path="/")
    return resp

# 프로필 조회
@app.route("/profile", methods=["GET"])
def profile():
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"error": "로그인이 필요합니다."}), 401
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "토큰이 만료되었습니다."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "유효하지 않은 토큰입니다.", "token" : token}), 401
    user_id = int(decoded['sub'])
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT username, email, role FROM users WHERE id=%s", (user_id,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if not row:
        return jsonify({"error": "유저 정보를 찾을 수 없습니다."}), 404
    return jsonify(row), 200

# 프로필 업데이트
@app.route("/api/user/profile", methods=["PUT"])
def update_profile():
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"error": "로그인이 필요합니다."}), 401
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "토큰이 만료되었습니다."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "유효하지 않은 토큰입니다."}), 401
    user_id = int(decoded['sub'])
    data = request.get_json() or {}
    username = data.get("username")
    email    = data.get("email")
    password = data.get("password")
    if not username or not email:
        return jsonify({"error": "username과 email은 필수입니다."}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET username=%s, email=%s WHERE id=%s",
                       (username, email, user_id))
        if password:
            pw_hash = hashpw(password.encode(), gensalt()).decode()
            cursor.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                           (pw_hash, user_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
    return jsonify({"message": "프로필 업데이트 성공"}), 200

# 카테고리 조회/수정
@app.route("/api/user/categories", methods=["GET", "PUT"])
def user_categories():
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"error": "로그인이 필요합니다."}), 401
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "토큰이 만료되었습니다."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "유효하지 않은 토큰입니다."}), 401
    user_id = int(decoded['sub'])
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT category FROM user_categories WHERE user_id=%s", (user_id,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({"categories": [r[0] for r in rows]}), 200
    # PUT
    data = request.get_json() or {}
    categories = data.get("categories", [])
    try:
        cursor.execute("DELETE FROM user_categories WHERE user_id=%s", (user_id,))
        for cat in categories:
            cursor.execute("INSERT INTO user_categories (user_id, category) VALUES (%s, %s)", (user_id, cat))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
    return jsonify({"message": "카테고리 업데이트 성공"}), 200

@app.route("/api/issues", methods=["GET"])
def list_issues():
    try:
        # limit/offset 파싱
        try:
            limit = int(request.args.get("limit", 20))
            offset = int(request.args.get("offset", 0))
        except ValueError:
            return jsonify({"error": "limit, offset은 정수여야 합니다."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, `date`, issue_name, summary, related_news_list
              FROM issues
             ORDER BY `date` DESC
             LIMIT %s OFFSET %s
        """, (limit, offset))
        issue_rows = cursor.fetchall()

        issues = []
        for iid, dt, name, summary, related_list in issue_rows:
            related_news = []
            if related_list:
                for art_id in related_list.split():
                    cursor.execute("""
                        SELECT
                          link,
                          article_id,
                          title,
                          description,
                          content,
                          pub_date,
                          image_url         -- 여기에 image_url 추가
                        FROM news_articles
                       WHERE article_id = %s
                    """, (art_id,))
                    row = cursor.fetchone()
                    if row:
                        article_id, title, description, content, pub_date, image_url = row
                        related_news.append({
                            "article_id": article_id,
                            "title": title,
                            "description": description,
                            "content": content,
                            "published_at": pub_date.isoformat() if hasattr(pub_date, 'isoformat') else str(pub_date),
                            "image_url": image_url    # JSON에도 포함
                        })

            issues.append({
                "id": iid,
                "date": dt.isoformat(),
                "issue_name": name,
                "summary": summary,
                "related_news": related_news
            })

        cursor.close()
        conn.close()
        return jsonify(issues), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route('/click-event', methods=['POST'])
def click_event():
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"error": "로그인이 필요합니다."}), 401
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "토큰이 만료되었습니다."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "유효하지 않은 토큰입니다."}), 401
    user_id = int(decoded['sub'])

    Q = request.get_json(silent=True) or {}

    issue_id = Q.get("issue_id")
    
    if not issue_id:
        return jsonify({"error" : "issue_id missing"}), 400
    
    issue_id = int(issue_id)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""INSERT INTO custom_events (eventname, user_id, issue_id) VALUES (%s, %s, %s)""", ("click", user_id, issue_id))

    conn.commit()

    cursor.close()
    conn.close()
    
    return jsonify({"message": "클릭 이벤트 전달 성공"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
