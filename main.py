import os
import datetime
import mysql.connector
import traceback
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from bcrypt import hashpw, gensalt, checkpw
import jwt

app = Flask(__name__)
CORS(
    app,
    supports_credentials=True,
    origins="*"  # dev 중이면 이 origin, 배포 때는 your.github.io
)
# 환경변수로부터 설정 읽기
DB_USER     = os.environ.get("DB_USER", "appuser")
DB_PASS     = os.environ.get("DB_PASS", "secure_app_password")
DB_NAME     = os.environ.get("DB_NAME", "myappdb")
DB_SOCKET   = os.environ.get("DB_SOCKET")   # ex) "/cloudsql/project:region:instance"
SECRET_KEY  = os.environ.get("JWT_SECRET", "change_this_in_prod")
JWT_ALGO    = "HS256"


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
    except mysql.connector.Error:
        traceback.print_exc()
        raise


def generate_jwt(user_id, username, role):
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)


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
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username   = data.get("username")
    password   = data.get("password")
    email      = data.get("email")
    categories = data.get("categories", [])

    if not username or not password or not email:
        return jsonify({"error": "username, password, email 모두 필요합니다."}), 400

    pw_hash = hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # users 테이블에 유저 저장
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (%s, %s, %s)",
            (username, pw_hash, email)
        )
        conn.commit()
        new_id = cursor.lastrowid

        # user_categories 테이블에 카테고리 저장
        for cat in categories:
            cursor.execute(
                "INSERT INTO user_categories (user_id, category) VALUES (%s, %s)",
                (new_id, cat)
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

    return jsonify({"message": "회원가입 성공", "user_id": new_id}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
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
        if not checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            return jsonify({"error": "비밀번호가 일치하지 않습니다."}), 401

        token = generate_jwt(user_id=user["id"], username=user["username"], role=user["role"])
        # HttpOnly 쿠키로 JWT 전송, 2시간 유효
        resp = make_response(jsonify({"message": "로그인 성공"}), 200)
        resp.set_cookie(
            "access_token",
            token,
            max_age=2 * 3600,
            httponly=True,
            secure=False, #배포시에 True로 돌리기
            samesite="Strict",
            path="/"
        )
        return resp

    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/logout", methods=["POST"])
def logout():
    # 쿠키 만료시켜 파기
    resp = make_response(jsonify({"message": "로그아웃 성공"}), 200)
    resp.set_cookie("access_token", "", max_age=0, path="/")
    return resp


@app.route("/profile", methods=["GET"])
def profile():
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"error": "헤더에 Bearer 토큰이 필요합니다."}), 401

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "토큰이 만료되었습니다."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "유효하지 않은 토큰입니다."}), 401

    user_id = decoded["sub"]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT username, email, role FROM users WHERE id = %s",
        (user_id,)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        return jsonify({"error": "유저 정보를 찾을 수 없습니다."}), 404

    return jsonify(row), 200


@app.route("/api/user/profile", methods=["PUT"])
def update_profile():
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"error": "헤더에 Bearer 토큰이 필요합니다."}), 401

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "토큰이 만료되었습니다."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "유효하지 않은 토큰입니다."}), 401

    user_id = decoded["sub"]
    data = request.get_json()
    username = data.get("username")
    email    = data.get("email")
    password = data.get("password", None)

    if not username or not email:
        return jsonify({"error": "username과 email은 필수입니다."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE users SET username=%s, email=%s WHERE id=%s",
            (username, email, user_id)
        )
        if password:
            pw_hash = hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")
            cursor.execute(
                "UPDATE users SET password_hash=%s WHERE id=%s",
                (pw_hash, user_id)
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

    return jsonify({"message": "프로필이 업데이트되었습니다."}), 200


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

    user_id = decoded["sub"]
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "GET":
        cursor.execute(
            "SELECT category FROM user_categories WHERE user_id=%s",
            (user_id,)
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({"categories": [r[0] for r in rows]}), 200

    # PUT
    data = request.get_json()
    categories = data.get("categories", [])
    try:
        cursor.execute("DELETE FROM user_categories WHERE user_id=%s", (user_id,))
        for cat in categories:
            cursor.execute(
                "INSERT INTO user_categories (user_id, category) VALUES (%s, %s)",
                (user_id, cat)
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

    return jsonify({"message": "카테고리가 업데이트되었습니다."}), 200

@app.route("/api/issues", methods=["GET"])
def list_issues():
    """
    Query params:
      - limit (int, default=20)
      - offset (int, default=0)
    Response:
      [
        {
          "id": 8,
          "date": "2025-06-08T12:09:35",
          "issue_name": "다양한 주제의 사회 및 스포츠 뉴스",
          "summary": "...",
          "related_news": [
            {
              "id": "54706f86490805050b9a33899ac5ab30",
              "title": "...",
              "content": "...",
              "published_at": "2025-06-08T11:00:00"
            },
            ...
          ]
        },
        ...
      ]
    """
    # 1) 파라미터 파싱
    try:
        limit = int(request.args.get("limit", 20))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return jsonify({"error": "limit, offset은 정수여야 합니다."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2) issues 조회
    cursor.execute("""
      SELECT id, `date`, issue_name, summary, related_news_list
      FROM issues
      ORDER BY `date` DESC
      LIMIT %s OFFSET %s
    """, (limit, offset))
    issue_rows = cursor.fetchall()

    issues = []
    # 3) 각 이슈마다 related_news_list 파싱 + 상세 뉴스 조회
    for iid, dt, name, summary, related_list in issue_rows:
        related_news = []
        if related_list:
            # ID 문자열이 "id1,id2,..." 형식이라면 split(',')
            for nid in related_list.split(','):
                # 뉴스 상세 조회
                cursor.execute(
                    "SELECT id, title, content, published_at FROM news WHERE id=%s",
                    (nid,)
                )
                news_row = cursor.fetchone()
                if news_row:
                    nid2, title, content, pub = news_row
                    related_news.append({
                        "id": nid2,
                        "title": title,
                        "content": content,
                        "published_at": pub.isoformat()
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
