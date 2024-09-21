from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from flask_mail import Mail, Message
import mysql.connector
import random
import string
from datetime import datetime, timedelta  # timedelta 추가
import os
from subprocess import Popen, PIPE, run


# 업로드 폴더 경로 설정
UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'mp4', 'mov', 'avi'}


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # 이메일 서버 설정 (Gmail 사용 예시)
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dntmdgns03@gmail.com'  # 발신자 이메일
app.config['MAIL_PASSWORD'] = 'qsui vner xrph lszl'
app.secret_key = 'super_secret_key'  # 세션을 위한 비밀 키 설정

mail = Mail(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# 허용된 파일 확장자 확인 함수
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# MySQL 연결 설정
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Dntmdgns01~",
    database="user_database"
)
cursor = db.cursor()


# 이메일로 인증 코드 전송 함수
def send_verification_email(email, code):
    msg = Message('이메일 인증 코드', sender='dntmdgns03@gmail.com', recipients=[email])
    msg.body = f"인증 코드: {code}\n3분 내에 입력해 주세요."
    mail.send(msg)


# 인증 코드 생성 함수
def generate_verification_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))


# 홈 페이지 라우트
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # GET 요청 처리: login.html 반환
        return render_template('login.html')

    if request.method == 'POST':
        # POST 요청 처리: 로그인 시도
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify(message="아이디 또는 비밀번호가 입력되지 않았습니다."), 400

        # DB에서 사용자 조회
        cursor.execute('SELECT username, password FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[1], password):
            session['username'] = user[0]
            session['logged_in'] = True
            session['sessionid'] = create_access_token(identity={'username': user[0]})
            return jsonify(sessionid=session['sessionid'], message="로그인 성공", redirect='/'), 200
        else:
            return jsonify(message="아이디 또는 비밀번호가 잘못되었습니다."), 401



# 회원가입 GET & POST 처리
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        # GET 요청 처리: signup.html을 반환하여 회원가입 폼을 표시
        return render_template('signup.html')

    elif request.method == 'POST':
        data = request.get_json()

        username = data.get('username')
        email = data.get('email')
        password = data.get('password').strip()

        # 이메일 중복 체크
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user_by_email = cursor.fetchone()
        if user_by_email:
            return jsonify({"message": "이미 존재하는 이메일입니다."}), 409

        # 비밀번호 해싱
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # 인증 코드 생성 및 세션에 저장
        verification_code = generate_verification_code()
        session['verification_code'] = verification_code
        session['verification_expiry'] = (datetime.now() + timedelta(minutes=3)).isoformat()

        # 이메일로 인증 코드 전송
        send_verification_email(email, verification_code)

        # 회원가입 정보 세션에 저장 (DB 저장 X, 인증 후 저장 예정)
        session['signup_data'] = {
            'username': username,
            'email': email,
            'password': hashed_password
        }

        return jsonify({"message": "인증 코드가 이메일로 전송되었습니다. 3분 내에 입력해 주세요."}), 200


# 인증 코드 검증 GET & POST 처리
@app.route('/verify', methods=['GET', 'POST'])
def verify_page():
    if request.method == 'GET':
        # GET 요청 처리: verify.html을 반환하여 인증 코드 입력 폼을 표시
        return render_template('verify.html')

    elif request.method == 'POST':
        data = request.get_json()
        input_code = data.get('code')

        # 세션에서 인증 코드 및 만료 시간 가져오기
        verification_code = session.get('verification_code')
        verification_expiry = session.get('verification_expiry')

        if not verification_code or not verification_expiry:
            return jsonify({"message": "인증 코드가 만료되었거나 존재하지 않습니다."}), 400

        # 세션에서 가져온 verification_expiry 문자열을 datetime 객체로 변환
        verification_expiry = datetime.fromisoformat(verification_expiry)

        # 현재 시간과 비교
        current_time = datetime.now()

        if current_time > verification_expiry:
            return jsonify({"message": "인증 코드가 만료되었습니다."}), 400

        if input_code == verification_code:
            # 사용자 정보 DB에 저장 (인증 완료 시점에 저장)
            signup_data = session.get('signup_data')
            cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
                           (signup_data['username'], signup_data['email'], signup_data['password']))
            db.commit()

            # 세션에서 데이터 삭제
            session.pop('verification_code', None)
            session.pop('signup_data', None)
            session.pop('verification_expiry', None)

            return jsonify({"message": "회원가입이 완료되었습니다.", "redirect": "/"}), 201
        else:
            return jsonify({"message": "인증 코드가 잘못되었습니다."}), 400

# 로그아웃 라우트
@app.route('/logout')
def logout():
    session.clear()
    return jsonify(message="로그아웃 성공"), 200



ALLOWED_EXTENSIONS = {'mp4'}

# 업로드 허용되는 파일 형식 확인 함수
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# test.py 스크립트를 subprocess로 실행하는 함수
def run_test_script(file_path):
    try:
        process = run(['python3', './hack/test.py', file_path], stdout=PIPE, stderr=PIPE)
        if process.returncode == 0:
            result_message = process.stdout.decode('utf-8')  # subprocess의 stdout 처리
            return {'success': True, 'result_message': result_message}
        else:
            error_message = process.stderr.decode('utf-8')  # subprocess의 stderr 처리
            return {'success': False, 'error_message': error_message}
    except Exception as e:
        return {'success': False, 'error_message': str(e)}

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'GET':
        # GET 요청 시: 업로드 페이지 렌더링
        return render_template('upload.html')  # 업로드 페이지 렌더링
    
    if 'file' not in request.files:
        return jsonify({'message': '파일이 없습니다.'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'message': '파일이 선택되지 않았습니다.'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # 여기에서 test.py 실행
        script_path = os.path.abspath('./test.py')
        full_video_path = os.path.abspath(file_path)

        process = run(['python3', script_path, full_video_path], stdout=PIPE, stderr=PIPE)
        print(f"파일 경로: {full_video_path}")  # 디버깅용 파일 경로 출력

        if process.returncode == 0:
            # 성공적으로 실행된 경우
            result_message = process.stdout.decode('utf-8')
            print(f"test.py 결과: {result_message}")
            return jsonify({'message': '파일이 성공적으로 업로드되었습니다.', 'result': result_message}), 200
        else:
            # 오류 발생 시
            error_message = process.stderr.decode('utf-8')
            print(f"Error: {error_message}")  # 에러 메시지 출력
            return jsonify({'message': f'파일 업로드는 성공했지만 처리 중 오류가 발생했습니다: {error_message}'}), 500

    return jsonify({'message': '허용되지 않는 파일 형식입니다.'}), 400



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    app = Flask(__name__, static_folder='static')
