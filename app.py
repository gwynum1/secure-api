import jwt
import bcrypt
from flask import Flask, request, jsonify
from markupsafe import escape
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = 'change-me-in-production'
db = SQLAlchemy(app)

# ---------- 数据模型 ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(80))
    title = db.Column(db.String(200))
    content = db.Column(db.Text)

# ---------- 工具函数 ----------
def generate_token(user_id):
    return jwt.encode({'user_id': user_id}, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'missing token'}), 401
        try:
            # 去掉 "Bearer " 前缀
            token = token.replace('Bearer ', '')
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except Exception:
            return jsonify({'error': 'invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return wrapper

# ---------- 1) 登录接口 ----------
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    # SQLAlchemy ORM = 参数化查询，天然防 SQLi
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return jsonify({'token': generate_token(user.id)}), 200
    return jsonify({'error': 'wrong credentials'}), 401

# ---------- 2) 受保护的数据接口 ----------
@app.route('/api/data', methods=['GET'])
@token_required
def get_data(current_user):
    posts = Post.query.all()
    result = []
    for p in posts:
        # escape() 转义所有返回给前端的用户数据 -> 防 XSS
        result.append({
            'id': p.id,
            'author': escape(p.author),
            'title': escape(p.title),
            'content': escape(p.content)
        })
    return jsonify(result), 200

# ---------- 3) 自己设计的第三个接口：注册用户 ----------
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    # bcrypt 加盐哈希，绝不存明文
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = User(username=username, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'registered'}), 201

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # 预置一个测试用户
        if not User.query.filter_by(username='admin').first():
            h = bcrypt.hashpw('secret123'.encode(), bcrypt.gensalt()).decode()
            db.session.add(User(username='admin', password_hash=h))
            db.session.commit()
        # 预置几条数据
        if Post.query.count() == 0:
            db.session.add(Post(author='admin', title='hello', content='world'))
            db.session.commit()
    app.run(debug=True)
