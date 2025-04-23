# file: app_test.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# ✅ Correct config using SQLAlchemy and PyMySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/new_task'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret123'

# ✅ Initialize SQLAlchemy
db = SQLAlchemy(app)

# ✅ Sample table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)

@app.route('/')
def index():
    try:
        db.create_all()
        return "✅ Flask connected to MySQL DB 'new_task' successfully!"
    except Exception as e:
        return f"❌ Error: {e}"

if __name__ == '__main__':
    app.run(debug=True)
