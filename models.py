"""
models.py - MVP Database Models
Person 1 Responsibility: Create ALL database tables
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # student/employer/admin
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    company_name = db.Column(db.String(100))
    
    # Relationships
    jobs = db.relationship('Job', backref='employer', lazy=True)
    reports = db.relationship('Report', backref='reporter', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_employer(self):
        return self.role == 'employer'
    
    def is_student(self):
        return self.role == 'student'
    
    def __repr__(self):
        return f'<User {self.email}>'

# ========== JOB MODEL ==========
class Job(db.Model):
    __tablename__ = 'jobs'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    company = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    apply_link = db.Column(db.String(500))
    risk_score = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='pending')  # pending/approved/flagged/removed
    attachment_path = db.Column(db.String(500))
    location = db.Column(db.String(100))
    job_type = db.Column(db.String(20))  # intern/full-time
    reports_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign key
    employer_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    def get_risk_badge(self):
        if self.risk_score < 30:
            return '🟢 Safe'
        elif self.risk_score < 70:
            return '🟡 Caution'
        else:
            return '🔴 High Risk'
    
    def __repr__(self):
        return f'<Job {self.title} at {self.company}>'

# ========== REPORT MODEL ==========
class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    reason = db.Column(db.String(50), nullable=False)
    comment = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending/reviewed/resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Report for Job {self.job_id}>'

# ========== BLACKLIST MODEL ==========
class Blacklist(db.Model):
    __tablename__ = 'blacklists'
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(100))
    email = db.Column(db.String(120))
    reason = db.Column(db.Text, nullable=False)
    added_by = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Blacklist {self.domain or self.email}>'

# ========== HELPER FUNCTIONS ==========
def init_database():
    """Initialize database with admin user"""
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(email='admin@jobportal.com').first():
        admin = User(
            email='admin@jobportal.com',
            role='admin',
            verified=True,
            company_name='SecureJob Admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("✅ Created admin user: admin@jobportal.com / admin123")
    
    # Create test employer
    if not User.query.filter_by(email='employer@example.com').first():
        employer = User(
            email='employer@example.com',
            role='employer',
            verified=True,
            company_name='Tech Corp'
        )
        employer.set_password('employer123')
        db.session.add(employer)
    
    # Create test student
    if not User.query.filter_by(email='student@example.com').first():
        student = User(
            email='student@example.com',
            role='student',
            verified=True
        )
        student.set_password('student123')
        db.session.add(student)
    
    db.session.commit()
    print("✅ Database initialized with test users")
    return True

