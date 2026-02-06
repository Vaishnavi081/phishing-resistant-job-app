"""
models.py - MVP Database Models
UPDATED to match merged app.py structure
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'user'  # CHANGED from 'users' to 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    company_name = db.Column(db.String(100))
    
    # ===== ADD YOUR ENHANCED FIELDS =====
    username = db.Column(db.String(80), unique=True)
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(200))
    last_login = db.Column(db.DateTime)
    
    # Relationships
    jobs = db.relationship('Job', backref='employer_user', lazy=True)
    reports = db.relationship('Report', backref='reporter', lazy=True)
    applications = db.relationship('Application', backref='applicant', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    
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

class Job(db.Model):
    __tablename__ = 'job'  # CHANGED from 'jobs' to 'job'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    company = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    apply_link = db.Column(db.String(500))
    risk_score = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='pending')
    attachment_path = db.Column(db.String(500))
    location = db.Column(db.String(100))
    job_type = db.Column(db.String(20))
    reports_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # ===== ADD YOUR ENHANCED FIELDS =====
    requirements = db.Column(db.Text)
    salary_min = db.Column(db.Integer)
    salary_max = db.Column(db.Integer)
    salary_currency = db.Column(db.String(10), default='USD')
    experience_level = db.Column(db.String(50))
    industry = db.Column(db.String(100))
    tags = db.Column(db.String(500))
    is_active = db.Column(db.Boolean, default=True)
    is_featured = db.Column(db.Boolean, default=False)
    application_deadline = db.Column(db.DateTime)
    views_count = db.Column(db.Integer, default=0)
    applications_count = db.Column(db.Integer, default=0)
    
    # Foreign key - CHANGED to reference 'user.id' not 'users.id'
    employer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    reports = db.relationship('Report', backref='job_report', lazy=True)
    applications = db.relationship('Application', backref='job', lazy=True)
    
    def get_risk_badge(self):
        if self.risk_score < 30:
            return '🟢 Safe'
        elif self.risk_score < 70:
            return '🟡 Caution'
        else:
            return '🔴 High Risk'
    
    @property
    def salary_range(self):
        if self.salary_min and self.salary_max:
            return f"{self.salary_currency} {self.salary_min:,} - {self.salary_max:,}"
        elif self.salary_min:
            return f"{self.salary_currency} {self.salary_min:,}+"
        return "Negotiable"
    
    def __repr__(self):
        return f'<Job {self.title} at {self.company}>'

class Report(db.Model):
    __tablename__ = 'report'  # CHANGED from 'reports' to 'report'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'))  # CHANGED to 'job.id'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # CHANGED to 'user.id'
    reason = db.Column(db.String(50), nullable=False)
    comment = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # ===== ADD YOUR ENHANCED FIELDS =====
    user_ip = db.Column(db.String(45))
    votes = db.Column(db.Integer, default=1)
    
    def __repr__(self):
        return f'<Report for Job {self.job_id}>'

class Blacklist(db.Model):
    __tablename__ = 'blacklist'  # CHANGED from 'blacklists' to 'blacklist'
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(100))
    email = db.Column(db.String(120))
    reason = db.Column(db.Text, nullable=False)
    added_by = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Blacklist {self.domain or self.email}>'

# ===== ADD YOUR NEW MODELS =====

class Application(db.Model):
    __tablename__ = 'application'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    applicant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cover_letter = db.Column(db.Text)
    resume_path = db.Column(db.String(200))
    status = db.Column(db.String(50), default='pending')
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    
    __table_args__ = (db.UniqueConstraint('job_id', 'applicant_id', name='_job_applicant_uc'),)
    
    def __repr__(self):
        return f'<Application {self.id} for Job {self.job_id}>'

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<AuditLog {self.action} by User {self.user_id}>'

def init_database():
    """Initialize database with admin user"""
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(email='admin@jobportal.com').first():
        admin = User(
            email='admin@jobportal.com',
            role='admin',
            verified=True,
            company_name='SecureJob Admin',
            full_name='System Administrator'
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
            company_name='Tech Corp',
            full_name='Jane Employer'
        )
        employer.set_password('employer123')
        db.session.add(employer)
    
    # Create test student
    if not User.query.filter_by(email='student@example.com').first():
        student = User(
            email='student@example.com',
            role='student',
            verified=True,
            full_name='John Student'
        )
        student.set_password('student123')
        db.session.add(student)
    
    db.session.commit()
    print("✅ Database initialized with test users")
    return True
