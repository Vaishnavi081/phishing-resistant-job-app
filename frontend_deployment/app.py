"""
MVP Flask Application - Person 3
ENHANCED with complete job application system
Merged by: [Your Name] - Backend Developer
"""

import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import bleach
import json

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

# ==================== ENHANCED DATABASE MODELS ====================
class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')  # student/employer/admin
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    company_name = db.Column(db.String(100))
    
    # ===== ENHANCED FIELDS (Your additions) =====
    username = db.Column(db.String(80), unique=True)
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(200))
    last_login = db.Column(db.DateTime)
    
    # Relationships
    jobs = db.relationship('Job', backref='employer_user', lazy=True)
    applications = db.relationship('Application', backref='applicant', lazy=True)  # Your addition
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)  # Your addition
    
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
    
    # Required by Flask-Login
    def get_id(self):
        return str(self.id)
    
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_active(self):
        return True
    
    @property
    def is_anonymous(self):
        return False

class Job(db.Model):
    __tablename__ = 'job'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    company = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    apply_link = db.Column(db.String(500))
    risk_score = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='pending')
    location = db.Column(db.String(100))
    job_type = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    employer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # ===== ENHANCED FIELDS (Your additions) =====
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
    
    # Relationships
    reports = db.relationship('Report', backref='job_report', lazy=True)
    applications = db.relationship('Application', backref='job', lazy=True)  # Your addition
    
    def get_risk_badge(self):
        if self.risk_score < 30:
            return ('🟢 Safe', 'success')
        elif self.risk_score < 70:
            return ('🟡 Caution', 'warning')
        else:
            return ('🔴 High Risk', 'danger')
    
    @property
    def salary_range(self):
        """Your enhancement"""
        if self.salary_min and self.salary_max:
            return f"{self.salary_currency} {self.salary_min:,} - {self.salary_max:,}"
        elif self.salary_min:
            return f"{self.salary_currency} {self.salary_min:,}+"
        return "Negotiable"

class Report(db.Model):
    __tablename__ = 'report'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'))
    user_ip = db.Column(db.String(45), nullable=False)
    reason = db.Column(db.String(50), nullable=False)
    votes = db.Column(db.Integer, default=1)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ===== NEW MODELS (Your additions) =====
class Application(db.Model):
    __tablename__ = 'application'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    applicant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cover_letter = db.Column(db.Text)
    resume_path = db.Column(db.String(200))
    status = db.Column(db.String(50), default='pending')  # pending, reviewed, accepted, rejected
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    
    # Ensure unique application per job per applicant
    __table_args__ = (db.UniqueConstraint('job_id', 'applicant_id', name='_job_applicant_uc'),)

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== ENHANCED FORMS (Your additions) ====================
class EnhancedJobForm(FlaskForm):
    """Enhanced job posting form with your fields"""
    title = StringField('Job Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    requirements = TextAreaField('Requirements')
    company = StringField('Company Name', validators=[DataRequired()])
    email = StringField('Contact Email', validators=[DataRequired(), Email()])
    apply_link = StringField('Application Link')
    location = StringField('Location', validators=[Length(max=100)])
    job_type = SelectField('Job Type', choices=[
        ('full-time', 'Full Time'),
        ('part-time', 'Part Time'),
        ('contract', 'Contract'),
        ('remote', 'Remote'),
        ('hybrid', 'Hybrid')
    ], default='full-time')
    
    # Your enhanced fields
    salary_min = IntegerField('Minimum Salary', validators=[NumberRange(min=0)])
    salary_max = IntegerField('Maximum Salary', validators=[NumberRange(min=0)])
    salary_currency = SelectField('Currency', choices=[
        ('USD', 'US Dollar'),
        ('EUR', 'Euro'),
        ('GBP', 'British Pound'),
        ('INR', 'Indian Rupee')
    ], default='USD')
    experience_level = SelectField('Experience Level', choices=[
        ('entry', 'Entry Level'),
        ('mid', 'Mid Level'),
        ('senior', 'Senior Level'),
        ('executive', 'Executive')
    ], default='mid')
    industry = StringField('Industry')
    application_deadline = StringField('Application Deadline (YYYY-MM-DD)')

class ApplicationForm(FlaskForm):
    """Your application form"""
    cover_letter = TextAreaField('Cover Letter', validators=[DataRequired()])

class ProfileForm(FlaskForm):
    """Your profile form"""
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[Length(max=20)])
    bio = TextAreaField('Bio')

# ==================== HELPER FUNCTIONS ====================
def log_audit(action, details=None, user_id=None):
    """Your audit logging function"""
    if user_id is None and current_user.is_authenticated:
        user_id = current_user.id
    
    log = AuditLog(
        user_id=user_id,
        action=action,
        details=json.dumps(details) if details else None,
        ip_address=request.remote_addr if request else None,
        user_agent=request.user_agent.string if request else None
    )
    db.session.add(log)
    db.session.commit()

# ==================== MAIN APPLICATION ====================
def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
    app.config['UPLOAD_FOLDER'] = 'static/uploads'
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    
    # Login manager config
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # ==================== ENHANCED ROUTES ====================
    
    # Keep all Person 3's original routes (they're already good)
    # I'll just show the NEW routes to add
    
    @app.route('/')
    def index():
        """Enhanced home page with stats"""
        jobs = Job.query.filter_by(status='approved', is_active=True).order_by(Job.created_at.desc()).limit(6).all()
        stats = {
            'total_jobs': Job.query.filter_by(status='approved', is_active=True).count(),
            'total_companies': User.query.filter_by(role='employer', verified=True).count(),
            'total_applications': Application.query.count() if 'application' in [table.name for table in db.metadata.tables.values()] else 0
        }
        return render_template('index.html', jobs=jobs, stats=stats)
    
    # Keep Person 3's original login, register, logout routes
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        """Enhanced dashboard based on role"""
        if current_user.is_admin():
            # Enhanced admin dashboard
            stats = {
                'total_users': User.query.count(),
                'total_jobs': Job.query.count(),
                'total_applications': Application.query.count() if 'application' in [table.name for table in db.metadata.tables.values()] else 0,
                'pending_jobs': Job.query.filter_by(status='pending').count()
            }
            return render_template('admin.html', stats=stats)
        
        elif current_user.is_employer():
            # Enhanced employer dashboard
            jobs = Job.query.filter_by(employer_id=current_user.id).all()
            total_applications = Application.query.filter(
                Application.job_id.in_([job.id for job in jobs])
            ).count() if 'application' in [table.name for table in db.metadata.tables.values()] else 0
            return render_template('dashboard.html', jobs=jobs, total_applications=total_applications)
        
        else:
            # Enhanced student/applicant dashboard
            applications = Application.query.filter_by(applicant_id=current_user.id).all() if 'application' in [table.name for table in db.metadata.tables.values()] else []
            return render_template('dashboard.html', applications=applications)
    
    # ===== NEW ROUTES (Your additions) =====
    
    @app.route('/profile', methods=['GET', 'POST'])
    @login_required
    def profile():
        """Your profile page"""
        form = ProfileForm(obj=current_user)
        
        if form.validate_on_submit():
            current_user.full_name = form.full_name.data
            current_user.email = form.email.data
            current_user.phone = form.phone.data
            current_user.bio = form.bio.data
            
            db.session.commit()
            log_audit('profile_update')
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        
        return render_template('profile.html', form=form)
    
    @app.route('/jobs')
    @login_required
    def jobs():
        """Enhanced job listings with filtering"""
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        # Filter parameters
        job_type = request.args.get('type')
        location = request.args.get('location')
        experience = request.args.get('experience')
        
        query = Job.query.filter_by(status='approved', is_active=True)
        
        if job_type:
            query = query.filter_by(job_type=job_type)
        if location:
            query = query.filter(Job.location.ilike(f'%{location}%'))
        if experience:
            query = query.filter_by(experience_level=experience)
        
        jobs = query.order_by(Job.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        
        return render_template('jobs.html', jobs=jobs)
    
    @app.route('/job/<int:job_id>/apply', methods=['GET', 'POST'])
    @login_required
    def apply_job(job_id):
        """Your job application route"""
        if not current_user.is_student():
            flash('Only students can apply for jobs', 'danger')
            return redirect(url_for('job_detail', job_id=job_id))
        
        job = Job.query.get_or_404(job_id)
        
        # Check if already applied
        existing_application = Application.query.filter_by(
            job_id=job_id,
            applicant_id=current_user.id
        ).first() if 'application' in [table.name for table in db.metadata.tables.values()] else None
        
        if existing_application:
            flash('You have already applied for this job', 'warning')
            return redirect(url_for('job_detail', job_id=job_id))
        
        form = ApplicationForm()
        if form.validate_on_submit():
            application = Application(
                job_id=job_id,
                applicant_id=current_user.id,
                cover_letter=form.cover_letter.data,
                status='pending'
            )
            
            # Handle resume upload
            if 'resume' in request.files:
                resume = request.files['resume']
                if resume.filename != '':
                    # Save resume
                    filename = f"resume_{current_user.id}_{job_id}_{datetime.utcnow().timestamp()}.pdf"
                    resume_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                    resume.save(resume_path)
                    application.resume_path = resume_path
            
            db.session.add(application)
            db.session.commit()
            
            log_audit('job_application', {'job_id': job_id, 'job_title': job.title})
            flash('Application submitted successfully!', 'success')
            return redirect(url_for('job_detail', job_id=job_id))
        
        return render_template('apply.html', job=job, form=form)
    
    @app.route('/post-job-enhanced', methods=['GET', 'POST'])
    @login_required
    def post_job_enhanced():
        """Enhanced job posting with your fields"""
        if not current_user.is_employer():
            flash('Only employers can post jobs', 'danger')
            return redirect(url_for('dashboard'))
        
        form = EnhancedJobForm()
        if form.validate_on_submit():
            # Sanitize inputs
            title = bleach.clean(form.title.data)
            description = bleach.clean(form.description.data)
            company = bleach.clean(form.company.data)
            email = bleach.clean(form.email.data.lower())
            apply_link = bleach.clean(form.apply_link.data) if form.apply_link.data else ''
            location = bleach.clean(form.location.data) if form.location.data else ''
            
            # Risk scoring (Person 3's logic)
            risk_score = 0
            if 'bit.ly' in apply_link or 'tinyurl' in apply_link:
                risk_score += 30
            if 'urgent' in description.lower():
                risk_score += 20
            if 'crypto' in description.lower():
                risk_score += 25
            
            # Check email domain
            if not email.endswith(('.com', '.org', '.edu', '.net')):
                risk_score += 30
            
            # Create job with enhanced fields
            job = Job(
                title=title,
                description=description,
                requirements=bleach.clean(form.requirements.data) if form.requirements.data else '',
                company=company,
                email=email,
                apply_link=apply_link,
                risk_score=min(risk_score, 100),
                status='rejected' if risk_score > 70 else 'pending',
                location=location,
                job_type=form.job_type.data,
                employer_id=current_user.id,
                
                # Your enhanced fields
                salary_min=form.salary_min.data,
                salary_max=form.salary_max.data,
                salary_currency=form.salary_currency.data,
                experience_level=form.experience_level.data,
                industry=bleach.clean(form.industry.data) if form.industry.data else '',
                is_active=True
            )
            
            # Handle deadline
            if form.application_deadline.data:
                try:
                    job.application_deadline = datetime.strptime(form.application_deadline.data, '%Y-%m-%d')
                except ValueError:
                    flash('Invalid date format. Use YYYY-MM-DD', 'danger')
                    return render_template('post_job.html', form=form)
            
            db.session.add(job)
            db.session.commit()
            
            log_audit('job_posted', {'job_id': job.id, 'title': job.title})
            
            if risk_score > 70:
                flash('Job rejected due to high risk score', 'danger')
            elif risk_score > 40:
                flash('Job posted for admin review', 'warning')
            else:
                flash('Job posted successfully!', 'success')
            
            return redirect(url_for('dashboard'))
        
        return render_template('post_job.html', form=form, enhanced=True)
    
    @app.route('/reports')
    @login_required
    def reports():
        """Your reports page"""
        if not current_user.is_admin():
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        
        # Generate report data
        report_data = {
            'user_growth': get_user_growth_report(),
            'job_statistics': get_job_statistics(),
            'application_metrics': get_application_metrics()
        }
        
        return render_template('reports.html', report_data=report_data)
    
    # ===== HELPER FUNCTIONS FOR REPORTS =====
    
    def get_user_growth_report():
        from datetime import timedelta
        days = 30
        data = []
        for i in range(days, -1, -1):
            date = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
