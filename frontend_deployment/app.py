"""
MVP Flask Application - Person 3
ENHANCED with complete job application system
Merged by: Backend Developer

USES: Person 1's models.py for database models
"""

import os
import json
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, Length, NumberRange
import bleach

# ==================== IMPORT PERSON 1'S MODELS ====================
from models import db, User, Job, Report, Application, AuditLog, Blacklist, init_database

# Initialize Flask-Login
login_manager = LoginManager()

# ==================== ENHANCED FORMS ====================
class EnhancedJobForm(FlaskForm):
    """Enhanced job posting form with additional fields"""
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
    
    # Enhanced fields
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
    """Job application form"""
    cover_letter = TextAreaField('Cover Letter', validators=[DataRequired()])

class ProfileForm(FlaskForm):
    """User profile form"""
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[Length(max=20)])
    bio = TextAreaField('Bio')
    current_password = PasswordField('Current Password (to change email/password)')
    new_password = PasswordField('New Password')
    confirm_password = PasswordField('Confirm New Password')

# ==================== HELPER FUNCTIONS ====================
def log_audit(action, details=None, user_id=None):
    """Log user actions for security audit"""
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
    
    # ==================== ROUTES ====================
    
    @app.route('/')
    def index():
        """Home page with stats"""
        jobs = Job.query.filter_by(status='approved', is_active=True).order_by(Job.created_at.desc()).limit(6).all()
        stats = {
            'total_jobs': Job.query.filter_by(status='approved', is_active=True).count(),
            'total_companies': User.query.filter_by(role='employer', verified=True).count(),
            'total_applications': Application.query.count()
        }
        return render_template('index.html', jobs=jobs, stats=stats)
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Login page"""
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            email = bleach.clean(request.form.get('email', ''))
            password = request.form.get('password', '')
            remember = bool(request.form.get('remember'))
            
            user = User.query.filter_by(email=email).first()
            
            if user and user.check_password(password):
                if not user.verified and user.role != 'admin':
                    flash('Account not verified. Please contact admin.', 'warning')
                    return redirect(url_for('login'))
                
                login_user(user, remember=remember)
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                log_audit('login', {'email': email})
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                log_audit('failed_login', {'email': email})
                flash('Invalid email or password', 'danger')
        
        return render_template('login.html')
    
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """Registration page"""
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            email = bleach.clean(request.form.get('email', '').lower())
            password = request.form.get('password', '')
            role = request.form.get('role', 'student')
            company_name = bleach.clean(request.form.get('company_name', '')) if role == 'employer' else None
            full_name = bleach.clean(request.form.get('full_name', ''))
            
            # Check if user exists
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'danger')
                return redirect(url_for('register'))
            
            # Create user
            user = User(
                email=email, 
                role=role, 
                company_name=company_name,
                full_name=full_name
            )
            user.set_password(password)
            
            # Auto-create admin for demo
            if email in ['admin@jobportal.com', 'superadmin@jobportal.com']:
                user.role = 'admin'
                user.verified = True
            
            db.session.add(user)
            db.session.commit()
            
            log_audit('registration', {'email': email, 'role': role})
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        
        return render_template('register.html')
    
    @app.route('/logout')
    @login_required
    def logout():
        """Logout user"""
        log_audit('logout')
        logout_user()
        flash('You have been logged out', 'info')
        return redirect(url_for('index'))
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        """User dashboard based on role"""
        if current_user.is_admin():
            # Admin dashboard
            stats = {
                'total_users': User.query.count(),
                'total_jobs': Job.query.count(),
                'total_applications': Application.query.count(),
                'pending_jobs': Job.query.filter_by(status='pending').count(),
                'pending_reports': Report.query.filter_by(status='pending').count()
            }
            recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()
            return render_template('admin.html', stats=stats, recent_logs=recent_logs)
        
        elif current_user.is_employer():
            # Employer dashboard
            jobs = Job.query.filter_by(employer_id=current_user.id).all()
            total_applications = Application.query.filter(
                Application.job_id.in_([job.id for job in jobs])
            ).count()
            return render_template('dashboard.html', jobs=jobs, total_applications=total_applications)
        
        else:
            # Student/Applicant dashboard
            applications = Application.query.filter_by(applicant_id=current_user.id).all()
            return render_template('dashboard.html', applications=applications)
    
    @app.route('/profile', methods=['GET', 'POST'])
    @login_required
    def profile():
        """User profile page"""
        form = ProfileForm(obj=current_user)
        
        if form.validate_on_submit():
            # Check if changing password
            if form.current_password.data:
                if not current_user.check_password(form.current_password.data):
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('profile'))
                
                if form.new_password.data != form.confirm_password.data:
                    flash('New passwords do not match', 'danger')
                    return redirect(url_for('profile'))
                
                current_user.set_password(form.new_password.data)
            
            # Update profile
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
        """Job listings with filtering"""
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
    
    @app.route('/job/<int:job_id>')
    @login_required
    def job_detail(job_id):
        """Job details page"""
        job = Job.query.get_or_404(job_id)
        
        # Increment view count
        job.views_count += 1
        db.session.commit()
        
        # Check if user has already applied
        has_applied = False
        if current_user.is_authenticated and current_user.is_student():
            has_applied = Application.query.filter_by(
                job_id=job_id,
                applicant_id=current_user.id
            ).first() is not None
        
        return render_template('job_detail.html', job=job, has_applied=has_applied)
    
    @app.route('/job/<int:job_id>/apply', methods=['GET', 'POST'])
    @login_required
    def apply_job(job_id):
        """Apply for a job"""
        if not current_user.is_student():
            flash('Only students can apply for jobs', 'danger')
            return redirect(url_for('job_detail', job_id=job_id))
        
        job = Job.query.get_or_404(job_id)
        
        # Check if already applied
        existing_application = Application.query.filter_by(
            job_id=job_id,
            applicant_id=current_user.id
        ).first()
        
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
            
            # Update job applications count
            job.applications_count += 1
            db.session.commit()
            
            log_audit('job_application', {'job_id': job_id, 'job_title': job.title})
            flash('Application submitted successfully!', 'success')
            return redirect(url_for('job_detail', job_id=job_id))
        
        return render_template('apply.html', job=job, form=form)
    
    @app.route('/post-job', methods=['GET', 'POST'])
    @login_required
    def post_job():
        """Post a new job (enhanced version)"""
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
            
            # Risk scoring
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
            
            # Create job
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
                
                # Enhanced fields
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
                    return render_template('post_job.html', form=form, enhanced=True)
            
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
    
    @app.route('/report/<int:job_id>', methods=['POST'])
    @login_required
    def report_job(job_id):
        """Report a suspicious job"""
        if not current_user.is_student():
            return jsonify({'error': 'Only students can report jobs'}), 403
        
        reason = bleach.clean(request.form.get('reason', ''))
        
        if not reason:
            return jsonify({'error': 'Reason is required'}), 400
        
        report = Report(
            job_id=job_id,
            user_id=current_user.id,
            reason=reason,
            user_ip=request.remote_addr
        )
        
        db.session.add(report)
        
        # Auto-flag if 3+ reports
        report_count = Report.query.filter_by(job_id=job_id).count()
        if report_count >= 3:
            job = Job.query.get(job_id)
            if job:
                job.status = 'flagged'
        
        db.session.commit()
        
        log_audit('job_reported', {'job_id': job_id, 'reason': reason})
        return jsonify({'message': 'Report submitted'})
    
    @app.route('/admin')
    @login_required
    def admin_dashboard():
        """Admin dashboard"""
        if not current_user.is_admin():
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        
        flagged_jobs = Job.query.filter_by(status='flagged').all()
        pending_jobs = Job.query.filter_by(status='pending').all()
        reports = Report.query.all()
        
        return render_template('admin.html', 
                             flagged_jobs=flagged_jobs,
                             pending_jobs=pending_jobs,
                             reports=reports)
    
    @app.route('/admin/job/<int:job_id>/<action>')
    @login_required
    def admin_job_action(job_id, action):
        """Admin job moderation"""
        if not current_user.is_admin():
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        
        job = Job.query.get_or_404(job_id)
        
        if action == 'approve':
            job.status = 'approved'
            flash(f'Job "{job.title}" ap
