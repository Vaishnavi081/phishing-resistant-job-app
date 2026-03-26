"""
MVP Flask Application - Person 3
ENHANCED with complete job application system
Merged by: Backend Developer

USES: Person 1's models.py for database models
"""

import os
import json
from datetime import datetime, timezone
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, IntegerField, SubmitField
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
    submit = SubmitField('Post Job')

class ApplicationForm(FlaskForm):
    """Job application form"""
    cover_letter = TextAreaField('Cover Letter', validators=[DataRequired()])
    submit = SubmitField('Submit Application')

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
    app = Flask(__name__,
                template_folder='frontend_deployment/templates',
                static_folder='frontend_deployment/static')
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
    app.config['UPLOAD_FOLDER'] = 'frontend_deployment/static/uploads'
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    
    # Login manager config
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))
    
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
                # Check verification for employers
                if user.role == 'employer' and not user.verified:
                    flash('Your employer account is pending admin verification. Please contact admin.', 'warning')
                    log_audit('employer_login_blocked_unverified', {'email': email})
                    return redirect(url_for('login'))
                
                # Check verification for other users (except admin)
                if not user.verified and user.role != 'admin':
                    flash('Account not verified. Please contact admin.', 'warning')
                    return redirect(url_for('login'))
                
                login_user(user, remember=remember)
                user.last_login = datetime.now(timezone.utc)
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
            
            # Auto-verify students, employers need admin verification
            if role == 'student':
                user.verified = True
            elif role == 'employer':
                user.verified = False  # Employers need admin verification
            
            # Auto-create admin for demo
            if email in ['admin@jobportal.com', 'superadmin@jobportal.com']:
                user.role = 'admin'
                user.verified = True
            
            db.session.add(user)
            db.session.commit()
            
            log_audit('registration', {'email': email, 'role': role})
            
            # Notify admin if employer registered
            if role == 'employer':
                log_audit('employer_registration_pending', 
                         {'email': email, 'company_name': company_name})
                flash('Registration successful! Your employer account is pending admin verification.', 'warning')
            else:
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
                'pending_reports': Report.query.filter_by(status='pending').count(),
                'pending_employers': User.query.filter_by(role='employer', verified=False).count()
            }
            recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()
            report_list = Report.query.order_by(Report.created_at.desc()).limit(10).all()
            
            # Get unverified employers
            pending_employers = User.query.filter_by(role='employer', verified=False).all()
            
            return render_template('admin.html', 
                                 stats=stats, 
                                 recent_logs=recent_logs, 
                                 report_list=report_list,
                                 pending_employers=pending_employers)
        
        elif current_user.is_employer():
            # Check if employer is verified
            if not current_user.verified:
                flash('Your employer account is pending admin verification. You cannot post jobs yet.', 'warning')
                return render_template('dashboard.html', 
                                     pending_verification=True)
            
            # Employer dashboard (only if verified)
            jobs = Job.query.filter_by(employer_id=current_user.id).all()
            total_applications = Application.query.filter(
                Application.job_id.in_([job.id for job in jobs])
            ).count()
            return render_template('dashboard.html', 
                                 jobs=jobs, 
                                 total_applications=total_applications,
                                 pending_verification=False)
        
        else:
            # Student/Applicant dashboard
            applications = Application.query.filter_by(applicant_id=current_user.id).all()
            return render_template('dashboard.html', 
                                 applications=applications,
                                 pending_verification=False)
    
    @app.route('/jobs')        
    @login_required
    def jobs():
        """Job listings with filtering"""
        # Prevent admin and employers from browsing jobs
        if current_user.is_employer():
            if current_user.is_admin():
                flash('Admins cannot browse jobs. Use the admin panel for job management.', 'warning')
            else:
                flash('Employers cannot browse jobs. Post jobs from your dashboard.', 'warning')
            return redirect(url_for('dashboard'))
        
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
        # Prevent admin from viewing job details
        if current_user.is_admin():
            flash('Admins cannot view job details. Use the admin panel for job management.', 'warning')
            return redirect(url_for('dashboard'))
        
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
        # Prevent admin from applying to jobs
        if current_user.is_admin():
            flash('Admins cannot apply for jobs.', 'warning')
            return redirect(url_for('dashboard'))
        
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
                    filename = f"resume_{current_user.id}_{job_id}_{datetime.now(timezone.utc).timestamp()}.pdf"
                    resume_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    os.makedirs(os.path.dirname(resume_path), exist_ok=True)
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
        # Prevent admin from posting jobs
        if current_user.is_admin():
            flash('Admins cannot post jobs. Use the admin panel for job management.', 'warning')
            return redirect(url_for('dashboard'))
        
        if not current_user.is_employer():
            flash('Only employers can post jobs', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check if employer is verified
        if not current_user.verified:
            flash('Your employer account needs admin verification before posting jobs.', 'warning')
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
    
    # ==================== EMPLOYER VERIFICATION ROUTES ====================
    
    @app.route('/admin/verify-employer/<int:user_id>')
    @login_required
    def verify_employer(user_id):
        """Admin verifies an employer"""
        if not current_user.is_admin():
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        
        employer = User.query.get_or_404(user_id)
        if employer.role != 'employer':
            flash('User is not an employer', 'danger')
            return redirect(url_for('dashboard'))
        
        employer.verified = True
        db.session.commit()
        
        log_audit('employer_verified', {'employer_id': user_id, 'email': employer.email})
        flash(f'Employer {employer.company_name} verified successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    @app.route('/admin/reject-employer/<int:user_id>')
    @login_required
    def reject_employer(user_id):
        """Admin rejects an employer"""
        if not current_user.is_admin():
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        
        employer = User.query.get_or_404(user_id)
        company_name = employer.company_name
        
        # Delete the employer (or you could just mark as rejected)
        db.session.delete(employer)
        db.session.commit()
        
        log_audit('employer_rejected', {'employer_id': user_id, 'email': employer.email})
        flash(f'Employer {company_name} rejected and removed.', 'warning')
        return redirect(url_for('dashboard'))
    
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
            flash(f'Job "{job.title}" approved', 'success')
        elif action == 'reject':
            job.status = 'rejected'
            flash(f'Job "{job.title}" rejected', 'warning')
        elif action == 'delete':
            # Delete related applications and reports
            Application.query.filter_by(job_id=job_id).delete()
            Report.query.filter_by(job_id=job_id).delete()
            db.session.delete(job)
            flash(f'Job "{job.title}" deleted', 'danger')
        
        db.session.commit()
        log_audit('admin_job_action', {'job_id': job_id, 'action': action})
        return redirect(url_for('dashboard'))
    
    @app.route('/reports')
    @login_required
    def reports():
        """System reports (admin only)"""
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
    
    @app.route('/calculate-risk', methods=['POST'])
    @login_required
    def calculate_risk():
        """Calculate risk score for job posting preview"""
        if not current_user.is_admin():
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        url = data.get('url', '')
        description = data.get('description', '')
        
        # Risk calculation
        risk_score = 0
        
        if not url.startswith(('http://', 'https://')):
            risk_score += 20
        
        if any(short in url for short in ['bit.ly', 'tinyurl', 'ow.ly']):
            risk_score += 30
        
        suspicious_keywords = ['urgent', 'crypto', 'bitcoin', 'paypal', 'western union']
        for keyword in suspicious_keywords:
            if keyword in (url + description).lower():
                risk_score += 15
        
        risk_score = min(risk_score, 100)
        
        if risk_score < 30:
            badge, color = '🟢 Safe', 'success'
        elif risk_score < 70:
            badge, color = '🟡 Caution', 'warning'
        else:
            badge, color = '🔴 High Risk', 'danger'
        
        return jsonify({
            'score': risk_score,
            'badge': badge,
            'color': color
        })
    
    @app.route('/health')
    def health():
        """Health check endpoint"""
        return jsonify({'status': 'healthy'}), 200
    
    # ==================== REPORT HELPER FUNCTIONS ====================
    
    def get_user_growth_report():
        """Generate user growth report"""
        from datetime import timedelta
        days = 30
        data = []
        for i in range(days, -1, -1):
            date = (datetime.now(timezone.utc) - timedelta(days=i)).strftime('%Y-%m-%d')
            count = User.query.filter(
                db.func.date(User.created_at) == date
            ).count()
            data.append({'date': date, 'count': count})
        return data
    
    def get_job_statistics():
        """Generate job statistics"""
        stats = {
            'total_jobs': Job.query.count(),
            'active_jobs': Job.query.filter_by(is_active=True).count(),
            'by_type': db.session.query(Job.job_type, db.func.count(Job.id)).group_by(Job.job_type).all(),
            'by_experience': db.session.query(Job.experience_level, db.func.count(Job.id)).group_by(Job.experience_level).all()
        }
        return stats
    
    def get_application_metrics():
        """Generate application metrics"""
        metrics = {
            'total_applications': Application.query.count(),
            'by_status': db.session.query(Application.status, db.func.count(Application.id)).group_by(Application.status).all(),
            'avg_applications_per_job': db.session.query(db.func.avg(db.func.count(Application.id))).group_by(Application.job_id).scalar() or 0
        }
        return metrics
    
    # ==================== ERROR HANDLERS ====================
    
    @app.errorhandler(404)
    def not_found(error):
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500
    
    @app.errorhandler(413)
    def too_large_error(error):
        return render_template('413.html'), 413
    
    # ==================== CONTEXT PROCESSORS ====================
    
    @app.context_processor
    def inject_user():
        return dict(current_user=current_user)
    
    @app.context_processor
    def inject_now():
        return {'now': datetime.now(timezone.utc)}
    
    return app

# ==================== MAIN EXECUTION ====================
if __name__ == '__main__':
    app = create_app()
    
    with app.app_context():
        # Initialize database using Person 1's function
        init_database()
        print("✓ Database initialized successfully")
    
    print("✓ Starting Flask application...")
    print("✓ Open http://localhost:5001 in your browser")
    app.run(host='0.0.0.0', port=5001, debug=True)