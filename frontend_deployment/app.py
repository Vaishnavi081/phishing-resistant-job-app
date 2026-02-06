"""
MVP Flask Application - Person 3
FIXED Foreign Key Issue
"""
import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import bleach

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

# Database Models - FIXED table names
class User(db.Model):
    __tablename__ = 'user'  # Explicit table name
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # student/employer/admin
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    company_name = db.Column(db.String(100))
    
    # Relationships
    jobs = db.relationship('Job', backref='employer_user', lazy=True)
    
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
    __tablename__ = 'job'  # Explicit table name
    
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
    employer_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # FIXED: 'user.id' not 'users.id'
    
    # Relationships
    reports = db.relationship('Report', backref='job_report', lazy=True)
    
    def get_risk_badge(self):
        if self.risk_score < 30:
            return ('🟢 Safe', 'success')
        elif self.risk_score < 70:
            return ('🟡 Caution', 'warning')
        else:
            return ('🔴 High Risk', 'danger')

class Report(db.Model):
    __tablename__ = 'report'  # Explicit table name
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'))  # FIXED: 'job.id' not 'jobs.id'
    user_ip = db.Column(db.String(45), nullable=False)
    reason = db.Column(db.String(50), nullable=False)
    votes = db.Column(db.Integer, default=1)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def create_app():
    app = Flask(__name__)
    
    # Basic config
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    
    # Login manager config
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Routes
    
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            email = bleach.clean(request.form.get('email', ''))
            password = request.form.get('password', '')
            remember = bool(request.form.get('remember'))
            
            user = User.query.filter_by(email=email).first()
            
            if user and user.check_password(password):
                login_user(user, remember=remember)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'danger')
        
        return render_template('login.html')
    
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            email = bleach.clean(request.form.get('email', '').lower())
            password = request.form.get('password', '')
            role = request.form.get('role', 'student')
            company_name = bleach.clean(request.form.get('company_name', '')) if role == 'employer' else None
            
            # Check if user exists
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'danger')
                return redirect(url_for('register'))
            
            # Create user
            user = User(email=email, role=role, company_name=company_name)
            user.set_password(password)
            
            # Auto-create admin for demo
            if email in ['admin@jobportal.com', 'superadmin@jobportal.com']:
                user.role = 'admin'
                user.verified = True
            
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        
        return render_template('register.html')
    
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out', 'info')
        return redirect(url_for('index'))
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        
        jobs = Job.query.filter_by(status='approved').order_by(Job.created_at.desc()).all()
        return render_template('dashboard.html', jobs=jobs, user=current_user)
    
    @app.route('/jobs')
    @login_required
    def jobs():
        jobs = Job.query.filter_by(status='approved').order_by(Job.created_at.desc()).all()
        return render_template('jobs.html', jobs=jobs)
    
    @app.route('/job/<int:job_id>')
    @login_required
    def job_detail(job_id):
        job = Job.query.get_or_404(job_id)
        return render_template('job_detail.html', job=job)
    
    @app.route('/post-job', methods=['GET', 'POST'])
    @login_required
    def post_job():
        if not current_user.is_employer():
            flash('Only employers can post jobs', 'danger')
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            # Sanitize inputs
            title = bleach.clean(request.form.get('title', ''))
            description = bleach.clean(request.form.get('description', ''))
            company = bleach.clean(request.form.get('company', ''))
            email = bleach.clean(request.form.get('email', '').lower())
            apply_link = bleach.clean(request.form.get('apply_link', ''))
            location = bleach.clean(request.form.get('location', ''))
            job_type = request.form.get('job_type', 'full-time')
            
            # Simple risk scoring
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
                company=company,
                email=email,
                apply_link=apply_link,
                risk_score=min(risk_score, 100),
                status='rejected' if risk_score > 70 else 'pending',
                location=location,
                job_type=job_type,
                employer_id=current_user.id
            )
            
            db.session.add(job)
            db.session.commit()
            
            if risk_score > 70:
                flash('Job rejected due to high risk score', 'danger')
            elif risk_score > 40:
                flash('Job posted for admin review', 'warning')
            else:
                flash('Job posted successfully!', 'success')
            
            return redirect(url_for('dashboard'))
        
        return render_template('post_job.html')
    
    @app.route('/report/<int:job_id>', methods=['POST'])
    @login_required
    def report_job(job_id):
        if not current_user.is_student():
            return jsonify({'error': 'Only students can report jobs'}), 403
        
        reason = bleach.clean(request.form.get('reason', ''))
        
        if not reason:
            return jsonify({'error': 'Reason is required'}), 400
        
        report = Report(
            job_id=job_id,
            user_ip=request.remote_addr,
            reason=reason
        )
        
        db.session.add(report)
        
        # Auto-flag if 3+ reports
        report_count = Report.query.filter_by(job_id=job_id).count()
        if report_count >= 3:
            job = Job.query.get(job_id)
            if job:
                job.status = 'flagged'
        
        db.session.commit()
        
        return jsonify({'message': 'Report submitted'})
    
    @app.route('/admin')
    @login_required
    def admin_dashboard():
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
            Report.query.filter_by(job_id=job_id).delete()
            db.session.delete(job)
            flash(f'Job "{job.title}" deleted', 'danger')
        
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    
    @app.route('/calculate-risk', methods=['POST'])
    @login_required
    def calculate_risk():
        if not current_user.is_employer():
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        url = data.get('url', '')
        description = data.get('description', '')
        
        # Simple risk calculation for live preview
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
        return jsonify({'status': 'healthy'}), 200
    
    @app.errorhandler(404)
    def not_found(error):
        return render_template('404.html'), 404
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    with app.app_context():
        # Delete existing database if there are issues
        try:
            db.create_all()
        except Exception as e:
            print(f"Database error: {e}")
            print("Trying to recreate database...")
            import sqlite3
            import os
            if os.path.exists('app.db'):
                os.remove('app.db')
            db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(email='admin@jobportal.com').first():
            admin = User(email='admin@jobportal.com', role='admin', verified=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("✓ Created admin user: admin@jobportal.com / admin123")
        
        print("✓ Database initialized successfully")
    
    print("✓ Starting Flask application...")
    print("✓ Open http://localhost:5001 in your browser")
    app.run(host='0.0.0.0', port=5001, debug=True)