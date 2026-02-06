from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from forms import JobPostingForm
from security_middleware import sanitize_input, job_limit
from file_handling import validate_file
import os
from datetime import datetime

jobs_bp = Blueprint('jobs', __name__)

@jobs_bp.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@jobs_bp.route('/jobs')
def browse_jobs():
    """Browse all approved jobs"""
    try:
        from models import Job
        jobs = Job.query.filter_by(status='approved').order_by(Job.created_at.desc()).all()
    except:
        jobs = []
    
    return render_template('jobs.html', jobs=jobs)

@jobs_bp.route('/job/<int:job_id>')
def job_detail(job_id):
    """View job details"""
    try:
        from models import Job
        job = Job.query.get_or_404(job_id)
    except:
        flash('Job not found!', 'danger')
        return redirect(url_for('jobs.browse_jobs'))
    
    return render_template('job_detail.html', job=job)

@jobs_bp.route('/employer/post-job', methods=['GET', 'POST'])
@login_required
@job_limit
def post_job():
    """CORE: Post a new job with risk scoring"""
    if current_user.role != 'employer':
        flash('Only employers can post jobs!', 'danger')
        return redirect(url_for('jobs.index'))
    
    form = JobPostingForm()
    
    if form.validate_on_submit():
        try:
            from models import db, Job
            from werkzeug.utils import secure_filename
            
            # Basic email domain check
            email_domain = form.email.data.split('@')[-1]
            
            # SIMPLE RISK SCORING (MVP)
            risk_score = 0
            url = form.apply_link.data.lower()
            description = form.description.data.lower()
            
            # 1. Check suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz']
            for tld in suspicious_tlds:
                if url.endswith(tld):
                    risk_score += 30
                    break
            
            # 2. Check suspicious keywords
            suspicious_words = ['urgent', 'crypto', 'paypal', 'western union', 'bitcoin']
            for word in suspicious_words:
                if word in url or word in description:
                    risk_score += 20
                    break
            
            # 3. Check fake domains (like gmai.com)
            fake_domains = ['gmai.com', 'gmal.com', 'yahooo.com']
            if any(fake in email_domain for fake in fake_domains):
                risk_score += 40
            
            # 4. Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl']
            for short in shorteners:
                if short in url:
                    risk_score += 25
                    break
            
            # Handle file upload
            attachment_path = None
            if form.attachment.data:
                is_valid, msg = validate_file(form.attachment.data)
                if is_valid:
                    filename = secure_filename(form.attachment.data.filename)
                    os.makedirs('uploads', exist_ok=True)
                    form.attachment.data.save(os.path.join('uploads', filename))
                    attachment_path = filename
                else:
                    flash(f'File error: {msg}', 'warning')
            
            # Determine status based on risk
            if risk_score > 70:
                status = 'rejected'
                flash_msg = f'❌ Job REJECTED! Risk score: {risk_score}/100'
                msg_type = 'danger'
            elif risk_score > 40:
                status = 'pending'
                flash_msg = f'⚠️ Job needs ADMIN REVIEW. Risk: {risk_score}/100'
                msg_type = 'warning'
            else:
                status = 'pending'  # Still needs admin approval
                flash_msg = f'✅ Job submitted! Risk: {risk_score}/100'
                msg_type = 'success'
            
            # Save to database
            job = Job(
                title=form.title.data,
                description=form.description.data,
                company=form.company.data,
                email=form.email.data,
                apply_link=form.apply_link.data,
                risk_score=risk_score,
                status=status,
                attachment_path=attachment_path,
                location=form.location.data,
                job_type=form.job_type.data,
                employer_id=current_user.id,
                created_at=datetime.utcnow()
            )
            
            db.session.add(job)
            db.session.commit()
            
            flash(flash_msg, msg_type)
            return redirect(url_for('jobs.employer_dashboard'))
            
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            print(f"Error posting job: {e}")
    
    return render_template('post_job.html', form=form)

@jobs_bp.route('/employer/dashboard')
@login_required
def employer_dashboard():
    """Employer sees their posted jobs"""
    if current_user.role != 'employer':
        flash('Access denied!', 'danger')
        return redirect(url_for('jobs.index'))
    
    try:
        from models import Job
        jobs = Job.query.filter_by(employer_id=current_user.id).order_by(Job.created_at.desc()).all()
    except:
        jobs = []
    
    return render_template('employer_dashboard.html', jobs=jobs)

@jobs_bp.route('/student/dashboard')
@login_required
def student_dashboard():
    """Student sees jobs they can apply to"""
    if current_user.role != 'student':
        flash('Access denied!', 'danger')
        return redirect(url_for('jobs.index'))
    
    try:
        from models import Job
        jobs = Job.query.filter_by(status='approved').order_by(Job.created_at.desc()).all()
    except:
        jobs = []
    
    return render_template('student_dashboard.html', jobs=jobs)

@jobs_bp.route('/api/risk-score', methods=['POST'])
def risk_score():
    """API for live risk score in form"""
    data = request.json
    url = data.get('url', '').lower()
    text = data.get('text', '').lower()
    
    score = 0
    
    # Simple scoring
    suspicious = ['.tk', '.ml', '.ga', 'bit.ly', 'urgent', 'crypto', 'paypal']
    
    for word in suspicious:
        if word in url or word in text:
            score += 15
    
    # Check for fake domains in email
    if 'email' in data:
        email = data['email'].lower()
        fake_domains = ['gmai.com', 'gmal.com']
        if any(fake in email for fake in fake_domains):
            score += 40
    
    return jsonify({
        'score': min(score, 100),
        'level': 'low' if score < 30 else 'medium' if score < 70 else 'high'
    })