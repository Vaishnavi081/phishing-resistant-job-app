# File: routes/admin.py
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

@admin_bp.before_request
def check_admin():
    """Verify user is authenticated and has admin role"""
    if not current_user.is_authenticated:
        flash('Please log in to access admin area.', 'danger')
        return redirect(url_for('auth.login'))
    
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('jobs.index'))

@admin_bp.route('/admin')
@login_required
def dashboard():
    """Admin dashboard with statistics"""
    try:
        from models import Job, Report, User
        
        flagged = Job.query.filter_by(status='flagged').count()
        pending = Job.query.filter_by(status='pending').count()
        reports = Report.query.filter_by(resolved=False).count()
        total_jobs = Job.query.count()
        total_users = User.query.count()
        
        # Recent flagged jobs
        recent_flagged = Job.query.filter_by(status='flagged')\
                                 .order_by(Job.created_at.desc())\
                                 .limit(5).all()
        
    except Exception as e:
        flagged = pending = reports = total_jobs = total_users = 0
        recent_flagged = []
        print(f"Error in admin dashboard: {e}")
    
    return render_template('admin_dashboard.html', 
                         flagged=flagged, 
                         pending=pending,
                         reports=reports,
                         total_jobs=total_jobs,
                         total_users=total_users,
                         recent_flagged=recent_flagged)

@admin_bp.route('/admin/jobs')
@login_required
def manage_jobs():
    """Manage jobs with filtering by status"""
    status = request.args.get('status', 'all')
    
    try:
        from models import Job
        
        if status == 'flagged':
            jobs = Job.query.filter_by(status='flagged')\
                           .order_by(Job.created_at.desc()).all()
        elif status == 'pending':
            jobs = Job.query.filter_by(status='pending')\
                           .order_by(Job.created_at.desc()).all()
        elif status == 'approved':
            jobs = Job.query.filter_by(status='approved')\
                           .order_by(Job.created_at.desc()).all()
        elif status == 'rejected':
            jobs = Job.query.filter_by(status='rejected')\
                           .order_by(Job.created_at.desc()).all()
        else:
            jobs = Job.query.order_by(Job.created_at.desc()).all()
            
    except Exception as e:
        jobs = []
        print(f"Error loading jobs: {e}")
    
    return render_template('admin_jobs.html', 
                         jobs=jobs, 
                         status=status)

@admin_bp.route('/admin/job/<int:job_id>/<action>')
@login_required
def job_action(job_id, action):
    """Perform actions on jobs (approve, reject, flag, blacklist)"""
    try:
        from models import db, Job, Blacklist
        
        job = Job.query.get_or_404(job_id)
        
        if action == 'approve':
            job.status = 'approved'
            flash(f'Job "{job.title}" has been approved.', 'success')
            
        elif action == 'reject':
            job.status = 'rejected'
            flash(f'Job "{job.title}" has been rejected.', 'warning')
            
        elif action == 'flag':
            job.status = 'flagged'
            flash(f'Job "{job.title}" has been flagged for review.', 'info')
            
        elif action == 'blacklist':
            # Extract domain from job email
            if '@' in job.email:
                domain = job.email.split('@')[-1]
                
                # Check if domain is already blacklisted
                existing = Blacklist.query.filter_by(domain=domain).first()
                if not existing:
                    blacklist = Blacklist(
                        domain=domain, 
                        reason=f'Blacklisted by admin from job: {job.title}',
                        admin_id=current_user.id
                    )
                    db.session.add(blacklist)
                    flash(f'Domain {domain} has been blacklisted.', 'danger')
                else:
                    flash(f'Domain {domain} is already blacklisted.', 'info')
                
                job.status = 'rejected'
            else:
                flash('Invalid email format.', 'danger')
        
        elif action == 'delete':
            db.session.delete(job)
            flash(f'Job "{job.title}" has been deleted.', 'danger')
        
        db.session.commit()
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        print(f"Error in job_action: {e}")
    
    return redirect(url_for('admin.manage_jobs'))

@admin_bp.route('/admin/reports')
@login_required
def view_reports():
    """View all user reports"""
    try:
        from models import Report, Job, User
        
        # Join reports with jobs and users
        reports = Report.query\
                       .join(Job, Report.job_id == Job.id)\
                       .join(User, Report.user_id == User.id)\
                       .add_columns(
                           Report.id,
                           Report.reason,
                           Report.comment,
                           Report.created_at,
                           Report.resolved,
                           Job.title.label('job_title'),
                           Job.company.label('company'),
                           User.email.label('reporter_email')
                       )\
                       .order_by(Report.created_at.desc())\
                       .all()
        
    except Exception as e:
        reports = []
        print(f"Error loading reports: {e}")
    
    return render_template('admin_reports.html', reports=reports)

@admin_bp.route('/admin/report/<int:report_id>/resolve', methods=['POST'])
@login_required
def resolve_report(report_id):
    """Mark a report as resolved"""
    try:
        from models import db, Report
        
        report = Report.query.get_or_404(report_id)
        report.resolved = True
        report.resolved_at = datetime.utcnow()
        
        db.session.commit()
        flash(f'Report #{report_id} has been marked as resolved.', 'success')
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        print(f"Error resolving report: {e}")
    
    return redirect(url_for('admin.view_reports'))

@admin_bp.route('/admin/blacklist')
@login_required
def manage_blacklist():
    """Manage blacklisted domains"""
    try:
        from models import Blacklist, User
        
        # Get blacklist with admin info
        blacklist = Blacklist.query\
                            .outerjoin(User, Blacklist.admin_id == User.id)\
                            .add_columns(
                                Blacklist.id,
                                Blacklist.domain,
                                Blacklist.email,
                                Blacklist.reason,
                                Blacklist.created_at,
                                User.email.label('admin_email')
                            )\
                            .order_by(Blacklist.created_at.desc())\
                            .all()
        
    except Exception as e:
        blacklist = []
        print(f"Error loading blacklist: {e}")
    
    return render_template('admin_blacklist.html', blacklist=blacklist)

@admin_bp.route('/admin/blacklist/<int:blacklist_id>/delete', methods=['POST'])
@login_required
def delete_blacklist(blacklist_id):
    """Remove from blacklist"""
    try:
        from models import db, Blacklist
        
        item = Blacklist.query.get_or_404(blacklist_id)
        db.session.delete(item)
        db.session.commit()
        
        flash('Removed from blacklist.', 'success')
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    
    return redirect(url_for('admin.manage_blacklist'))

@admin_bp.route('/admin/stats')
@login_required
def view_stats():
    """View statistics"""
    try:
        from models import Job, Report, User
        from sqlalchemy import func
        
        # Risk score distribution
        risk_stats = {
            'safe': Job.query.filter(Job.risk_score < 30).count(),
            'caution': Job.query.filter(Job.risk_score.between(30, 70)).count(),
            'high_risk': Job.query.filter(Job.risk_score >= 70).count()
        }
        
        # Top reported jobs
        from sqlalchemy.sql import label
        top_reported = Job.query\
                         .join(Report, Job.id == Report.job_id)\
                         .group_by(Job.id)\
                         .order_by(func.count(Report.id).desc())\
                         .limit(5)\
                         .add_columns(
                             Job.title,
                             Job.company,
                             func.count(Report.id).label('report_count')
                         )\
                         .all()
        
        # Recent activity
        recent_jobs = Job.query.order_by(Job.created_at.desc()).limit(10).all()
        
    except Exception as e:
        risk_stats = {'safe': 0, 'caution': 0, 'high_risk': 0}
        top_reported = []
        recent_jobs = []
        print(f"Error loading stats: {e}")
    
    return render_template('admin_stats.html',
                         risk_stats=risk_stats,
                         top_reported=top_reported,
                         recent_jobs=recent_jobs)