from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from security_middleware import report_limit

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/report/<int:job_id>', methods=['POST'])
@login_required
@report_limit
def report_job(job_id):
    """Simple report endpoint"""
    if current_user.role != 'student':
        return jsonify({'error': 'Students only'}), 403
    
    try:
        from models import db, Report
        
        report = Report(
            job_id=job_id,
            user_id=current_user.id,
            reason=request.json.get('reason', 'other'),
            comment=request.json.get('comment', '')
        )
        
        db.session.add(report)
         
        # Auto-flag if 3+ reports
        from models import Job
        count = Report.query.filter_by(job_id=job_id).count()
        if count >= 3:
            job = Job.query.get(job_id)
            if job:
                job.status = 'flagged'
        
        db.session.commit()
        return jsonify({'message': 'Reported!'})
        
    except:
        return jsonify({'error': 'Failed'}), 500