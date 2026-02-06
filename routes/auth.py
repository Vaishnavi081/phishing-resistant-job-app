from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from forms import RegistrationForm, LoginForm
from security_middleware import sanitize_input

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('jobs.index'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        try:
            from models import db, User
            from werkzeug.security import generate_password_hash
            
            # Create user
            user = User(
                email=form.email.data,
                role=form.role.data,
                password_hash=generate_password_hash(form.password.data)
            )
            
            db.session.add(user)
            db.session.commit()
            
            login_user(user)
            flash('Registered!', 'success')
            
            if user.role == 'admin':
                return redirect(url_for('admin.dashboard'))
            elif user.role == 'employer':
                return redirect(url_for('jobs.employer_dashboard'))
            else:
                return redirect(url_for('jobs.student_dashboard'))
                
        except:
            flash('Error!', 'danger')
    
    return render_template('register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('jobs.index'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        try:
            from models import User
            from werkzeug.security import check_password_hash
            
            user = User.query.filter_by(email=form.email.data).first()
            
            if user and check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('Logged in!', 'success')
                return redirect(url_for('jobs.index'))
            else:
                flash('Wrong email/password!', 'danger')
        except:
            flash('Error!', 'danger')
    
    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out!', 'info')
    return redirect(url_for('auth.login'))