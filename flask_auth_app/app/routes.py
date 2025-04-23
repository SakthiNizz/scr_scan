from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app.forms import AlertForm, SignupForm, LoginForm
from app.models import Alert, Customer, db, User
from datetime import timedelta  # 🔒 ADDED FOR SESSION TIMEOUT
from flask import make_response
from app.models import UserCustomer

main = Blueprint('main', __name__)

def nocache(view):
    def no_cache_wrapper(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    no_cache_wrapper.__name__ = view.__name__
    return no_cache_wrapper

@main.before_app_request  # 🔒 ADDED: Enforce session timeout across app
def make_session_permanent():
    session.permanent = True
    current_app.permanent_session_lifetime = timedelta(minutes=15)

@main.route('/')
def home():
    return redirect(url_for('main.login'))

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        print("✅ Form validated")
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('main.signup'))
        
        try:
            hashed_pw = generate_password_hash(form.password.data)
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_pw
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful. Please login.', 'success')
            print("✅ User created:", new_user.email)
            return redirect(url_for('main.login'))

        except Exception as e:
            db.session.rollback()
            flash(f'❌ Error during signup: {str(e)}', 'danger')
            print("❌ DB insert failed:", str(e))

    else:
        if request.method == 'POST':
            print("❌ Form errors:", form.errors)

    return render_template('signup.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print("✅ Form validated")

        user = User.query.filter_by(email=form.email.data).first()
        if user:
            print(f"🔍 Found user: {user.email}")
        else:
            print("❌ No user found")

        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            session.permanent = True  # 🔒 ADDED: Make session follow expiration setting
            flash('✅ Login successful!', 'success')
            print("✅ User logged in")
            return redirect(url_for('main.dashboard'))
        else:
            flash('❌ Invalid email or password!', 'danger')
            print("❌ Invalid credentials")

    else:
        if request.method == 'POST':
            print("❌ Form validation errors:", form.errors)

    return render_template('login.html', form=form)

@main.route('/dashboard', methods=['GET', 'POST'])
@login_required
@nocache
def dashboard():
    mapped_customers = db.session.query(Customer).join(UserCustomer).filter(
        UserCustomer.user_id == current_user.id
    ).all()
    return render_template('dashboard.html', customers=mapped_customers)

@main.route('/add_alert', methods=['GET', 'POST'])
@login_required
@nocache
def add_alert():
    form = AlertForm()
    mapped_customers = db.session.query(Customer).join(UserCustomer).filter(
        UserCustomer.user_id == current_user.id
    ).all()
    form.customer.choices = [(c.id, c.name) for c in mapped_customers]

    if form.validate_on_submit():
        new_alert = Alert(
            customer_id=form.customer.data,
            vuln_name=form.vuln_name.data,
            link=form.link.data,
            description=form.description.data
        )
        db.session.add(new_alert)
        db.session.commit()
        flash('✅ Alert added successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('add_alert.html', form=form)

@main.route('/view_alerts/<int:customer_id>')
@login_required
@nocache
def view_alerts(customer_id):
    is_mapped = db.session.query(UserCustomer).filter_by(
        user_id=current_user.id,
        customer_id=customer_id
    ).first()

    if not is_mapped:
        flash("❌ Unauthorized access to this customer's data.", 'danger')
        return redirect(url_for('main.dashboard'))

    alerts = Alert.query.filter_by(customer_id=customer_id).all()
    customer = Customer.query.get_or_404(customer_id)
    return render_template('view_alerts.html', alerts=alerts, customer=customer)

@main.route('/logout', methods=['GET', 'POST'])  # 👈 Add POST here
@login_required
def logout():
    logout_user()
    flash('👋 You have been logged out.', 'info')
    return redirect(url_for('main.login'))


@main.route('/db-check')
def db_check():
    try:
        # A simple test query to see if DB is connected
        db.create_all()
        return "✅ Flask connected to MySQL DB 'new_task' successfully!"
    except Exception as e:
        return f"❌ Error: {e}"
