from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length
from proxmoxer import ProxmoxAPI

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'



available_os = [
    ('local:vztmpl/debian-10-standard_10.7-1_amd64.tar.gz', 'Debian 10'),
    ('local:vztmpl/ubuntu-20.04-standard_20.04-1_amd64.tar.gz', 'Ubuntu 20.04'),
    ('local:vztmpl/centos-7-default_7.9-2009_amd64.tar.gz', 'CentOS 7'),
]



# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('plan.id'), nullable=True)
    credits = db.Column(db.Integer, default=0)

    plan = db.relationship('Plan', backref=db.backref('users', lazy=True))
    instances = db.relationship('Instance', backref='user', lazy=True)

class Plan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    credits = db.Column(db.Integer, nullable=False)
    cpu_cores = db.Column(db.Integer, nullable=False)  # Number of CPU cores
    memory = db.Column(db.Integer, nullable=False)  # Memory in MB
    disk_size = db.Column(db.Integer, nullable=False)  # Disk size in GB

class Instance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vmid = db.Column(db.Integer, nullable=False)
    hostname = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Initialize forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    plan = SelectField('Select Plan', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CreateServerForm(FlaskForm):
    hostname = StringField('Hostname', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    os = SelectField('Operating System', choices=[], validators=[DataRequired()])
    submit = SubmitField('Create Server')


# Proxmox API Interaction
def create_lxc_instance(vmid, hostname, cpu_cores, memory, disk_size, os_template, password):
    proxmox = ProxmoxAPI('YOUR_PROXMOX_IP', user='YOUR_USER@pam', password='YOUR_PASSWORD', verify_ssl=False)
    
    # Create a new LXC container
    proxmox.nodes('YOUR_NODE_NAME').lxc.create(
        vmid=vmid,
        hostname=hostname,
        ostemplate=os_template,
        memory=memory,
        cores=cpu_cores,
        net0='name=eth0,bridge=vmbr0,ip=dhcp',
        rootfs=f'local-lvm:{disk_size}G',
        password=password,  # Password from the form
        unprivileged=1,
    )

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/')
def home():
    return render_template('home.html')




# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    form.plan.choices = [(plan.id, plan.name) for plan in Plan.query.all()]  # Populate plans
    if form.validate_on_submit():
        user = User(username=form.username.data, password=form.password.data)
        selected_plan = Plan.query.get(form.plan.data)
        user.credits = selected_plan.credits  # Set credits based on selected plan
        db.session.add(user)
        db.session.commit()
        
        # Create an LXC instance on Proxmox
        create_lxc_instance(
            vmid=user.id + 100,  # Ensure unique VMID, adjust as necessary
            hostname=form.username.data,
            cpu_cores=selected_plan.cpu_cores,
            memory=selected_plan.memory,
            disk_size=selected_plan.disk_size
        )
        
        flash('Account created and instance provisioned!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:  # Use hashed passwords in production
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', instances=current_user.instances)


@app.route('/create_server', methods=['GET', 'POST'])
@login_required
def create_server():
    form = CreateServerForm()
    form.os.choices = available_os  # Populate OS choices

    if form.validate_on_submit():
        # Create the LXC instance on Proxmox
        create_lxc_instance(
            vmid=current_user.id + 100,  # Ensure unique VMID, adjust as necessary
            hostname=form.hostname.data,
            cpu_cores=1,  # Adjust based on your plan/requirements
            memory=1024,  # Adjust based on your plan/requirements
            disk_size=10,  # Adjust based on your plan/requirements
            os_template=form.os.data,
            password=form.password.data
        )

        # Create an Instance record in the database
        instance = Instance(vmid=current_user.id + 100, hostname=form.hostname.data, user_id=current_user.id)
        db.session.add(instance)
        db.session.commit()

        flash('Server created successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_server.html', form=form)




@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def create_sample_plans():
    basic_plan = Plan(name='Basic Plan', credits=10, cpu_cores=1, memory=1024, disk_size=10)
    premium_plan = Plan(name='Premium Plan', credits=20, cpu_cores=2, memory=2048, disk_size=20)
    db.session.add(basic_plan)
    db.session.add(premium_plan)
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
        create_sample_plans()  # Create sample plans
    app.run(host='0.0.0.0', port=5000, debug=True)
