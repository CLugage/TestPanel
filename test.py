from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length

from proxmoxer import ProxmoxAPI
import json
import socket
import subprocess
import random
import os
import requests

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Available OS templates for LXC
available_os = [
    ('local:vztmpl/ubuntu-23.04-standard_23.04-1_amd64.tar.zst', 'Ubuntu 23.04'),
]


# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    credits = db.Column(db.Integer, default=5000)  # Start with 5000 credits
    is_admin = db.Column(db.Boolean, default=False)
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
    port = db.Column(db.Integer, nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)

# Initialize forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CreateServerForm(FlaskForm):
    hostname = StringField('Hostname', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    os = SelectField('Operating System', choices=[], validators=[DataRequired()])
    plan = SelectField('Select Plan', choices=[], validators=[DataRequired()])
    submit = SubmitField('Create Server')

def load_plans_from_json():
    try:
        with open('plans.json') as f:
            plans_data = json.load(f)
        
        for plan in plans_data:
            # Check if the plan already exists
            existing_plan = Plan.query.get(plan['id'])
            if not existing_plan:
                new_plan = Plan(
                    id=plan['id'],
                    name=plan['name'],
                    credits=plan['credits'],
                    cpu_cores=plan['cpu_cores'],
                    memory=plan['memory'],
                    disk_size=plan['disk_size']
                )
                db.session.add(new_plan)
        db.session.commit()
    except FileNotFoundError:
        print("plans.json not found. Make sure it exists in the project directory.")
    except json.JSONDecodeError:
        print("Error decoding JSON from plans.json. Please check the file format.")

def get_next_vmid(proxmox):
    return proxmox.cluster.nextid.get()

# Function to find an available port
def find_available_port(start_port=20000, end_port=30000):
    while True:
        port = random.randint(start_port, end_port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) != 0:  # Port is available
                return port


def get_lxc_config(vmid):
    proxmox = ProxmoxAPI('45.137.70.53', user='root@pam', password='raCz3M7WoEqbtmYemUQI', verify_ssl=False)
    try:
        config = proxmox.nodes('vps1').lxc(vmid).config.get()
        return config
    except Exception as e:
        print(f"Error fetching LXC config for VMID {vmid}: {e}")
        return None




def update_nat_post_up(vmid, port, ip):
    # Get the LXC configuration
    config = get_lxc_config(vmid)
    
    if not config:
        print(f"Could not retrieve config for VMID {vmid}. Aborting NAT update.")
        return
    
    # Assume the scripts are stored in a specific path, modify if necessary
    nat_post_up_path = config.get('nat_post_up', '/root/nat-post-up.sh')  # Example path
    command = f"iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport {port} -j DNAT --to {ip}:22"
    
    # Write the command to the NAT post-up script
    with open(nat_post_up_path, 'a') as f:
        f.write(command + '\n')
    
    # Run the command in the terminal
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Executed command: {command}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")


def update_nat_pre_down(vmid, port, ip):
    # Get the LXC configuration
    config = get_lxc_config(vmid)
    
    if not config:
        print(f"Could not retrieve config for VMID {vmid}. Aborting NAT update.")
        return
    
    # Assume the scripts are stored in a specific path, modify if necessary
    nat_pre_down_path = config.get('nat_pre_down', '/root/nat-pre-down.sh')  # Example path
    command = f"iptables -t nat -D PREROUTING -i vmbr0 -p tcp --dport {port} -j DNAT --to {ip}:22"
    
    with open(nat_pre_down_path, 'a') as f:
        f.write(command + '\n')


# Function to update SSH configuration in the container
def update_ssh_config(vmid):
    # Path to the SSH config file inside the container
    sshd_conf_path = '/etc/ssh/sshd_config'
    
    # Read the contents of sshd_conf.txt
    try:
        with open('sshd_conf.txt', 'r') as f:
            sshd_conf_content = f.read()
    except FileNotFoundError:
        print("sshd_conf.txt not found. Please check the file path.")
        return
    
    # Command to write to the sshd_config file using 'tee'
    command_write = f'echo "{sshd_conf_content}" | pct exec {vmid} -- tee {sshd_conf_path} > /dev/null'
    # Command to restart the SSH service
    command_restart = f"pct exec {vmid} -- systemctl restart sshd"

    # Execute the commands in the container
    try:
        # Write the SSH configuration
        write_result = subprocess.run(command_write, shell=True, check=True, capture_output=True)
        print(f"Write SSH configuration output: {write_result.stdout.decode()}")
        
        # Restart the SSH service
        restart_result = subprocess.run(command_restart, shell=True, check=True, capture_output=True)
        print(f"Restart SSH service output: {restart_result.stdout.decode()}")

        print(f"SSH configuration updated and service restarted for VMID {vmid}.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating SSH config or restarting service: {e.stderr.decode()}")



def get_next_ip_address(current_instances):
    base_ip = [10, 10, 10]  # Base for your network
    used_ips = {instance.ip_address for instance in current_instances}  # Set of used IP addresses

    # Start from the first usable IP address
    next_ip = 3  # Start from 10.10.10.3
    while next_ip <= 254:  # Check until the last possible address
        candidate_ip = f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.{next_ip}"
        if candidate_ip not in used_ips:
            return candidate_ip
        next_ip += 1

    raise Exception("No available IP addresses left in the range.")  # Handle case when no IP is available



def setup_ssh_on_start(vmid):
    """Set up SSH configuration to run on container startup."""
    # Create a startup script
    startup_script = f"""
#!/bin/bash
# Update SSH configuration
sshd_conf_path='/etc/ssh/sshd_config'
# Read the contents of sshd_conf.txt
if [ -f /root/sshd_conf.txt ]; then
    cat /root/sshd_conf.txt > $sshd_conf_path
    systemctl restart sshd
    echo "SSH configuration updated and service restarted."
else
    echo "sshd_conf.txt not found. Please ensure it exists."
fi
"""
    
    # Write the startup script to a file
    script_path = f"/tmp/setup_ssh_{vmid}.sh"
    with open(script_path, 'w') as f:
        f.write(startup_script)
    
    # Copy the SSH config and startup script to the container
    try:
        # Copy the SSH configuration file
        result = subprocess.run(f"pct push {vmid} sshd_conf.txt /root/sshd_conf.txt", shell=True, check=True, capture_output=True)
        print(f"Copy sshd_conf.txt output: {result.stdout.decode() if result.stdout else 'No output'}")

        # Copy the startup script into the container
        result = subprocess.run(f"pct push {vmid} {script_path} /root/setup_ssh.sh", shell=True, check=True, capture_output=True)
        print(f"Copy setup_ssh.sh output: {result.stdout.decode() if result.stdout else 'No output'}")

        # Set the script to be executable
        result = subprocess.run(f"pct exec {vmid} -- chmod +x /root/setup_ssh.sh", shell=True, check=True, capture_output=True)
        print(f"Set executable output: {result.stdout.decode() if result.stdout else 'No output'}")

        # Add a command to run the script on startup
        result = subprocess.run(f"pct exec {vmid} -- bash -c 'echo \"/root/setup_ssh.sh\" >> /etc/rc.local'", shell=True, check=True, capture_output=True)
        print(f"Update rc.local output: {result.stdout.decode() if result.stdout else 'No output'}")

        print(f"SSH setup script configured for VMID {vmid}.")

    except subprocess.CalledProcessError as e:
        print(f"Error during SSH setup for VMID {vmid}: {e.stderr.decode() if e.stderr else 'No error output'}")
        print(f"Return code: {e.returncode}")

    # Clean up the temporary script file
    os.remove(script_path)




import subprocess
from proxmoxer import ProxmoxAPI

def create_lxc_instance(vmid, hostname, cpu_cores, memory, disk_size, os_template, password, ip_address):
    proxmox = ProxmoxAPI('45.137.70.53', user='root@pam', password='raCz3M7WoEqbtmYemUQI', verify_ssl=False)

    try:
        proxmox.nodes('vps1').lxc.create(
            vmid=vmid,
            hostname=hostname,
            ostemplate=os_template,
            memory=memory,
            cores=cpu_cores,
            net0=f'name=eth0,bridge=vmbr1,ip={ip_address}/24,gw=10.10.10.1',
            rootfs=f'local:{disk_size * 1024}',
            password=password,
            unprivileged=1,
            onboot=1,  # Set the container to start on boot
        )
        print(f'Instance {vmid} created successfully.')

        # Prepare the SSH configuration content
        sshd_conf_content = """# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

# Port and ListenAddress options are not used when sshd is socket-activated,
# which is now the default in Ubuntu.  See sshd_config(5) and
# /usr/share/doc/openssh-server/README.Debian.gz for details.
#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile     .ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
KbdInteractiveAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck no
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem       sftp    /usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server
"""

        # Create the SSH config inside the container using a temporary file
        command_update_sshd = f"""bash -c 'echo "{sshd_conf_content.replace("\"", "\\\"").replace("\n", "\\n")}" > /etc/ssh/sshd_config && systemctl restart sshd'"""
        subprocess.run(f"pct exec {vmid} -- {command_update_sshd}", shell=True, check=True)

        print(f'SSH configuration updated for VMID {vmid}.')

    except Exception as e:
        print(f'Error creating instance {vmid}: {e}')
        raise  # Raise the exception to propagate the error




        
# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

# Login Route
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

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', instances=current_user.instances)

# Create route
@app.route('/create_server', methods=['GET', 'POST'])
@login_required
def create_server():
    form = CreateServerForm()
    form.os.choices = available_os  # Populate OS choices

    # Add plan choices to the form
    plans = Plan.query.all()
    form.plan.choices = [(plan.id, plan.name) for plan in plans]

    if form.validate_on_submit():
        # Check if the user already has an instance
        if len(current_user.instances) >= 1:
            flash('You can only have one instance at a time.', 'danger')
            return redirect(url_for('dashboard'))

        selected_plan = Plan.query.get(form.plan.data)

        # Check if user has enough credits
        if current_user.credits < selected_plan.credits:
            flash('Insufficient credits to create this server.', 'danger')
            return redirect(url_for('dashboard'))

        # Initialize Proxmox API client
        proxmox = ProxmoxAPI('45.137.70.53', user='root@pam', password='raCz3M7WoEqbtmYemUQI', verify_ssl=False)

        # Get next VM ID
        try:
            vmid = get_next_vmid(proxmox)
            print(f'Next VMID: {vmid}')  # Debug output
        except Exception as e:
            flash(f'Error retrieving next VMID: {e}', 'danger')
            return redirect(url_for('dashboard'))

        # Get the next available IP address
        current_instances = Instance.query.filter_by(user_id=current_user.id).all()
        ip_address = get_next_ip_address(current_instances)

        # Create the LXC instance on Proxmox
        try:
            create_lxc_instance(
                vmid=vmid,
                hostname=form.hostname.data,
                cpu_cores=selected_plan.cpu_cores,
                memory=selected_plan.memory,
                disk_size=selected_plan.disk_size,
                os_template=form.os.data,
                password=form.password.data,
                ip_address=ip_address
            )
        except Exception as e:
            flash(f'Error creating server: {e}', 'danger')
            return redirect(url_for('dashboard'))

        # Create an Instance record in the database
        instance = Instance(vmid=vmid, hostname=form.hostname.data, user_id=current_user.id, port=find_available_port(), ip_address=ip_address)
        db.session.add(instance)

        # Update iptables rules in the NAT scripts
        update_nat_post_up(vmid, instance.port, ip_address)
        update_nat_pre_down(vmid, instance.port, ip_address)

        # Update SSH configuration and restart service
        update_ssh_config(vmid)

        # Deduct credits from user
        current_user.credits -= selected_plan.credits
        db.session.commit()

        flash('Server created successfully!', 'success')
        return redirect(url_for('manage_instances'))  # Redirect to manage instances

    return render_template('create_server.html', form=form)




@app.route('/manage_instances')
@login_required
def manage_instances():
    instances = current_user.instances  # Get user instances
    proxmox = ProxmoxAPI('45.137.70.53', user='root@pam', password='raCz3M7WoEqbtmYemUQI', verify_ssl=False)
    
    # Get status for each instance from Proxmox
    instance_statuses = []
    for instance in instances:
        status = proxmox.nodes('vps1').lxc(instance.vmid).status.current.get()
        instance_statuses.append({
            'id': instance.id,
            'hostname': instance.hostname,
            'vmid': instance.vmid,
            'status': status['status'],
            'port': instance.port  # Include the port information
        })

    return render_template('manage_instances.html', instances=instance_statuses)



@app.route('/start_instance/<int:vmid>', methods=['POST'])
@login_required
def start_instance(vmid):
    proxmox = ProxmoxAPI('45.137.70.53', user='root@pam', password='raCz3M7WoEqbtmYemUQI', verify_ssl=False)
    proxmox.nodes('vps1').lxc(vmid).status.start.post()
    flash(f'Instance {vmid} started successfully.', 'success')
    return redirect(url_for('manage_instances'))

@app.route('/stop_instance/<int:vmid>', methods=['POST'])
@login_required
def stop_instance(vmid):
    proxmox = ProxmoxAPI('45.137.70.53', user='root@pam', password='raCz3M7WoEqbtmYemUQI', verify_ssl=False)
    proxmox.nodes('vps1').lxc(vmid).status.stop.post()
    flash(f'Instance {vmid} stopped successfully.', 'success')
    return redirect(url_for('manage_instances'))



# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Admin Routes

def create_admin_user(username, password):
    admin = User(username=username, password=password, is_admin=True)
    db.session.add(admin)
    db.session.commit()
    print(f'Admin user {username} created successfully.')


@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/delete_instance/<int:instance_id>', methods=['POST'])
@login_required
def admin_delete_instance(instance_id):
    if not current_user.is_admin:
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))
    
    instance = Instance.query.get(instance_id)
    if instance:
        db.session.delete(instance)
        db.session.commit()
        flash('Instance deleted successfully.', 'success')
    else:
        flash('Instance not found.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/give_credits', methods=['GET', 'POST'])
@login_required
def admin_give_credits():
    if not current_user.is_admin:
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        credits_to_add = int(request.form.get('credits'))
        user = User.query.filter_by(username=username).first()
        if user:
            user.credits += credits_to_add
            db.session.commit()
            flash(f'{credits_to_add} credits given to {username}.', 'success')
        else:
            flash('User not found.', 'danger')
        return redirect(url_for('admin_give_credits'))

    return render_template('admin_give_credits.html')

@app.route('/admin/remove_credits', methods=['GET', 'POST'])
@login_required
def admin_remove_credits():
    if not current_user.is_admin:
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        credits_to_remove = int(request.form.get('credits'))
        user = User.query.filter_by(username=username).first()
        if user:
            if user.credits >= credits_to_remove:
                user.credits -= credits_to_remove
                db.session.commit()
                flash(f'{credits_to_remove} credits removed from {username}.', 'success')
            else:
                flash('User does not have enough credits.', 'danger')
        else:
            flash('User not found.', 'danger')
        return redirect(url_for('admin_remove_credits'))

    return render_template('admin_remove_credits.html')


# Run Application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
        load_plans_from_json()  # Load plans from JSON file
        if not User.query.filter_by(username='admin').first():
            create_admin_user('admin', 'Allexander01')  # Change to a secure password
    app.run(host='0.0.0.0', port=5000, debug=True)
