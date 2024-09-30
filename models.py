from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('plan.id'), nullable=True)
    credits = db.Column(db.Integer, default=5000)

    instances = db.relationship('Instance', backref='owner', lazy=True)


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

    user = db.relationship('User', backref=db.backref('instances', lazy=True))
