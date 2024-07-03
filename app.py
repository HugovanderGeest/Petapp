from flask import Flask, render_template, redirect, request, url_for, flash, jsonify, send_from_directory, abort, session# Added session here
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
import os
import logging
import datetime
from werkzeug.utils import secure_filename
from PIL import Image, ExifTags
from datetime import datetime
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, URL
from wtforms_sqlalchemy.fields import QuerySelectField
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, FormField, FieldList
import requests
import pandas as pd
from flask_wtf.file import FileField, FileAllowed
from flask import current_app
from wtforms import SelectField, Form
from flask import send_from_directory
from flask import Flask, send_from_directory
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_login import current_user
from wtforms import TextAreaField, IntegerField, DateField
from flask_login import UserMixin, login_user, login_required, logout_user, current_user  # Import UserMixin and login_user
from wtforms_sqlalchemy.fields import QuerySelectMultipleField
from wtforms import SelectMultipleField, widgets
from forms import SimpleForm  # Import the form you just defined
from wtforms.validators import DataRequired, Email
import email
import csv
from flask import Response
import pytz
import json

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s', handlers=[
    logging.StreamHandler()
])

logger = logging.getLogger(__name__)

app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Specify the login view
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['GOOGLE_MAPS_API_KEY'] = 'AIzaSyDjyGyXUa6Wnapxt-7HOity5K4Ydnb--2w'
app.config['UPLOAD_FOLDER'] = 'photos'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)



def utc_to_local(utc_dt):
    if utc_dt is None: 
        return None
    if isinstance(utc_dt, str):
        # Parse the string to a datetime object
        utc_dt = datetime.strptime(utc_dt, '%Y-%m-%d %H:%M:%S')
    if utc_dt.tzinfo is None:
        # If the datetime object is naive, make it aware with UTC
        utc_dt = utc_dt.replace(tzinfo=pytz.utc)
    local_tz = pytz.timezone('Europe/Amsterdam')  # Use the Netherlands timezone
    local_dt = utc_dt.astimezone(local_tz)
    return local_tz.normalize(local_dt)  # Nor



@app.template_filter('to_local')
def to_local_filter(utc_dt):
    local_dt = utc_to_local(utc_dt)
    return local_dt.strftime("%Y-%m-%d %H:%M:%S")  # Format as Year-Month-Day Hour:Minute:Second

migrate = Migrate(app, db)

class User(db.Model, UserMixin):  # Extend User model with UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=True)
    location = db.relationship('Location', backref=db.backref('users', lazy=True))
    group = db.Column(db.String(120), nullable=True)
    badges = db.Column(db.Integer, default=0)
    profile_picture = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)  # New email field
    phone_number = db.Column(db.String(20), nullable=True)  # New phone number field    
    has_accessed_briefing = db.Column(db.Boolean, default=False)

    def __init__(self, username, password, email, phone_number, location_id=None, group=None, badges=0, is_admin=False):
        self.username = username
        self.password = generate_password_hash(password)
        self.email = email
        self.phone_number = phone_number
        self.location_id = location_id
        self.group = group
        self.badges = badges
        self.is_admin = is_admin

class WorkRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    status = db.Column(db.String(10), default='pending')  # pending, approved, denied
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('work_requests', lazy=True))
    location = db.relationship('Location', backref=db.backref('work_requests', lazy=True))

    def __repr__(self):
        return f'<WorkRequest user_id={self.user_id}, location_id={self.location_id}, status={self.status}>'

class CheckInOutLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    check_in_time = db.Column(db.DateTime, nullable=True)
    check_out_time = db.Column(db.DateTime, nullable=True)
    user = db.relationship('User', backref='check_in_out_logs')
    location = db.relationship('Location', backref='check_in_out_logs')


class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number')
    location = QuerySelectField('Location', query_factory=lambda: Location.query, allow_blank=True, get_label='name')
    is_admin = BooleanField('Admin')
    submit = SubmitField('Update')

class ChangeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Add this line
    user = db.relationship('User', backref='change_logs')  # Add this line for backref
    bar_id = db.Column(db.Integer, db.ForeignKey('bar.id'), nullable=False)
    field = db.Column(db.String, nullable=False)
    old_value = db.Column(db.String, nullable=True)
    new_value = db.Column(db.String, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


    def __repr__(self):
        return f'<ChangeLog {self.field} - Old Value: {self.old_value}, New Value: {self.new_value}, Timestamp: {self.timestamp}>'

class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

class BarPhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    bar_id = db.Column(db.Integer, db.ForeignKey('bar.id'), nullable=False)
    bar = db.relationship('Bar', backref=db.backref('photos', lazy=True))

    def __repr__(self):
        return f'<BarPhoto {self.filename} - Bar ID: {self.bar_id}>'

class ZakkenKGLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bar_id = db.Column(db.Integer, db.ForeignKey('bar.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    kg_submitted = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ZakkenKGLog bar_id={self.bar_id}, user_id={self.user_id}, kg_submitted={self.kg_submitted}, timestamp={self.timestamp}>'

class UpdateLocationForm(FlaskForm):
    submit = SubmitField('Update')


from flask_wtf import FlaskForm
from wtforms import StringField, DateField, TimeField, IntegerField, SubmitField
from wtforms.validators import Optional, URL

class LocationForm(FlaskForm):
    name = StringField('Location', validators=[Optional()])
    date = DateField('Date', format='%Y-%m-%d', validators=[Optional()])
    address = StringField('Address', validators=[Optional()])
    start_time = TimeField('Start Time', validators=[Optional()])
    amount_of_days = IntegerField('Amount of Days', validators=[Optional()])
    website_links = StringField('Website Links', validators=[Optional()])  # Removed URL validator
    max_people = IntegerField('Max People', default=10, validators=[Optional()])
    submit = SubmitField('Create Location')


class LocationSelectForm(FlaskForm):
    location = QuerySelectField('Location', query_factory=lambda: Location.query, get_label='name')
    submit = SubmitField('Update Location')

class BarForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    link = StringField('Link', validators=[DataRequired(), URL()])  # Ensure this is included if you need a direct URL field
    submit = SubmitField('Add Bar')


class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    date = db.Column(db.Date, nullable=True)
    address = db.Column(db.String(200), nullable=True)
    start_time = db.Column(db.Time, nullable=True)
    amount_of_days = db.Column(db.Integer, nullable=True)
    website_links = db.Column(db.String(200), nullable=True)
    zakken = db.Column(db.Integer, nullable=False, default=0)
    bekers = db.Column(db.Integer, nullable=False, default=0)
    url = db.Column(db.String(500), nullable=True)
    map_image = db.Column(db.String(255))
    max_people = db.Column(db.Integer, nullable=False, default=10)
    closed = db.Column(db.Boolean, default=False)  # Make sure this line is included
    pdf_path = db.Column(db.String(255), nullable=True)  # Add this line


    def __init__(self, name=None, date=None, address=None, start_time=None, amount_of_days=None, website_links=None, zakken=0, bekers=0, url=None, map_image=None, max_people=10, closed=False):
        self.name = name
        self.date = date
        self.address = address
        self.start_time = start_time
        self.amount_of_days = amount_of_days
        self.website_links = website_links
        self.zakken = zakken
        self.bekers = bekers
        self.url = url
        self.map_image = map_image
        self.max_people = max_people
        self.closed = closed



    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'date': self.date.strftime('%Y-%m-%d') if self.date else None,
            'address': self.address,
            'start_time': self.start_time.strftime('%H:%M:%S') if self.start_time else None,
            'amount_of_days': self.amount_of_days,
            'website_links': self.website_links
        }

def location():
    location = Location.query.first()  # Replace with your logic to get the correct location
    if request.method == 'POST':
        bar_name = request.form.get('bar_name')
        zakken = request.form.get('zakken')
        bekers = request.form.get('bekers')
        bar = Bar(bar_name, zakken, bekers, location.id)
        db.session.add(bar)
        db.session.commit()
        flash('Your data has been updated!')
        return redirect(url_for('location'))  # Redirect to location after updating data
    return render_template('location.html', location=location)

class BarLinkForm(FlaskForm):
    bar_number = StringField('Bar Number', validators=[DataRequired()])
    submit = SubmitField('Create Link')

class BarLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    x = db.Column(db.Float, nullable=False)  # X coordinate as percentage
    y = db.Column(db.Float, nullable=False)  # Y coordinate as percentage
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    location = db.relationship('Location', backref=db.backref('bar_locations', lazy=True))

    def __repr__(self):
        return f'<BarLocation x={self.x}, y={self.y}, location_id={self.location_id}>'

@app.route('/create_bar_link', methods=['GET', 'POST'])
def create_bar_link():
    bar_link_form = BarLinkForm()
    if bar_link_form.validate_on_submit():
        bar_number = bar_link_form.bar_number.data
        # Assuming you want to redirect to the 'bar' endpoint with the appropriate 'bar_id' parameter
        return redirect(url_for('bar', bar_id=bar_number))
    # Pass the form to your template
    return render_template('location.html', bar_link_form=bar_link_form)

class CheckInLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bar_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


    def __repr__(self):
        return f'<CheckInLog bar_id={self.bar_id}, user_id={self.user_id}, timestamp={self.timestamp}>'


class PostForm(FlaskForm):
    text = StringField('Text', validators=[DataRequired()])
    url = StringField('Google Maps URL', validators=[DataRequired(), URL()])
    submit = SubmitField('Post')

class Bar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    total_kg = db.Column(db.Integer, default=0)  # Total kilograms of zakken collected
    background_color = db.Column(db.String(10), default='#1700a1')  # New field to store color
    zakken = db.Column(db.Integer, nullable=False, default=0)
    bekers = db.Column(db.Integer, nullable=False, default=0)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    location = db.relationship('Location', backref=db.backref('bars', lazy=True))
    x = db.Column(db.Float, nullable=True)  # X coordinate as percentage
    y = db.Column(db.Float, nullable=True)  # Y coordinate as percentage
    note = db.Column(db.String(1000))  # Assuming note is just a text field for simplicity
    url = db.Column(db.String)
    link = db.Column(db.String)
    last_checked_in = db.Column(db.DateTime, nullable=True)
    last_checked_in_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    last_checked_in_user = db.relationship('User', foreign_keys=[last_checked_in_user_id], backref='checked_in_bars')
    notifications = db.relationship('Notification', backref='related_bar', lazy=True)  # Ensure unique backref name

    def __init__(self, name, location_id, zakken=0, bekers=0):
        self.name = name
        self.zakken = zakken
        self.bekers = bekers
        self.location_id = location_id

class ActivityLog(db.Model):
    __table_args__ = {'extend_existing': True}  # Add this line to extend existing table definition
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bar_id = db.Column(db.Integer, db.ForeignKey('bar.id'), nullable=False)
    field = db.Column(db.String, nullable=False)
    old_value = db.Column(db.String, nullable=True)
    new_value = db.Column(db.String, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ActivityLog {self.field} - User: {self.user.username}, Bar: {self.bar.name}>'

# Define the translation dictionary
NOTIFICATION_TYPES_TRANSLATIONS = {
    'need_bags': 'Heeft zakken nodig',
    'new_user': 'Nieuwe gebruiker',
    'update': 'Update',
    'too_many_full_bags': 'Te veel volle zakken',
    # Add other translations as needed
}

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bar_id = db.Column(db.Integer, db.ForeignKey('bar.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    note = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, bar_id, type, note=None):
        self.bar_id = bar_id
        self.type = type
        self.note = note
        self.is_read = False  # Initialize is_read to False

    @property
    def translated_type(self):
        return NOTIFICATION_TYPES_TRANSLATIONS.get(self.type, self.type)

@app.route('/bar/<int:bar_id>/update_location_link', methods=['POST'])
def update_location_link(bar_id):
    new_link = request.form.get('newLocationLink')
    # Assume you have a Bar model with a 'link' field that you want to update
    bar = Bar.query.get_or_404(bar_id)
    bar.link = new_link
    db.session.commit()
    flash('Location link updated successfully!')
    return redirect(url_for('some_view_function', bar_id=bar.id))

@app.route('/access-briefing/<int:user_id>')
def access_briefing(user_id):
    user = User.query.get_or_404(user_id)
    if not user.has_accessed_briefing:
        user.has_accessed_briefing = True
        db.session.commit()
        flash('Briefing accessed.', 'success')
    else:
        flash('Briefing already accessed.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/notifications', methods=['GET'])
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    
    # Mark all retrieved notifications as read
    for notification in user_notifications:
        notification.is_read = True
    db.session.commit()
    
    return render_template('notifications.html', notifications=user_notifications)


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    location_form = LocationForm()
    user_form = UserForm()

    logger.debug("Handling /admin route")
    
    if location_form.validate_on_submit():
        logger.debug("Location form validated successfully")
        logger.debug(f"Form data: name={location_form.name.data}, date={location_form.date.data}, address={location_form.address.data}, start_time={location_form.start_time.data}, amount_of_days={location_form.amount_of_days.data}, website_links={location_form.website_links.data}, max_people={location_form.max_people.data}")
        
        try:
            # Log existing locations
            existing_locations = Location.query.all()
            logger.debug(f"Existing locations before insert: {[loc.name for loc in existing_locations]}")
            
            location = Location(
                name=location_form.name.data,
                date=location_form.date.data,
                address=location_form.address.data,
                start_time=location_form.start_time.data,
                amount_of_days=location_form.amount_of_days.data,
                website_links=location_form.website_links.data,
                max_people=location_form.max_people.data
            )
            db.session.add(location)
            db.session.commit()
            
            # Log new locations after insert
            updated_locations = Location.query.all()
            logger.debug(f"Existing locations after insert: {[loc.name for loc in updated_locations]}")
            
            flash('Location created successfully!', 'success')
            return redirect(url_for('admin'))
        except Exception as e:
            db.session.rollback()
            flash('Error adding location to the database', 'error')
            logger.error(f"Error creating location: {e}", exc_info=True)
    else:
        logger.debug("Location form did not validate")
        logger.debug(f"Form errors: {location_form.errors}")

    users = User.query.all()
    work_requests = WorkRequest.query.all()
    locations = Location.query.all()
    notifications = Notification.query.order_by(Notification.timestamp.desc()).all()

    return render_template('admin.html', location_form=location_form, user_form=user_form, users=users, work_requests=work_requests, locations=locations, notifications=notifications)


@app.route('/add_user', methods=['POST'])
def add_user():
    form = UserForm()
    if form.validate_on_submit():
        try:
            user = User(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                phone_number=form.phone_number.data if form.phone_number.data else None,
                location_id=form.location.data.id if form.location.data else None,
                is_admin=form.is_admin.data
            )
            db.session.add(user)
            db.session.commit()
            flash('User created successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"Error adding user to the database: {e}")  # Debug print
            flash('Error adding user to the database', 'error')
    else:
        print("Form validation failed")  # Debug print
        print(form.errors)  # Debug print
    return redirect(url_for('admin'))


import logging

# Set up basic logging configuration
logging.basicConfig(level=logging.INFO)

# Create a logger for your application
logger = logging.getLogger(__name__)

@app.route('/add_location', methods=['POST'])
def add_location():
    location_form = LocationForm()
    if location_form.validate_on_submit():
        try:
            location = Location(
                name=location_form.name.data,
                date=location_form.date.data,
                address=location_form.address.data,
                start_time=location_form.start_time.data,
                amount_of_days=location_form.amount_of_days.data,
                website_links=location_form.website_links.data,
                max_people=location_form.max_people.data
            )
            db.session.add(location)
            db.session.commit()
            flash('Location created successfully!', 'success')
            logger.info(f"Location created: {location.name}")
        except Exception as e:
            db.session.rollback()
            flash('Error adding location to the database', 'error')
            logger.error(f"Error creating location: {e}")
    return redirect(url_for('admin'))

from flask import Flask, render_template, redirect, request, url_for, flash, send_file
import os
import io
import zipfile  # Correct import for the standard library
# ... other imports ...

@app.route('/download_photos')
def download_photos():
    location_filter = request.args.get('location_filter')
    if location_filter:
        photos = BarPhoto.query.join(Bar).join(Location).filter(Location.id == location_filter).all()
    else:
        photos = BarPhoto.query.all()
    
    if not photos:
        flash('No photos available to download for the selected location.', 'info')
        return redirect(url_for('view_photos'))
    
    # Create a zip file in memory
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        for photo in photos:
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo.filename)
            zf.write(photo_path, os.path.basename(photo_path))
    
    memory_file.seek(0)
    
    # Serve the zip file
    return send_file(memory_file, mimetype='application/zip', as_attachment=True, download_name='photos.zip')



@app.route('/respond_work_request/<int:request_id>', methods=['POST'])
def respond_work_request(request_id):
    work_request = WorkRequest.query.get_or_404(request_id)
    if not current_user.is_admin:
        flash('You must be an admin to perform this action.', 'error')
        return redirect(url_for('index'))

    action = request.form.get('action')
    location = work_request.location
    approved_requests_count = WorkRequest.query.filter_by(location_id=location.id, status='approved').count()

    if action == 'approve':
        if approved_requests_count < location.max_people:
            work_request.status = 'approved'
            user = User.query.get(work_request.user_id)
            user.location_id = work_request.location_id
            db.session.commit()
            flash(f'Request approved. {user.username} is now assigned to {work_request.location.name}.', 'success')
        else:
            flash(f'Cannot approve request. The location {location.name} has reached its maximum capacity of {location.max_people} people.', 'error')
    elif action == 'deny':
        work_request.status = 'denied'
        db.session.commit()
        flash('Request denied.', 'info')
    return redirect(url_for('admin'))


@app.route('/upload_photo_page', methods=['GET', 'POST'])
@login_required  # Ensure this page requires user login
def upload_photo_page():
    if request.method == 'POST':
        file = request.files['photo']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            flash('Photo uploaded successfully!')
            return redirect(url_for('some_page_to_view_photos'))  # Redirect to a page to view the uploaded photos
    return render_template('upload_photo.html')

@app.route('/upload_photo_to_view', methods=['POST'])
@login_required  # Ensure this page requires user login
def upload_photo_to_view():
    file = request.files['photo']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        flash('Photo uploaded successfully!')
        return redirect(url_for('view_photos'))  # Assuming view_photos is the correct endpoint to show uploaded photos
    else:
        flash('Invalid file type or no file uploaded.')
        return redirect(request.url)

# @app.route('/submit_kg', methods=['POST'])
# @login_required  # Ensure that the route can only be accessed by logged-in users
# def submit_kg():
#     bar_id = request.form.get('bar_id')
#     kg_list = request.form.getlist('kg[]')  # Assuming your input fields are named 'kg[]' in the HTML form

#     if bar_id:
#         bar = Bar.query.get_or_404(bar_id)
#         if bar:
#             total_kg = sum(int(kg) for kg in kg_list)  # Summing up all kg inputs

#             # Ensure there is a logged-in user
#             if not current_user.is_authenticated:
#                 flash('You must be logged in to submit kg.', 'error')
#                 return redirect(url_for('login'))  # Redirect to login page or appropriate error page

#             # Update the total kg for the bar
#             bar.total_kg += total_kg

#             # Create log entries for each kg submission
#             for kg in kg_list:
#                 log_entry = ZakkenKGLog(bar_id=bar.id, user_id=current_user.id, kg_submitted=int(kg))
#                 db.session.add(log_entry)

#             db.session.commit()
#             flash(f'Successfully submitted {total_kg} KG for {bar.name}.', 'success')
#         else:
#             flash('Bar not found.', 'error')
#     else:
#         flash('No bar selected.', 'error')

#     return redirect(url_for('zakkeneerst'))


# @app.route('/update_zakken_kg/<int:bar_id>/<int:kg>', methods=['POST'])
# def update_zakken_kg(bar_id, kg):
#     bar = Bar.query.get_or_404(bar_id)
#     if bar:
#         # Update the total kg for the bar
#         bar.total_kg += kg
#         # Create a log entry for the submission
#         log_entry = ZakkenKGLog(bar_id=bar.id, kg_submitted=kg)
#         db.session.add(log_entry)
#         db.session.commit()
#         flash(f'Successfully submitted {kg} KG for {bar.name}.', 'success')
#     else:
#         flash('Bar not found.', 'error')
#     return redirect(url_for('zakkeneerst'))


@app.route('/bar/<int:bar_id>/upload_photo', methods=['POST'])
def upload_photo(bar_id):
    if 'photo' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['photo']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Open the image using Pillow
        image = Image.open(file)
        
        # Fix orientation if needed
        try:
            for orientation in ExifTags.TAGS.keys():
                if ExifTags.TAGS[orientation]=='Orientation':
                    break
            exif=dict(image._getexif().items())
            if exif[orientation] == 3:
                image=image.rotate(180, expand=True)
            elif exif[orientation] == 6:
                image=image.rotate(270, expand=True)
            elif exif[orientation] == 8:
                image=image.rotate(90, expand=True)
        except (AttributeError, KeyError, IndexError):
            # cases: image don't have getexif
            pass

        # Optionally, resize the image here if you want to ensure images are of a uniform size
        # image = image.resize((800, 600))
        
        # Compress and save the image
        image.save(filepath, optimize=True, quality=85)  # Adjust quality for your needs
        
        # Proceed with adding a record for the photo in the database, etc.
        new_photo = BarPhoto(filename=filename, bar_id=bar_id)
        db.session.add(new_photo)
        db.session.commit()

        flash('Photo uploaded and compressed successfully!')
        return redirect(url_for('bar', bar_id=bar_id))
    else:
        flash('File type not allowed')
        return redirect(request.url)

@app.route('/photos')
def view_photos():
    locations = Location.query.all()  # Ensure this query is correctly fetching data
    location_filter = request.args.get('location_filter')
    if location_filter:
        photos = BarPhoto.query.join(Bar).join(Location).filter(Location.id == location_filter).all()
    else:
        photos = BarPhoto.query.all()
    
    if not locations:  # Debugging line to check if locations are fetched
        print("No locations found!")  # Check your console logs

    return render_template('photos.html', photos=photos, locations=locations)



@app.route('/export_zakken_kg_logs')
def export_zakken_kg_logs():
    logs = db.session.query(
        ZakkenKGLog.kg_submitted,
        ZakkenKGLog.timestamp,
        User.username.label('user_name'),
        Bar.name.label('bar_name'),
        Location.name.label('location_name')
    ).join(User, ZakkenKGLog.user_id == User.id)\
     .join(Bar, ZakkenKGLog.bar_id == Bar.id)\
     .join(Location, Bar.location_id == Location.id).all()

    data = [{
            "User Name": log.user_name,
            "Bar Name": log.bar_name,
            "Location Name": log.location_name,
            "KG Submitted": log.kg_submitted,
            "Timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        } for log in logs]
    
    df = pd.DataFrame(data)
    
    # Calculate totals per location
    totals = df.groupby('Location Name')['KG Submitted'].sum().reset_index()
    totals.columns = ['Location Name', 'Total KG']
    
    # Calculate the number of bags per location
    bag_counts = df.groupby('Location Name').size().reset_index(name='Number of Bags')
    
    # Merge totals and bag counts
    summary = pd.merge(totals, bag_counts, on='Location Name')
    
    # Append summary to the main DataFrame
    summary_df = pd.DataFrame({'User Name': '', 'Bar Name': '', 'Location Name': summary['Location Name'], 'KG Submitted': summary['Total KG'], 'Timestamp': ''})
    summary_df['Number of Bags'] = summary['Number of Bags']
    
    df = pd.concat([df, summary_df], ignore_index=True)
    
    # Define the file path
    directory = os.path.join(app.root_path, 'static')
    filepath = os.path.join(directory, 'zakken_kg_logs.xlsx')
    
    # Write the DataFrame to an Excel file
    df.to_excel(filepath, index=False)
    
    return send_from_directory(directory=directory, path='zakken_kg_logs.xlsx', as_attachment=True, download_name='zakken_kg_logs.xlsx')



@app.route('/photos/<filename>')
def uploaded_photos(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/user/<int:user_id>/upload_profile_picture', methods=['POST'])
def upload_profile_picture(user_id):
    if 'profile_picture' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['profile_picture']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        profile_folder = os.path.join('static', 'uploads', str(user_id))  # Adjusted path to 'uploads' directory within 'static'
        if not os.path.exists(profile_folder):
            os.makedirs(profile_folder)
        filepath = os.path.join(profile_folder, filename)
        file.save(filepath)
        
        # The relative path for storing in the database
        static_file_path = os.path.join('uploads', str(user_id), filename)
        
        # Update the user profile with the new image path
        user = User.query.get(user_id)
        if user:
            user.profile_picture = static_file_path  # Store the relative path
            db.session.commit()
            return jsonify({'message': 'Profile picture uploaded successfully!', 'image_url': url_for('static', filename=static_file_path)}), 200
        else:
            return jsonify({'error': 'User not found.'}), 404
        
    return jsonify({'error': 'File type not allowed'}), 400


@app.route('/download')
def download_file():
    directory = '/path/to/your/files'  # Make sure to use your actual file directory
    filename = 'example.xlsx'  # Replace with your actual file name
    return send_from_directory(directory, filename, as_attachment=True, download_name='custom_filename.xlsx')

@login_manager.user_loader
def load_user(user_id):
    # This callback is used to reload the user object from the user ID stored in the session
    return User.query.get(int(user_id))

@app.route('/')
def index():
    locations = Location.query.all()
    return render_template('index.html', locations=locations)

@app.route('/locatie/<int:location_id>')
def locatie_bars(location_id):
    location = Location.query.get_or_404(location_id)
    bars = Bar.query.filter_by(location_id=location_id).all()
    return render_template('locatie_bars.html', location=location, bars=bars)



@app.route('/bar_details/<int:bar_id>')
def view_bar(bar_id):
    bar = Bar.query.get_or_404(bar_id)
    return render_template('jouwbar.html', bar=bar)


@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    # Fetch the user by id
    user = User.query.get(id)
    if user:
        # If the user exists, delete them
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted!', 'success')
    else:
        flash('User not found!', 'error')
    # Redirect to the admin page
    return redirect(url_for('admin'))

@app.route('/uploads/<path:filename>')
def serve_user_profile_picture(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/delete_location/<int:location_id>', methods=['POST'])
def delete_location(location_id):
    location = Location.query.get_or_404(location_id)
    
    # Delete associated bars first
    bars = Bar.query.filter_by(location_id=location_id).all()
    for bar in bars:
        db.session.delete(bar)
    
    # Delete the location
    db.session.delete(location)
    db.session.commit()
    
    flash('Location and its associated bars have been deleted!', 'success')
    return redirect(url_for('admin'))


@app.route('/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    if user.is_admin:
        flash(f'{user.username} is now an admin.', 'success')
    else:
        flash(f'{user.username} is no longer an admin.', 'info')
    
    return redirect(url_for('dashboard', user_id=user.id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')



@app.route('/change_password/<int:user_id>', methods=['GET', 'POST'])
def change_password(user_id):
    # Ensure the current user is the one whose password is being changed or is an admin
    if current_user.id != user_id and not current_user.is_admin:
        flash("You are not authorized to perform this action.", "error")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('dashboard'))

        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Password updated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', user=user)

from datetime import datetime, timedelta

@app.route('/check_ins')
def check_ins():
    location_id = request.args.get('location_id')
    if location_id:
        bars = Bar.query.filter_by(location_id=location_id).all()
    else:
        bars = Bar.query.all()

    now = datetime.utcnow()
    for bar in bars:
        if bar.last_checked_in:
            delta = now - bar.last_checked_in
            bar.last_check_in_time_ago = humanize_time_since(bar.last_checked_in)
            # Calculate the percentage of the color change (0 to 120 minutes)
            minutes = min(delta.total_seconds() / 60, 120)
            bar.color_intensity = int((minutes / 120) * 100)  # from 0% to 100%
        else:
            bar.last_check_in_time_ago = "Nog geen"
            bar.color_intensity = 0  # No color if never checked in

    locations = Location.query.all()
    return render_template('check_ins.html', bars=bars, locations=locations)


@app.template_filter('humanize')
def humanize_time_since(dt):
    if dt is None:
        return "never"
        
    now = datetime.now(pytz.timezone('Europe/Amsterdam'))
    if dt.tzinfo is None:
        # Make the naive datetime object timezone-aware
        dt = pytz.timezone('Europe/Amsterdam').localize(dt)
    diff = now - dt
    
    seconds = diff.total_seconds()
    minutes = seconds // 60
    hours = minutes // 60
    days = hours // 24
    weeks = days // 7

    if seconds < 60:
        return "Net"
    elif minutes < 60:
        return f"{int(minutes)}m gel."
    elif hours < 24:
        return f"{int(hours)}u gel."
    elif days < 7:
        return f"{int(days)}d gel."
    else:
        return dt.strftime('%Y-%m-%d %H:%M:%S')  # Fall back to datetime string if older than a month




@app.route('/log_activity', methods=['POST'])
def log_activity():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Invalid request data'}), 400

    user_id = data.get('user_id')
    bar_id = data.get('bar_id')
    field = data.get('field')
    old_value = data.get('old_value')
    new_value = data.get('new_value')

    activity_log = ActivityLog(
        user_id=user_id,
        bar_id=bar_id,
        field=field,
        old_value=old_value,
        new_value=new_value
    )

    db.session.add(activity_log)
    db.session.commit()

    return jsonify({'success': 'Activity logged successfully'}), 200

@app.template_filter('time_since')
def time_since(dt):
    if dt is None:
        return "nooit"
    now = datetime.utcnow()
    diff = now - dt
    if diff.days > 0:
        return f"{diff.days} dagen geleden"
    elif diff.seconds >= 3600:
        return f"{diff.seconds // 3600} uur geleden"
    elif diff.seconds >= 60:
        return f"{diff.seconds // 60} minuten geleden"
    else:
        return "Zojuist"


@app.route('/user_dashboard/<int:user_id>', methods=['GET', 'POST'])
def user_dashboard(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user)

    if form.validate_on_submit():
        user.username = form.username.data
        user.password = generate_password_hash(form.password.data)
        
        # Check if a location is selected before updating the user's location
        if form.location.data:
            user.location_id = form.location.data.id
            flash('User details and location updated successfully!', 'success')
        else:
            flash('Please select a location for the user', 'error')
        
        db.session.commit()
        return redirect(url_for('user_dashboard', user_id=user.id))

    return render_template('user_dashboard.html', user=user, form=form)\
        
@app.route('/location/<int:user_id>/<int:location_id>', methods=['GET', 'POST'])
@login_required
def location(user_id, location_id):
    session['location_id'] = location_id  # Store location_id in session
    location = Location.query.get_or_404(location_id)
    bars = Bar.query.filter_by(location_id=location_id).all()
    bar_form = BarForm()  # For adding new bars
    bar_link_form = BarLinkForm()  # For navigating to a specific bar
    from_admin = request.args.get('from_admin', 'false').lower() == 'true'  # Capture the parameter

    if bar_form.validate_on_submit():
        new_bar = Bar(
            name=bar_form.name.data,
            zakken=0,
            bekers=0,
            location_id=location_id,
            link=bar_form.link.data
        )
        db.session.add(new_bar)
        db.session.commit()
        flash('New bar added successfully!', 'success')
        return redirect(url_for('location', user_id=user_id, location_id=location_id))

    formatted_bars = []
    for bar in bars:
        formatted_bar = {
            'id': bar.id,
            'name': bar.name,
            'total_kg': bar.total_kg,
            'background_color': bar.background_color,
            'zakken': bar.zakken,
            'bekers': bar.bekers,
            'location_id': bar.location_id,
            'last_checked_in': bar.last_checked_in.strftime('%Y-%m-%d %H:%M:%S') if bar.last_checked_in else None,
            'last_checked_in_user_id': bar.last_checked_in_user_id
        }
        formatted_bars.append(formatted_bar)

    return render_template('location.html', location=location, bars=formatted_bars, bar_form=bar_form, from_admin=from_admin, bar_link_form=bar_link_form, current_user=current_user)

@app.template_filter('hours_since')
def hours_since(dt):
    if dt is None:
        return float('inf')  # Return infinity if there's no last check-in time
    now = datetime.utcnow()
    diff = now - dt
    hours = diff.total_seconds() / 3600
    return hours

@app.route('/log_change', methods=['POST'])
@login_required  # Ensures only logged-in users can log changes
def log_change():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Invalid request data'}), 400

    # Ensure the current user is logged in
    if not current_user.is_authenticated:
        return jsonify({'error': 'User not authenticated'}), 403

    change_log = ChangeLog(
        user_id=current_user.id,  # Get the current user's ID   
        bar_id=data.get('bar_id'),
        field=data.get('field'),
        old_value=data.get('old_value'),
        new_value=data.get('new_value')
    )

    db.session.add(change_log)
    db.session.commit()

    return jsonify({'success': 'Change logged successfully'}), 200

@app.route('/notify/<notification_type>/<int:bar_id>', methods=['POST'])
def notify(notification_type, bar_id):
    bar = Bar.query.get_or_404(bar_id)
    if notification_type in ['too_many_full_bags', 'need_bags']:
        notification = Notification(bar_id=bar_id, type=notification_type)
        db.session.add(notification)
        db.session.commit()
        return jsonify({'message': 'Notification sent successfully'}), 200
    elif notification_type == 'leave_note':
        data = request.get_json()
        note = data.get('note')
        if note:
            notification = Notification(bar_id=bar_id, type='note', note=note)
            db.session.add(notification)
            db.session.commit()
            return jsonify({'message': 'Note submitted successfully'}), 200
        else:
            return jsonify({'error': 'Note content is required'}), 400
    return jsonify({'error': 'Invalid notification type'}), 400

@app.route('/bar/<int:bar_id>/update_details_and_check_in', methods=['POST'])
def update_bar_details_and_check_in(bar_id):
    # First, handle the check-in
    bar = Bar.query.get_or_404(bar_id)
    bar.last_checked_in = datetime.utcnow()
    bar.last_checked_in_user_id = current_user.id  # Assuming current_user is the logged-in user
    db.session.commit()

    # Then, process the KG submissions
    try:
        zakken_kg_submissions = []
        for key, value in request.form.items():
            if key.startswith('zakken[') and key.endswith('].kg'):
                value = value.replace(',', '.')
                kg = float(value)
                zakken_kg_submissions.append(kg)
                log_entry = ZakkenKGLog(bar_id=bar_id, user_id=current_user.id, kg_submitted=kg)
                db.session.add(log_entry)
        db.session.commit()
        flash(f'Successfully checked in and submitted {len(zakken_kg_submissions)} zakken KG entries for bar {bar.name}.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while processing your submission. Please try again.', 'error')
        return redirect(url_for('bar', bar_id=bar_id))

    # Redirect to the location route after processing
    return redirect(url_for('location', user_id=current_user.id, location_id=bar.location_id))

@app.route('/toggle_check/<int:location_id>', methods=['POST'])
@login_required
def toggle_check(location_id):
    log = CheckInOutLog.query.filter_by(user_id=current_user.id, location_id=location_id, check_out_time=None).first()
    if log:
        log.check_out_time = datetime.utcnow()
        db.session.commit()
        flash('Checked out successfully!', 'success')
    else:
        new_log = CheckInOutLog(user_id=current_user.id, location_id=location_id, check_in_time=datetime.utcnow())
        db.session.add(new_log)
        db.session.commit()
        flash('Checked in successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/check_in_out_logs')
@login_required
def check_in_out_logs():
    location_id = request.args.get('location')
    user_id = request.args.get('user')
    day = request.args.get('day')

    logs_query = CheckInOutLog.query

    if location_id:
        logs_query = logs_query.filter_by(location_id=location_id)
    if user_id:
        logs_query = logs_query.filter_by(user_id=user_id)
    if day:
        day_start = datetime.strptime(day, '%Y-%m-%d')
        day_end = day_start + timedelta(days=1)
        logs_query = logs_query.filter(CheckInOutLog.check_in_time >= day_start, CheckInOutLog.check_in_time < day_end)

    logs = logs_query.order_by(CheckInOutLog.check_in_time.desc()).all()

    locations = Location.query.all()
    users = User.query.all()
    selected_location = int(location_id) if location_id else None
    selected_user = int(user_id) if user_id else None
    selected_day = day if day else ""

    # Calculate total time per user
    total_time_per_user = {}
    for log in logs:
        if log.check_in_time and log.check_out_time:
            duration = log.check_out_time - log.check_in_time
            if log.user.username not in total_time_per_user:
                total_time_per_user[log.user.username] = duration
            else:
                total_time_per_user[log.user.username] += duration

    return render_template('check_in_out_logs.html', logs=logs, locations=locations, users=users, selected_location=selected_location, selected_user=selected_user, selected_day=selected_day, total_time_per_user=total_time_per_user)

class DayTimeEntryForm(FlaskForm):
    day = StringField('Day', validators=[DataRequired()])
    time = StringField('Time', validators=[DataRequired()])


class LocationAttribute(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    key = db.Column(db.String(255), nullable=False)
    value = db.Column(db.String(255))

    location = db.relationship('Location', backref=db.backref('attributes', lazy=True))

    def __repr__(self):
        return f'<LocationAttribute {self.key}: {self.value}>'

@app.route('/check_in_logs')
@login_required
def check_in_logs():
    # Fetch the check-in logs from the database
    check_in_logs = CheckInOutLog.query.all()
    locations = Location.query.all()

    # Calculate total time per user
    from collections import defaultdict
    from datetime import timedelta

    total_time_per_user = defaultdict(timedelta)

    for log in check_in_logs:
        if log.check_in_time and log.check_out_time:
            total_time_per_user[log.user.username] += (log.check_out_time - log.check_in_time)

    return render_template('check_in_out_logs.html', check_in_logs=check_in_logs, locations=locations, total_time_per_user=total_time_per_user)



@app.route('/briefings')
def show_briefings():
    all_briefings = Location.query.all()  # This assumes locations are the same as briefings; adjust if necessary
    return render_template('briefings.html', briefings=all_briefings)


from flask import request, render_template

@app.route('/change_log')
def change_log():
    location_id = request.args.get('location_id')

    # Start constructing the query for ChangeLog and associated tables
    query = db.session.query(
        ChangeLog, Bar.name.label('bar_name')
    ).join(Bar, ChangeLog.bar_id == Bar.id)

    # Apply the location filter if a location ID is provided
    if location_id and location_id.strip():
        query = query.join(Location, Bar.location_id == Location.id).filter(Location.id == location_id)

    changes_with_bar_names = query.all()

    # Group changes by bar to display in the template
    changes_grouped_by_bar = {}
    for change, bar_name in changes_with_bar_names:
        bar_changes = changes_grouped_by_bar.setdefault(bar_name, [])
        bar_changes.append(change)

    # Similarly, handle the query for ZakkenKGLog entries
    zakken_kg_log_query = db.session.query(
        ZakkenKGLog.bar_id, Bar.name, db.func.sum(ZakkenKGLog.kg_submitted).label('total_kg')
    ).join(Bar, ZakkenKGLog.bar_id == Bar.id)

    if location_id and location_id.strip():
        zakken_kg_log_query = zakken_kg_log_query.join(Location, Bar.location_id == Location.id)\
                                                 .filter(Location.id == location_id)

    zakken_kg_logs_grouped = zakken_kg_log_query.group_by(ZakkenKGLog.bar_id, Bar.name).order_by(Bar.name).all()

    # Fetch locations for the dropdown filter
    locations = Location.query.all()

    # Fetch detailed logs for each bar separately
    detailed_logs_by_bar = {}
    for bar_id, _, _ in zakken_kg_logs_grouped:
        detailed_logs = db.session.query(
            ZakkenKGLog,
            User.username,
            Bar.name.label('bar_name')
        ).join(User, ZakkenKGLog.user_id == User.id)\
         .join(Bar, ZakkenKGLog.bar_id == Bar.id)\
         .filter(ZakkenKGLog.bar_id == bar_id)\
         .order_by(ZakkenKGLog.timestamp.desc()).all()
        detailed_logs_by_bar[bar_id] = detailed_logs

    # Render the template with all necessary data
    return render_template('change_log.html',
                           changes_grouped_by_bar=changes_grouped_by_bar,
                           zakken_kg_logs_grouped=zakken_kg_logs_grouped,
                           detailed_logs_by_bar=detailed_logs_by_bar,
                           locations=locations)  # Include locations in the context for the dropdown


from io import BytesIO
import pandas as pd
from flask import send_file, flash, redirect, url_for

@app.route('/export_check_ins')
def export_check_ins():
    # Fetch data from CheckInLog with additional details
    logs = db.session.query(
        User.username,
        Bar.name.label('bar_name'),
        Location.name.label('location_name'),
        CheckInLog.timestamp
    ).join(User, User.id == CheckInLog.user_id) \
    .join(Bar, Bar.id == CheckInLog.bar_id) \
    .join(Location, Location.id == Bar.location_id) \
    .all()

    if not logs:
        flash('No check-in data available to export.', 'info')
        return redirect(url_for('check_ins'))

    # Convert data to DataFrame
    df = pd.DataFrame([{
        'User Name': username,
        'Bar Name': bar_name,
        'Location Name': location_name,
        'Timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
    } for username, bar_name, location_name, timestamp in logs])

    # Convert DataFrame to Excel
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Check-In Logs')

    output.seek(0)

    # Set the download headers
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name="check-in_logs.xlsx"
    )

@app.route('/delete_notification/<int:notification_id>', methods=['POST'])
@login_required
def delete_notification(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    
    # Check if the current user is authorized to delete the notification
    if not current_user.is_admin:
        flash('You do not have permission to delete this notification.', 'error')
        return redirect(url_for('admin'))
    
    db.session.delete(notification)
    db.session.commit()
    
    flash('Notification has been deleted!', 'success')
    return redirect(url_for('admin'))



@app.template_filter('to_local')
def to_local_filter(utc_dt):
    return utc_to_local(utc_dt)


@app.route('/add_bar_to_location/<int:location_id>', methods=['POST'])
def add_bar_to_location(location_id):
    bar_name = request.form.get('bar_name')
    
    if bar_name:
        new_bar = Bar(name=bar_name, location_id=location_id)
        db.session.add(new_bar)
        db.session.commit()
        
        # Log the creation of the bar
        logger.info(f"Bar created: {new_bar.name} (ID: {new_bar.id})")
        
        return jsonify({'success': 'Bar added successfully', 'bar_name': new_bar.name, 'bar_id': new_bar.id})
    return jsonify({'error': 'Missing data'}), 400

@app.route('/location_details/<int:location_id>', methods=['GET', 'POST'])
def location_details(location_id):
    location = Location.query.get_or_404(location_id)
    form = SimpleForm()  # Create an instance of the form
    all_users = User.query.all()  # Fetch all users for the dropdown

    if request.method == 'POST':
        if 'user_id' in request.form:
            # Handle adding a user to this location
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user:
                user.location_id = location_id
                db.session.commit()
                flash('User added to location successfully!', 'success')
            else:
                flash('User not found.', 'error')
        
        if form.validate_on_submit():
            # Handle dynamic fields updates
            LocationAttribute.query.filter_by(location_id=location_id).delete()
            keys = request.form.getlist('dynamicField_key[]')
            values = request.form.getlist('dynamicField_value[]')
            for key, value in zip(keys, values):
                if key:  # Ensure there is a key
                    new_attribute = LocationAttribute(location_id=location_id, key=key, value=value)
                    db.session.add(new_attribute)
            db.session.commit()
            flash('Location updated with dynamic fields!', 'success')
            return redirect(url_for('view_location', location_id=location_id))

    attributes = location.attributes
    return render_template('location_details.html', location=location, attributes=attributes, form=form, all_users=all_users)

@app.route('/location/<int:location_id>/add_user', methods=['POST'])
def add_user_to_location(location_id):
    user_id = request.form.get('user_id')
    user = User.query.get(user_id)
    if user:
        user.location_id = location_id
        db.session.commit()
        flash('User added to location successfully!', 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('location_details', location_id=location_id))


@app.route('/view_location/<int:location_id>')
def view_location(location_id):
    location = Location.query.get_or_404(location_id)
    attributes = location.attributes  # Fetching dynamic attributes of the location
    users = User.query.filter_by(location_id=location_id).all()  # Fetching all users associated with this location
    return render_template('view_location.html', location=location, attributes=attributes, users=users)

@app.route('/edit_location/<int:location_id>', methods=['GET'])
def edit_location(location_id):
    location = Location.query.get_or_404(location_id)
    return render_template('edit_location.html', location=location)

@app.route('/update_location/<int:location_id>', methods=['POST'])
def update_location(location_id):
    location = Location.query.get_or_404(location_id)
    location.name = request.form['name']
    # Clear existing attributes
    LocationAttribute.query.filter_by(location_id=location_id).delete()
    # Add new or updated attributes
    keys = request.form.getlist('dynamicField_key[]')
    values = request.form.getlist('dynamicField_value[]')
    for key, value in zip(keys, values):
        if key and value:
            new_attr = LocationAttribute(location_id=location_id, key=key, value=value)
            db.session.add(new_attr)
    db.session.commit()
    return redirect(url_for('view_location', location_id=location_id))

from flask import Flask, render_template, redirect, request, url_for, flash, send_file
from werkzeug.utils import secure_filename
import os

# Configuration
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')  # Ensure this directory exists
ALLOWED_EXTENSIONS = {'pdf'}

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route to handle PDF upload
@app.route('/upload_pdf/<int:location_id>', methods=['GET', 'POST'])
@login_required
def upload_pdf(location_id):
    if request.method == 'POST':
        if 'pdf_file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['pdf_file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            # Assuming you have a Location model and a 'pdf_path' column
            location = Location.query.get_or_404(location_id)
            location.pdf_path = filename
            db.session.commit()
            flash('PDF uploaded successfully!')
            return redirect(url_for('location_details', location_id=location_id))
    return render_template('upload_pdf.html', location_id=location_id)


@app.route('/bar/<int:bar_id>/update_color', methods=['POST'])
def update_bar_color(bar_id):
    bar = Bar.query.get_or_404(bar_id)
    new_color = request.form.get('color')
    bar.background_color = new_color
    db.session.commit()
    # Assuming each bar has a location_id attribute to find its associated location
    # Redirect back to the location details page
    return redirect(url_for('admin'))

@app.route('/bar/<int:bar_id>', methods=['GET', 'POST'])
def bar(bar_id):
    from_admin = request.args.get('from_admin', 'false').lower() == 'true'
    session['bar_id'] = bar_id  # Store bar_id in session
    bar = Bar.query.get_or_404(bar_id)
    user = User.query.get_or_404(bar.location.users[0].id)  # Fetch the first user of the bar's location

    # Ensure that the link fallbacks correctly if bar.link is not set
    link = bar.link if bar.link else (Bar.query.first().link if Bar.query.first() else "")

    if request.method == 'POST':
        # If the method is POST, handle the form submission here (if any forms exist)
        return redirect(url_for('bar', bar_id=bar_id))

    # Pass the bar object to the template, which includes the last_checked_in field
    return render_template('bar.html', bar=bar, link=link, user=user, from_admin=from_admin)



@app.route('/bar/<int:bar_id>/update', methods=['POST'])
def update_bar(bar_id):
    data = request.get_json()
    print(f"Received data: {data}")  # Debugging line

    if not data:
        return jsonify({'error': 'Invalid request data'}), 400

    field = data.get('field')
    increment = data.get('increment', 0)
    print(f"Field: {field}, Increment: {increment}")  # Debugging line

    valid_fields = ['zakken_gekregen', 'volle_zakken_opgehaald']

    if field in valid_fields and isinstance(increment, int):
        bar = Bar.query.get_or_404(bar_id)
        current_value = getattr(bar, field, 0)
        new_value = current_value + increment
        setattr(bar, field, new_value)
        db.session.commit()
        return jsonify({field: new_value})
    else:
        return jsonify({'error': 'Invalid field or increment value'}), 400
    
@app.route('/toggle_location_status/<int:location_id>', methods=['POST'])
@login_required
def toggle_location_status(location_id):
    try:
        location = Location.query.get_or_404(location_id)
        location.closed = not location.closed
        db.session.commit()
        status = 'closed' if location.closed else 'open'
        flash(f"Location '{location.name}' status changed to {status}.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to update the status of location '{location.name}'.", 'error')
    return redirect(url_for('admin'))

    
@app.route('/bar/<int:bar_id>/check_in', methods=['POST'])
def check_in_bar(bar_id):
    print(f"Attempting to check in at bar ID: {bar_id} by user ID: {current_user.id}")
    # Retrieve the bar instance
    bar = Bar.query.get_or_404(bar_id)

    # Update the last_checked_in timestamp for the bar
    bar.last_checked_in = datetime.utcnow()
    bar.last_checked_in_user_id = current_user.id

    # Log the check-in in a separate log table
    new_check_in = CheckInLog(bar_id=bar_id, user_id=current_user.id, timestamp=bar.last_checked_in)
    db.session.add(new_check_in)

    # Commit the changes to the database
    db.session.commit()

    print(f"Check-in logged: {new_check_in}")
    flash('Successfully checked in.', 'success')

    # Redirect to a relevant page, such as a location overview or back to the bar details
    return redirect(url_for('location', user_id=current_user.id, location_id=bar.location_id))


@app.route('/save_bar_location', methods=['POST'])
def save_bar_location():
    x = request.form.get('x')
    y = request.form.get('y')
    bar_id = request.form.get('bar_id')

    try:
        bar = Bar.query.get(bar_id)
        if bar:
            bar.x = float(x)
            bar.y = float(y)
            db.session.commit()
            return jsonify({'success': 'Bar location updated successfully', 'x': x, 'y': y})
        else:
            return jsonify({'error': 'Bar not found'}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    


@app.route('/get_bars/<int:location_id>', methods=['GET'])
def get_bars(location_id):
    # Fetch only bars that belong to the given location ID and have valid x, y coordinates
    bars = Bar.query.filter(
        Bar.location_id == location_id,
        Bar.x != None,
        Bar.y != None
    ).all()

    bars_data = [{
        'id': bar.id,
        'name': bar.name,
        'x': bar.x,
        'y': bar.y,
        'background_color': bar.background_color
    } for bar in bars]

    return jsonify(bars_data)

@app.route('/bar_notes')
def bar_notes():
    location_query = request.args.get('location')  # Get location name from query parameters
    if location_query:
        # Filter bars by the location name
        bars_with_notes = Bar.query.join(Location).filter(Location.name == location_query, Bar.note.isnot(None)).all()
    else:
        # No filter applied, fetch all bars with notes
        bars_with_notes = Bar.query.filter(Bar.note.isnot(None)).all()

    # Fetch all locations to populate the dropdown filter in the template
    locations = Location.query.all()
    return render_template('bar_notes.html', bars=bars_with_notes, locations=locations)

@app.route('/bar/<int:bar_id>/update_details', methods=['POST'])
def update_bar_details(bar_id):
    # Ensure the user is authenticated
    if not current_user.is_authenticated:
        flash('You need to be logged in to perform this action.', 'error')
        return redirect(url_for('login'))

    bar = Bar.query.get_or_404(bar_id)

    try:
        # Process form data
        zakken_kg_submissions = []
        for key, value in request.form.items():
            if key.startswith('zakken[') and key.endswith('].kg'):
                # Replace comma with dot for decimal numbers
                value = value.replace(',', '.')
                try:
                    kg = float(value)
                    zakken_kg_submissions.append(kg)
                    # Create and add each ZakkenKGLog entry to the session
                    log_entry = ZakkenKGLog(bar_id=bar_id, user_id=current_user.id, kg_submitted=kg)
                    db.session.add(log_entry)
                except ValueError:
                    # Handle the case where conversion to float fails
                    flash('Invalid number format.', 'error')
                    return redirect(url_for('bar', bar_id=bar_id))

        db.session.commit()

        # For debugging: Print or log the processed submissions
        print(f"Processed zakken KG submissions for bar {bar_id}: {zakken_kg_submissions}")

        # Feedback to user
        flash(f'Successfully submitted {len(zakken_kg_submissions)} zakken KG entries for bar {bar.name}.', 'success')

    except Exception as e:
        db.session.rollback()
        print(e)  # For debugging: print the exception to the console or log it.
        flash('An error occurred while processing your submission. Please try again.', 'error')

    return redirect(url_for('bar', bar_id=bar_id))

@app.route('/map/<int:location_id>', methods=['GET', 'POST'])
def map_page(location_id):
    location = Location.query.get_or_404(location_id)
    bars = Bar.query.filter_by(location_id=location_id).all()

    if request.method == 'POST' and 'map_photo' in request.files:
        file = request.files['map_photo']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            location.map_image = filename  # Save the filename in the database
            db.session.commit()
            flash('Map photo uploaded successfully!')
            return redirect(url_for('map_page', location_id=location_id))

    filename = location.map_image  # Retrieve the filename from the database to display
    if filename is None:
        flash('No map photo available. Please upload one.')
    
    return render_template('map.html', location=location, bars=bars, filename=filename)


@app.route('/zakken_kg_log')
def zakken_kg_log():
    # Assuming you have admin check and login requirement
    logs = ZakkenKGLog.query.order_by(ZakkenKGLog.timestamp.desc()).all()
    return render_template('change_log.html', zakken_kg_logs=logs)

@app.route('/upload_map_photo', methods=['POST'])
@login_required  # Require user to be logged in
def upload_map_photo():
    if 'map_photo' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['map_photo']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        flash('Map photo uploaded successfully!')
        # Add any additional handling here, like saving to a database, if necessary
        return redirect(url_for('some_function_to_view_or_use_the_map', filename=filename))
    else:
        flash('File type not allowed')
        return redirect(request.url)


def log_change(user_id, bar_id, field, old_value, new_value):
    change_log = ChangeLog(
        user_id=user_id,
        bar_id=bar_id,
        field=field,
        old_value=str(old_value),
        new_value=str(new_value),
        timestamp=datetime.utcnow()
    )
    db.session.add(change_log)
    db.session.commit()

@app.route('/bar/<int:bar_id>/leave_note', methods=['POST'])
def leave_note_for_bar(bar_id):
    bar = Bar.query.get_or_404(bar_id)
    note = request.form.get('bar_note')
    if note:
        # Save the note in the database (if you're doing this)
        bar.note = note
        db.session.commit()

        # Save the note to a text file
        with open("notes_log.txt", "a") as file:
            # Prepare the data to be written
            timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            user_info = f"{current_user.username} (ID: {current_user.id})"
            bar_info = f"{bar.name} (ID: {bar.id})"
            location_info = f"{bar.location.name} (ID: {bar.location.id})"
            note_info = note.replace('\n', ' ').replace('\r', '')  # Flatten the note into one line

            # Write the data
            file.write(f"{timestamp} | {user_info} | {location_info} | {bar_info} | Note: {note_info}\n")

        flash('Your note has been saved!', 'success')
    else:
        flash('Please enter a note before submitting.', 'error')
    return redirect(url_for('bar', bar_id=bar_id))


@app.route('/bar/<int:bar_id>/update-link', methods=['POST'])
def update_bar_link(bar_id):
    data = request.get_json()
    if data and 'link' in data:
        bar = Bar.query.get_or_404(bar_id)  # Ensure bar exists or return 404
        bar.link = data['link']  # Update the bar's link
        db.session.commit()  # Save changes to the database
        return jsonify({'message': 'Link updated successfully'}), 200
    else:
        return jsonify({'error': 'Invalid request'}), 

@app.route('/activity_log')
def activity_log():
    # Fetch the activity log entries from the database
    activity_log_entries = ActivityLog.query.all()  # Example; adjust based on your actual data model and needs
    # Render a template or return a JSON response with these entries
    return render_template('activity_log.html', activity_log=activity_log_entries)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/submit_link', methods=['POST'])
def submit_link():
    link = request.form['link']
    bar_id = request.form['bar_id']  # Assuming you have a hidden input field named 'bar_id' in your form
    bar = Bar.query.get(bar_id)
    if bar:
        bar.link = link
        db.session.commit() 
    return redirect(url_for('bar', bar_id=bar_id))

@app.route('/delete_log/<int:log_id>', methods=['POST'])
def delete_log(log_id):
    log = ZakkenKGLog.query.get_or_404(log_id)
    db.session.delete(log)
    db.session.commit()
    flash('Log entry deleted successfully.', 'success')
    return redirect(url_for('change_log'))  # Redirect to the change log page or wherever appropriate

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user
    last_check_in_log = CheckInOutLog.query.filter_by(user_id=user.id, check_out_time=None).order_by(CheckInOutLog.check_in_time.desc()).first()
    last_check_out_log = CheckInOutLog.query.filter_by(user_id=user.id).filter(CheckInOutLog.check_out_time.isnot(None)).order_by(CheckInOutLog.check_out_time.desc()).first()

    current_check_in = last_check_in_log if last_check_in_log else None
    last_check_out_time = last_check_out_log.check_out_time if last_check_out_log else None

    return render_template(
        'dashboard.html',
        username=user.username,
        location_name=user.location.name if user.location else 'No location set',
        profile_picture=user.profile_picture,
        current_check_in=current_check_in,
        last_check_out_time=last_check_out_time,
        user=user
    )

@app.route('/check_in/<int:location_id>', methods=['GET', 'POST'])
@login_required
def check_in(location_id):
    location = Location.query.get_or_404(location_id)
    log = CheckInOutLog(user_id=current_user.id, location_id=location_id, check_in_time=datetime.utcnow())
    db.session.add(log)
    db.session.commit()
    flash('Checked in successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/check_out/<int:location_id>', methods=['GET', 'POST'])
@login_required
def check_out(location_id):
    log = CheckInOutLog.query.filter_by(user_id=current_user.id, location_id=location_id, check_out_time=None).first_or_404()
    log.check_out_time = datetime.utcnow()
    db.session.commit()
    flash('Checked out successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/assign_location/<int:user_id>', methods=['GET', 'POST'])
def assign_location(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user)
    
    if form.validate_on_submit():
        user.username = form.username.data  # Assuming you want to possibly update this as well
        user.password = form.password.data  # And this, though consider hashing the password before saving
        user.location_id = form.location.data.id
        db.session.commit()
        flash('User location updated successfully!', 'success')
        return redirect(url_for('admin'))  # Redirect to /admin
    
    return render_template('assign_location.html', form=form)

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.config['STATIC_FOLDER'], filename)

@app.route('/list_locations')
def list_locations():
    locations = Location.query.all()
    locations_dict = [location.to_dict() for location in locations]
    return render_template('list.html', locations=locations_dict)


@app.route('/request_to_work/<int:location_id>', methods=['POST'])
@login_required
def request_to_work(location_id):
    logger.debug(f"Request received for location ID: {location_id} by user ID: {current_user.id}")
    existing_request = WorkRequest.query.filter_by(user_id=current_user.id, location_id=location_id).first()
    if existing_request:
        logger.info('User has already requested this location.')
        flash('You have already requested this location!', 'info')
    else:
        new_request = WorkRequest(user_id=current_user.id, location_id=location_id)
        db.session.add(new_request)
        db.session.commit()
        logger.info('Request sent successfully.')
        flash('Request sent successfully!', 'success')
    return redirect(url_for('list_locations'))



@app.route('/backup_and_restore_users', methods=['GET'])
def backup_and_restore_users():
    # Backup users
    users = User.query.all()
    users_data = []
    for user in users:
        user_data = {
            'username': user.username,
            'password': user.password,
            'email': user.email,
            'phone_number': user.phone_number,
            'is_admin': user.is_admin
        }
        users_data.append(user_data)
    
    # Save to a temporary file
    with open('users_backup.json', 'w') as f:
        json.dump(users_data, f)
    
    # Drop all tables
    db.drop_all()
    
    # Recreate all tables
    db.create_all()
    
    # Restore users
    with open('users_backup.json', 'r') as f:
        users_data = json.load(f)
        for user_data in users_data:
            user = User(
                username=user_data['username'],
                password=user_data['password'],
                email=user_data['email'],
                phone_number=user_data['phone_number'],
                is_admin=user_data['is_admin']
            )
            db.session.add(user)
        db.session.commit()
    
    return 'Backup and restore completed successfully.'

@app.route('/remove_bar/<int:bar_id>', methods=['POST'])
def remove_bar(bar_id):
    bar = Bar.query.get_or_404(bar_id)
    db.session.delete(bar)
    db.session.commit()
    return jsonify({'success': 'Bar removed successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)  