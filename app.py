from flask import Flask, render_template, redirect, request, url_for, flash, jsonify, send_from_directory, abort, session# Added session here
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
import os
import logging
import datetime
from werkzeug.utils import secure_filename
from PIL import Image
from datetime import datetime
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, URL
from wtforms_sqlalchemy.fields import QuerySelectField
from flask import send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from flask import current_app
from wtforms import SelectField, Form
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_login import current_user
from flask_login import UserMixin, login_user, login_required, logout_user, current_user  # Import UserMixin and login_user

app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Specify the login view
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['GOOGLE_MAPS_API_KEY'] = 'AIzaSyDjyGyXUa6Wnapxt-7HOity5K4Ydnb--2w'
app.config['UPLOAD_FOLDER'] = 'photos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


db = SQLAlchemy(app)

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

    def __init__(self, username, password, location_id=None, group=None, badges=0, is_admin=False):
        self.username = username
        self.password = generate_password_hash(password)
        self.location_id = location_id
        self.group = group
        self.badges = badges
        self.is_admin = is_admin


class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    location = QuerySelectField('Location', query_factory=lambda: Location.query, allow_blank=True, get_label='name')
    is_admin = BooleanField('Admin')  # Add this line to include an admin checkbox
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

class BarPhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    bar_id = db.Column(db.Integer, db.ForeignKey('bar.id'), nullable=False)
    bar = db.relationship('Bar', backref=db.backref('photos', lazy=True))

    def __repr__(self):
        return f'<BarPhoto {self.filename} - Bar ID: {self.bar_id}>'



class LocationForm(FlaskForm):
    name = StringField('Location', validators=[DataRequired()])
    submit = SubmitField('Create Location')

class LocationSelectForm(FlaskForm):
    location = QuerySelectField('Location', query_factory=lambda: Location.query, get_label='name')
    submit = SubmitField('Update Location')

class BarForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    link = StringField('Link', validators=[DataRequired(), URL()])  # Ensure this is included if you need a direct URL field
    submit = SubmitField('Add Bar')


class Location(db.Model):
    __tablename__ = 'location'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    zakken = db.Column(db.Integer, nullable=False, default=0)
    bekers = db.Column(db.Integer, nullable=False, default=0)
    url = db.Column(db.String(500), nullable=True)

    def __init__(self, name, zakken=0, bekers=0, url=None):
        self.name = name
        self.zakken = zakken
        self.bekers = bekers
        self.url = url

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

@app.route('/create_bar_link', methods=['GET', 'POST'])
def create_bar_link():
    bar_link_form = BarLinkForm()
    if bar_link_form.validate_on_submit():
        bar_number = bar_link_form.bar_number.data
        # Assuming you want to redirect to the 'bar' endpoint with the appropriate 'bar_id' parameter
        return redirect(url_for('bar', bar_id=bar_number))
    # Pass the form to your template
    return render_template('location.html', bar_link_form=bar_link_form)


class PostForm(FlaskForm):
    text = StringField('Text', validators=[DataRequired()])
    url = StringField('Google Maps URL', validators=[DataRequired(), URL()])
    submit = SubmitField('Post')

class Bar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    zakken_gekregen = db.Column(db.Integer, default=0)
    volle_zakken_opgehaald = db.Column(db.Integer, default=0)
    kg_van_zak = db.Column(db.Integer, default=0)
    url = db.Column(db.String)
    link = db.Column(db.String)
    note = db.Column(db.String, nullable=True)  # Add this line to include a note field
    change_log = db.Column(db.String, default="", nullable=True)
    activity_log = db.relationship('ActivityLog', backref='bar', lazy=True)
    last_checked_in = db.Column(db.DateTime, nullable=True)

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    zakken = db.Column(db.Integer, nullable=False, default=0)
    bekers = db.Column(db.Integer, nullable=False, default=0)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)

    location = db.relationship('Location', backref=db.backref('bars', lazy=True))

    def __init__(self, name, location_id, zakken=0, bekers=0):
        self.name = name
        self.zakken = zakken
        self.bekers = bekers
        self.location_id = location_id

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bar_id = db.Column(db.Integer, db.ForeignKey('bar.id'), nullable=False)
    field = db.Column(db.String, nullable=False)
    old_value = db.Column(db.String, nullable=True)
    new_value = db.Column(db.String, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ActivityLog {self.field} - User: {self.user.username}, Bar: {self.bar.name}>'


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    form = UserForm()
    location_form = LocationForm()
    if form.validate_on_submit():
        # Creating the user as before
        user = User(
            username=form.username.data,
            password=form.password.data,
            location_id=form.location.data.id if form.location.data else None,
            is_admin=form.is_admin.data
        )
        db.session.add(user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('admin'))  # Redirect back to the admin page to refresh the list of users

    # Moved the users query after the if block for form validation.
    # This ensures it runs after a new user is added, thus including the new user in the query result.
    users = User.query.all()

    # Handling location form submission remains unchanged
    if location_form.validate_on_submit():
        location = Location(name=location_form.name.data)
        db.session.add(location)
        db.session.commit()
        flash('Location created successfully!', 'success')

    locations = Location.query.all()
    # Now 'users' includes any new user added by the form submission.
    return render_template('admin.html', form=form, location_form=location_form, users=users, locations=locations)

@app.route('/bar/<int:bar_id>/upload_photo', methods=['POST'])
@login_required
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
    photos = BarPhoto.query.all()
    return render_template('photos.html', photos=photos)


@app.route('/photos/<filename>')
def uploaded_photos(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)



@login_manager.user_loader
def load_user(user_id):
    # This callback is used to reload the user object from the user ID stored in the session
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('/index.html')

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            print(f"Logging in user: {user.username}, Admin: {user.is_admin}")  # Debug print
            if user.is_admin:
                return redirect(url_for('admin'))
            return redirect(url_for('dashboard'))
        else:
            flash('Verkeerd Naam of wachtwoord, vraag een admin om hulp', 'error')  # Flash a message if login fails
            return redirect(url_for('index'))  # Redirect back to the index page
    # Return a login template if the method is not POST or no valid conditions are met
    return render_template('login.html')


@app.route('/check_ins')
def check_ins():
    location_id = request.args.get('location_id')
    if location_id:
        bars = Bar.query.filter_by(location_id=location_id).all()
    else:
        bars = Bar.query.all()
    
    locations = Location.query.all()  # Fetch all locations to display as filter options
    return render_template('check_ins.html', bars=bars, locations=locations)

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
def time_since(dt, default="just now"):
    now = datetime.utcnow()
    diff = now - dt if dt else None

    if diff is None:
        return default

    periods = [
        (diff.days // 365, "year", "years"),
        (diff.days // 30, "month", "months"),
        (diff.days, "day", "days"),
        (diff.seconds // 3600, "hour", "hours"),
        (diff.seconds // 60, "minute", "minutes"),
        (diff.seconds, "second", "seconds"),
    ]

    for period, singular, plural in periods:
        if period:
            return f"{period} {singular if period == 1 else plural} ago"

    return default

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

    return render_template('user_dashboard.html', user=user, form=form)

@app.route('/location/<int:user_id>/<int:location_id>', methods=['GET', 'POST'])
@login_required  # Use login_required to ensure the user is logged in
def location(user_id, location_id):
    session['location_id'] = location_id  # Store location_id in session
    location = Location.query.get_or_404(location_id)
    bars = Bar.query.filter_by(location_id=location_id).all()
    bar_form = BarForm()  # For adding new bars
    bar_link_form = BarLinkForm()  # For navigating to a specific bar
    from_admin = request.args.get('from_admin', 'false').lower() == 'true'  # Capture the parameter

    if bar_form.validate_on_submit():
        # Create a new Bar instance with form data
        new_bar = Bar(
            name=bar_form.name.data,
            zakken=0,  # Assuming default values or you might want to include these in your form
            bekers=0,  # Assuming default values
            location_id=location_id,
            link=bar_form.link.data  # Assuming your form has a 'link' field
        )
        db.session.add(new_bar)
        db.session.commit()
        flash('New bar added successfully!', 'success')
        return redirect(url_for('location', location_id=location_id))  # Redirect back to the location page

    if bar_link_form.validate_on_submit():
        # Redirect to the specific bar page
        bar_number = bar_link_form.bar_number.data
        return redirect(url_for('bar', bar_id=bar_number))

    return render_template('location.html', location=location, bars=bars, bar_form=bar_form, from_admin=from_admin, bar_link_form=bar_link_form, current_user=current_user)

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

@app.route('/change_log')
def change_log():
    # Fetch all changes with bar names and user names
    changes_with_bar_names = db.session.query(
        ChangeLog, Bar.name.label('bar_name')
    ).join(Bar, ChangeLog.bar_id == Bar.id).all()

    # Group changes by user (existing logic)
    changes_grouped_by_user = {}
    for change, bar_name in changes_with_bar_names:
        user_changes = changes_grouped_by_user.setdefault(change.user, [])
        user_changes.append((change, bar_name))

    # New logic to group changes by bar
    changes_grouped_by_bar = {}
    for change, bar_name in changes_with_bar_names:
        bar_changes = changes_grouped_by_bar.setdefault(bar_name, [])
        bar_changes.append(change)

    # Pass both dictionaries to the template
    return render_template('change_log.html', 
                           changes_grouped_by_user=changes_grouped_by_user, 
                           changes_grouped_by_bar=changes_grouped_by_bar)


@app.route('/add_bar_to_location/<int:location_id>', methods=['POST'])
def add_bar_to_location(location_id):
    bar_name = request.form.get('bar_name')
    if bar_name:
        new_bar = Bar(name=bar_name, location_id=location_id)
        db.session.add(new_bar)
        db.session.commit()
        return jsonify({'success': 'Bar added successfully', 'bar_name': new_bar.name, 'bar_id': new_bar.id})
    return jsonify({'error': 'Missing data'}), 400


@app.route('/bar/<int:bar_id>', methods=['GET', 'POST'])
def bar(bar_id):
    from_admin = request.args.get('from_admin', 'false').lower() == 'true'
    session['bar_id'] = bar_id  # Store bar_id in session
    bar = Bar.query.get_or_404(bar_id)
    user = User.query.get_or_404(bar.location.users[0].id)  # Fetch the first user of the bar's location
    if request.method == 'POST':
        return redirect(url_for('bar', bar_id=bar_id))
    link = bar.link if bar.link else Bar.query.first().link  # Fallback to the first bar's link if none set.
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
    
@app.route('/bar/<int:bar_id>/check_in', methods=['POST'])
@login_required
def check_in_bar(bar_id):
    bar = Bar.query.get_or_404(bar_id)
    bar.last_checked_in = datetime.utcnow()  # Assuming you have a 'last_checked_in' column in your Bar model
    db.session.commit()
    flash('Successfully checked in.', 'success')
    return redirect(url_for('bar', bar_id=bar_id))


@app.route('/bar/<int:bar_id>/update_details', methods=['POST'])
def update_bar_details(bar_id):
    bar = Bar.query.get_or_404(bar_id)

    # Fetch current values to compare and log changes later
    old_zakken_gekregen = bar.zakken_gekregen
    old_volle_zakken_opgehaald = bar.volle_zakken_opgehaald
    old_kg_van_zak = bar.kg_van_zak

    # Update values from form
    zakken_gekregen = request.form.get('zakken_gekregen')
    if zakken_gekregen.isdigit():
        bar.zakken_gekregen += int(zakken_gekregen)

    volle_zakken_opgehaald = request.form.get('volle_zakken_opgehaald')
    if volle_zakken_opgehaald.isdigit():
        bar.volle_zakken_opgehaald += int(volle_zakken_opgehaald)

    kg_van_zak_input = request.form.get('kg_van_zak')
    if kg_van_zak_input and kg_van_zak_input.isdigit():
        bar.kg_van_zak += int(kg_van_zak_input)

    db.session.commit()

    # Log changes
    if old_zakken_gekregen != bar.zakken_gekregen:
        log_change(current_user.id, bar_id, 'zakken_gekregen', old_zakken_gekregen, bar.zakken_gekregen)
    if old_volle_zakken_opgehaald != bar.volle_zakken_opgehaald:
        log_change(current_user.id, bar_id, 'volle_zakken_opgehaald', old_volle_zakken_opgehaald, bar.volle_zakken_opgehaald)
    if old_kg_van_zak != bar.kg_van_zak:
        log_change(current_user.id, bar_id, 'kg_van_zak', old_kg_van_zak, bar.kg_van_zak)

    flash('Verstuurd', 'success')
    return redirect(url_for('bar', bar_id=bar_id))

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
        # Assuming you have a notes or similar attribute in your Bar model to store the note
        # You might need to adjust this part according to your data model
        bar.note = note  # Add or update the note for the bar
        db.session.commit()
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

@app.route('/remove_bar_from_location/<int:bar_id>', methods=['POST'])
def remove_bar(bar_id):
    bar_to_remove = Bar.query.get_or_404(bar_id)  # Get the bar or return 404 if not found
    db.session.delete(bar_to_remove)  # Remove the bar from the database
    db.session.commit()  # Commit the changes to the database
    return jsonify({'success': 'Bar removed successfully'}), 200

@app.route('/submit_link', methods=['POST'])
def submit_link():
    link = request.form['link']
    bar_id = request.form['bar_id']  # Assuming you have a hidden input field named 'bar_id' in your form
    bar = Bar.query.get(bar_id)
    if bar:
        bar.link = link
        db.session.commit() 
    return redirect(url_for('bar', bar_id=bar_id))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if current_user.is_authenticated:
        username = current_user.username
        location_name = current_user.location.name if current_user.location else 'No location assigned'
        return render_template('dashboard.html', username=username, location_name=location_name, user=current_user)
    else:
        return redirect(url_for('login'))


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

# with app.app_context():
#     db.drop_all()
#     db.create_all()

if __name__ == '__main__':
    app.run(debug=True)  