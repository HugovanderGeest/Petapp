from flask import Flask, render_template, redirect, request, url_for, flash, jsonify, send_from_directory, abort  # Added abort herefrom flask import flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
import os
import logging
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, URL
from wtforms_sqlalchemy.fields import QuerySelectField
from flask import send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['GOOGLE_MAPS_API_KEY'] = 'AIzaSyDjyGyXUa6Wnapxt-7HOity5K4Ydnb--2w'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(120), nullable=True)
    group = db.Column(db.String(120), nullable=True)
    badges = db.Column(db.Integer, default=0)

    def __init__(self, username, password, location=None, group=None, badges=0):
        self.username = username
        self.password = generate_password_hash(password)
        self.location = location
        self.group = group
        self.badges = badges
        
class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Create User')

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
    munten_gekregen = db.Column(db.Integer, default=0)
    volle_zakken_opgehaald = db.Column(db.Integer, default=0)
    url = db.Column(db.String)  # Add this line
    link = db.Column(db.String)  # Add this line

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    zakken = db.Column(db.Integer, nullable=False, default=0)
    bekers = db.Column(db.Integer, nullable=False, default=0)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)

    location = db.relationship('Location', backref=db.backref('bars', lazy=True))

    def __init__(self, name, location_id, zakken=0, bekers=0):
        self.name = name
        self.zakken = zakken
        self.bekers = bekers
        self.location_id = location_id

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    form = UserForm()
    location_form = LocationForm()
    if form.validate_on_submit():
        user = User(form.username.data, form.password.data)
        db.session.add(user)
        db.session.commit()
    if location_form.validate_on_submit():
        location = Location(location_form.name.data)
        db.session.add(location)
        db.session.commit()
    users = User.query.all()  # Fetch all users
    locations = Location.query.all()  # Fetch all locations
    # fetch all locations and pass them to the template, can be used to display a list of locations. 
    return render_template('admin.html', form=form, location_form=location_form, users=users, locations=locations)

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
        # Handle login
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Store the user's username in the session
            session['username'] = user.username
            return redirect(url_for('dashboard'))  # Redirect to dashboard after successful login
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('index'))  # Redirect to index page if login fails
    # Render login form
    return render_template('login.html')

@app.route('/user_dashboard/<int:user_id>')
def user_dashboard(user_id):
    user = User.query.get_or_404(user_id)
    # Assuming you want to display the same information as the dashboard but for a specific user
    return render_template('user_dashboard.html', user=user)

@app.route('/location/<int:location_id>', methods=['GET', 'POST'])
def location(location_id):
    location = Location.query.get_or_404(location_id)
    bars = Bar.query.filter_by(location_id=location_id).all()
    bar_form = BarForm()  # For adding new bars
    bar_link_form = BarLinkForm()  # For navigating to a specific bar

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

    return render_template('location.html', location=location, bars=bars, bar_form=bar_form, bar_link_form=bar_link_form)

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
    bar = Bar.query.get_or_404(bar_id)  # Fetch the specific bar or return 404
    if request.method == 'POST':
        # Handle any POST request logic here. You might want to process form submissions for updates.
        # Example: Updating bar description or details.
        # After processing, redirect back to the same bar page.
        return redirect(url_for('bar', bar_id=bar_id))
    # 'link' is used for a default bar URL if the specific bar has no URL set.
    link = bar.link if bar.link else Bar.query.first().link  # Fallback to the first bar's link if none set.
    return render_template('bar.html', bar=bar, link=link)

@app.route('/bar/<int:bar_id>/update', methods=['POST'])
def update_bar(bar_id):
    bar = Bar.query.get_or_404(bar_id)  # Ensure bar exists or return 404
    data = request.get_json()  # Get JSON data from the request
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400
    field = data.get('field')
    increment = data.get('increment')
    if field in ['zakken_gekregen', 'munten_gekregen', 'volle_zakken_opgehaald'] and isinstance(increment, int):
        # Update the specified field by incrementing/decrementing its value
        current_value = getattr(bar, field, 0)
        new_value = current_value + increment
        setattr(bar, field, new_value)
        db.session.commit()  # Commit the update to the database
        return jsonify({field: new_value})  # Return the updated value for the field
    else:
        return jsonify({'error': 'Invalid field or increment value'}), 400

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

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    form = LocationSelectForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=session['username']).first()
        if user:
            user.location = form.location.data.name
            db.session.commit()
            flash('Your location has been updated!')
            return redirect(url_for('dashboard'))  # Redirect to dashboard after updating location
    elif request.method == 'GET' and 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user and user.location:
            form.location.data = Location.query.filter_by(name=user.location).first()
    return render_template('dashboard.html', form=form, username=session.get('username'))

with app.app_context():
    db.drop_all()
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)  