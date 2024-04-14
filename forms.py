from flask_wtf import FlaskForm
from wtforms import SubmitField

class SimpleForm(FlaskForm):
    submit = SubmitField('Submit')
