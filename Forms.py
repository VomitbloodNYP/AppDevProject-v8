from wtforms import Form, validators, IntegerField, StringField, DateField, TextAreaField
import re
from wtforms.validators import DataRequired, Regexp

# YX forms
class EditPackForm(Form):
    pack_name = StringField('First Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    pack_count = IntegerField('', [validators.NumberRange(min=1, max=150), validators.DataRequired()], default=0)
    pack_price = IntegerField('', [validators.NumberRange(min=1, max=150), validators.DataRequired()], default=0)

class PersonalDetailsForm(Form):
    city = StringField('City/Region', validators=[DataRequired(), Regexp(r'^[a-zA-Z]+$', message="Name can only contain letters")])
    full_name = StringField('Full Name', [validators.DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Regexp(r'^\d{8}$', message="Phone number must be 8 digits long")], render_kw={"placeholder": "9123 5677"})
    zip = StringField('Zip code', validators=[DataRequired(), Regexp(r'^\d{6}$', message="Zip code must be 6 digits long")], render_kw={"placeholder": "123456"})
    address = StringField('Address', [validators.DataRequired()], render_kw={"placeholder": "Block number, Street, Unit number"})
    card_number = StringField('Card Number', validators=[DataRequired(), Regexp(r'^\d{16}$', message="Card number must be 16 digits long")], render_kw={"placeholder": "1234 5678 9012 3456"})
    card_holder_name = StringField('Card Holder Name', [validators.DataRequired()])
    expiry_date = StringField('Expiry Date (MM/YY)', validators=[DataRequired(), Regexp(r'^(0[1-9]|1[0-2])\/[0-9]{2}$', message="Month and Year must be in MM/YY format")])
    cvv = StringField('CVV', validators=[DataRequired(), Regexp(r'^\d{3,4}$', message="CVV code must be 3 or 4 digits long")], render_kw={"placeholder": "123 or 1234"})

#Dominic
class CreateReviewForm(Form):
    rating = IntegerField('Star', [validators.DataRequired(),validators.NumberRange(min=1,max=5,message='Rating must be between 1 - 5')])
    reviews = TextAreaField('Reviews', [validators.Length(min=1, max=500), validators.DataRequired()])

class UpdateReviewForm(Form):
    rating = IntegerField('Star', [validators.DataRequired(),validators.NumberRange(min=1,max=5,message='Rating must be between 1 - 5')])
    reviews = TextAreaField('Reviews', [validators.Length(min=1, max=500), validators.DataRequired()])

