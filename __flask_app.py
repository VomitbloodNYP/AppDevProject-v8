from flask import Flask, flash, request, redirect, render_template, Response, url_for, send_file, g, session, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, LargeBinary, create_engine
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from datetime import timedelta
from flask_bcrypt import Bcrypt
from wtforms import Form, StringField, IntegerField, validators
from wtforms.fields import EmailField, SubmitField, PasswordField, BooleanField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError
from wtforms.widgets import PasswordInput
from flask_mail import Mail, Message
from random import *
from datetime import datetime
from pytz import timezone
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_recaptcha import ReCaptcha
import requests, time, shelve, Review, io, CardInBasket, PersonalDetails, random
from Forms import CreateReviewForm, UpdateReviewForm
from Forms import PersonalDetailsForm
from PersonalDetails import *
import pandas as pd

app = Flask(__name__)

# YX part starts here
# main store page - retrieve from card db
@app.route('/store', methods=['GET', 'POST'])
def add_pack():

    print("hello there console snooper")
    # shelve things
    data = Card.query.all()
    return render_template('store.html', data=data)

@app.route('/storesearch', methods = ["POST"])
def searchbar():
    filter_name = request.form.get('filter_name')
    if filter_name == '':
        filterdata = Card.query.all()
    else:
        filterdata = Card.query.filter(Card.name.contains(filter_name))
    return render_template('store.html',data=filterdata,query = filter_name)

# shopping cart page - retrieve items from basket shelve db
@app.route('/basket')
def basket():
    # shelve things
    basketdb = shelve.open('basket.db', 'c')
    basket_dict = basketdb['Basket']
    basket_list = []
    subtotal = 0
    session['subtotal'] = 0
    for key in basket_dict:
        cardInBasket = basket_dict.get(key)
        basket_list.append(cardInBasket)

        # calculate subtotal i want to kill myself
        subtotal += cardInBasket.get_price()
        session['subtotal'] = subtotal

    count = len(basket_list)
    basketdb.close()

    return render_template('basket.html', count=count, basket_list=basket_list, subtotal=subtotal)

# pack listing page show details of each pack - retrieve and update
@app.route('/packListing/<int:id>/', methods=['GET', 'POST'])
def update_pack_listing(id):
    displayThisCard = Card.query.filter_by(id=id).first()

    # shelve things
    basket_dict = {}
    basketdb = shelve.open('basket.db', 'c')

    try:
        basket_dict = basketdb['Basket']
    except:
        print("Error in retrieving Packs from pack.db.")

    # add pack to basket
    if request.method == 'POST':
        cardInBasket = CardInBasket.CardInBasket(displayThisCard.id, displayThisCard.name, displayThisCard.type, displayThisCard.price, displayThisCard.rarity, displayThisCard.booster, displayThisCard.description, False)

        basket_dict[cardInBasket.get_id()] = cardInBasket
        basketdb['Basket'] = basket_dict

        basketdb.close()

        return redirect(url_for('basket'))

    return render_template('packListing.html', displayThisCard=displayThisCard)

# delete pack from basket - retrieve and delete
@app.route('/deletePack/<int:id>', methods=['POST'])
def delete_pack(id):
    basket_dict = {}

    basketdb = shelve.open('basket.db', 'w')
    basket_dict = basketdb['Basket']

    basket_dict.pop(id)

    basketdb['Basket'] = basket_dict
    basketdb.close()

    return redirect(url_for('basket'))

# checkout page - create retrieve and update
@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    subtotal = session.get('subtotal', None)

    # create form objects
    personal_details_form = PersonalDetailsForm(request.form)

    if request.method == 'POST' and personal_details_form.validate():
        personal_details_dict = {}
        personal_detailsdb = shelve.open('personal_details.db', 'w')
        try:
            personal_details_dict = personal_detailsdb['PersonalDetails']
        except:
            print("Error in retrieving Packs from bleh.")

        # create personal details object
        personal_details = PersonalDetails(current_user.username, personal_details_form.city.data, personal_details_form.full_name.data, personal_details_form.phone_number.data, personal_details_form.zip.data, personal_details_form.address.data, personal_details_form.card_number.data, personal_details_form.card_holder_name.data, personal_details_form.expiry_date.data, personal_details_form.cvv.data)

        # put personal details object back into dictionary
        personal_details_dict[personal_details.get_account_id()] = personal_details

        # put dictionary back into shelve
        personal_detailsdb['PersonalDetails'] = personal_details_dict

        # close shelve
        personal_detailsdb.close()

        return redirect(url_for('success'))

    else:
        # shelve for personal details
        personal_details_dict = {}
        personal_detailsdb = shelve.open('personal_details.db', 'c')
        try:
            personal_details_dict = personal_detailsdb['PersonalDetails']
        except:
            print("Error in retrieving Packs from bleh.")

        personal_detailsdb.close()

        # initialize boolean to check for initial user
        isInitialUser = False

        # loop through personal details dict to check if user is initial user
        for key in personal_details_dict:
            # if user is NOT initial user, ONLY ONE value will match
            if key == current_user.username:
                isInitialUser = True
                break
            # if user is initial user, key will not exist at all
            else:
                isInitialUser = False

        # if true, user is initial user, retrieve the good stuff
        if isInitialUser == True:
            personal_details_form.city.data = personal_details_dict[current_user.username].get_city()
            personal_details_form.full_name.data = personal_details_dict[current_user.username].get_full_name()
            personal_details_form.phone_number.data = personal_details_dict[current_user.username].get_phone_number()
            personal_details_form.zip.data = personal_details_dict[current_user.username].get_zip()
            personal_details_form.address.data = personal_details_dict[current_user.username].get_address()
            personal_details_form.card_number.data = personal_details_dict[current_user.username].get_card_number()
            personal_details_form.card_holder_name.data = personal_details_dict[current_user.username].get_card_holder_name()
            personal_details_form.expiry_date.data = personal_details_dict[current_user.username].get_expiry_date()
            personal_details_form.cvv.data = personal_details_dict[current_user.username].get_cvv()

        # if false, user is not initial user, do blank fields
        else:
            print("chatgpt how to unalive myself")

        return render_template('checkout.html', personal_details_form=personal_details_form, subtotal=subtotal)

# checkout page FOR GACHA - create retrieve and update
@app.route('/checkoutGacha/<string:series>', methods=['GET', 'POST'])
def checkoutGacha(series):

    # create form objects
    personal_details_form = PersonalDetailsForm(request.form)

    if series == 'crownzenith':
        filtered = 'Crown Zenith'
    if series == 'silvertempest':
        filtered = 'Silver Tempest'
    if series == 'astralradiance':
        filtered = 'Astral Radiance'
    if series == 'brilliantstars':
        filtered = 'Brilliant Stars'
    if series == 'celebrations':
        filtered = 'Celebrations'
    if series == 'evolvingskies':
        filtered = 'Evolving Skies'
    if series == 'vividvoltage':
        filtered = 'Vivid Voltage'
    if series == 'sunandmoon':
        filtered = 'Sun & moon'

    try:
        data = Card.query.filter_by(booster=filtered).all()
        temp = []
        for card in data:
            temp.append(card)
        size = len(temp)
        gacharate = random.randint(0, size-1)
        chosenvalue = temp[gacharate]
        if request.method == 'POST' and personal_details_form.validate():
            personal_details_dict = {}
            personal_detailsdb = shelve.open('personal_details.db', 'w')
            try:
                personal_details_dict = personal_detailsdb['PersonalDetails']
            except:
                print("Error in retrieving Packs from bleh.")

            # create personal details object
            personal_details = PersonalDetails(current_user.username, personal_details_form.city.data, personal_details_form.full_name.data, personal_details_form.phone_number.data, personal_details_form.zip.data, personal_details_form.address.data, personal_details_form.card_number.data, personal_details_form.card_holder_name.data, personal_details_form.expiry_date.data, personal_details_form.cvv.data)

            # put personal details object back into dictionary
            personal_details_dict[personal_details.get_account_id()] = personal_details

            # put dictionary back into shelve
            personal_detailsdb['PersonalDetails'] = personal_details_dict

            # close shelve
            personal_detailsdb.close()

            return redirect(url_for(series))

        else:
            # shelve for personal details
            personal_details_dict = {}
            personal_detailsdb = shelve.open('personal_details.db', 'c')
            try:
                personal_details_dict = personal_detailsdb['PersonalDetails']
            except:
                print("Error in retrieving Packs from bleh.")

            personal_detailsdb.close()

            # initialize boolean to check for initial user
            isInitialUser = False

            # loop through personal details dict to check if user is initial user
            for key in personal_details_dict:
                # if user is NOT initial user, ONLY ONE value will match
                if key == current_user.username:
                    isInitialUser = True
                    break
                # if user is initial user, key will not exist at all
                else:
                    isInitialUser = False

            # if true, user is initial user, retrieve the good stuff
            if isInitialUser == True:
                personal_details_form.city.data = personal_details_dict[current_user.username].get_city()
                personal_details_form.full_name.data = personal_details_dict[current_user.username].get_full_name()
                personal_details_form.phone_number.data = personal_details_dict[current_user.username].get_phone_number()
                personal_details_form.zip.data = personal_details_dict[current_user.username].get_zip()
                personal_details_form.address.data = personal_details_dict[current_user.username].get_address()
                personal_details_form.card_number.data = personal_details_dict[current_user.username].get_card_number()
                personal_details_form.card_holder_name.data = personal_details_dict[current_user.username].get_card_holder_name()
                personal_details_form.expiry_date.data = personal_details_dict[current_user.username].get_expiry_date()
                personal_details_form.cvv.data = personal_details_dict[current_user.username].get_cvv()

            # if false, user is not initial user, do blank fields
            else:
                print("chatgpt how to unalive myself")

            return render_template('checkoutGacha.html', personal_details_form=personal_details_form, series=series)

    except:
        return render_template('gachastock.html')

# very nice
@app.route('/success')
def success():
    return render_template('success.html')

# not very nice
@app.route('/fail')
def fail():
    return render_template('fail.html')
# YX part ends here

#Start of Matthew's Part
bcrypt = Bcrypt(app)
recaptcha = ReCaptcha(app=app)

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///Database.db"

app.config['SECRET_KEY'] = 'be3816ab3ea3b8672fa608a'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
SITE_KEY = '6LdTJGgkAAAAAG6y0Q7g36W_yX1KVLxw3C8Op-zx'
SECRET_KEY = '6LdTJGgkAAAAAOuSwXjo-2lNNLbY5wFDSj9FGdR8'
VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

app.config['MAIL_SERVER'] = "smtp-mail.outlook.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = "pokeimpact@outlook.com"
app.config['MAIL_PASSWORD'] = "!P@ssW0rD123"
app.config['MAIL_USE_TLS'] = True
s = URLSafeTimedSerializer('ThisIsASecret!')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False)
    phone_num = db.Column(db.Integer, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False)
    activity = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.String(50), default=datetime.now(timezone('Asia/Singapore')).strftime("%Y-%m-%d %H:%M:%S"))


class CreateUserForm(FlaskForm):
    first_name = StringField('First Name', [validators.DataRequired()])
    last_name = StringField('Last Name', [validators.DataRequired()])
    username = StringField('Username', [validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone_num = StringField('Phone Number', [validators.Length(min=8,max=8), validators.DataRequired()])
    password = StringField('Password', [validators.Length(min=8, max=100), validators.DataRequired(),
                                        validators.EqualTo('confirm_password', message="Passwords Must Match")],
                           widget=PasswordInput(hide_value=False))
    confirm_password = StringField('Re-enter Password', [validators.Length(min=8, max=100), validators.DataRequired(),
                                                         validators.EqualTo('password',
                                                                            message="Passwords Must Match")],
                                   widget=PasswordInput(hide_value=False))
    submit = SubmitField("Submit")
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email already exists. Please choose a different one.')

    def validate_phone_num(self, phone_num):
        check = phone_num.data
        if check.isdigit() !=  True:
            raise ValidationError("Only enter integers for phone number")

    def validate_password(self, password):
        lower = 0
        upper = 0
        special = 0
        number = 0
        for char in password.data:
            if char.isupper():
                upper += 1
            elif char.islower():
                lower += 1
            elif char.isalpha() == False and char.isnumeric() == False:
                special += 1
            elif char.isnumeric():
                number += 1
        if lower != 0 and upper != 0 and special != 0 and number != 0:
            pass
        else:
            raise ValidationError("Password should contain lowercase, uppercase, number and special characters")

class ForgotPasswordForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])

class ResetPasswordForm(FlaskForm):
    password = StringField('Password', [validators.Length(min=8, max=100), validators.DataRequired(),
                                        validators.EqualTo('confirm_password', message="Passwords Must Match")],
                           widget=PasswordInput(hide_value=False))
    confirm_password = StringField('Re-enter Password', [validators.Length(min=8, max=100), validators.DataRequired(),
                                                         validators.EqualTo('password',
                                                                            message="Passwords Must Match")],
                                   widget=PasswordInput(hide_value=False))
    def validate_password(self, password):
        lower = 0
        upper = 0
        special = 0
        number = 0
        for char in password.data:
            if char.isupper():
                upper += 1
            elif char.islower():
                lower += 1
            elif char.isalpha() == False and char.isnumeric() == False:
                special += 1
            elif char.isnumeric():
                number += 1
        if lower != 0 and upper != 0 and special != 0 and number != 0:
            pass
        else:
            raise ValidationError("Password should contain lowercase, uppercase, number and special characters")



class LoginForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = StringField('Password',[validators.Length(max=100), validators.DataRequired()], widget=PasswordInput(hide_value=False))
    checkbox = BooleanField("Remember Me")

class ProfileForm(FlaskForm):
    first_name = StringField('First Name', [validators.DataRequired()])
    last_name = StringField('Last Name', [validators.DataRequired()])
    username = StringField('Username', [validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone_num = StringField('Phone Number', [validators.Length(min=8,max=8), validators.DataRequired()])
    def validate_username(self, username):
        existing_user = User.query.filter_by(
            username=username.data).first()
        if existing_user:
            if existing_user.username == current_user.username:
                pass
            else:
                raise ValidationError(
                    'That username already exists. Please choose a different one.')
    def validate_email(self, email):
        existing_email = User.query.filter_by(
            email=email.data).first()
        if existing_email:
            if existing_email.email == current_user.email:
                pass
            else:
                raise ValidationError(
                    'That email already exists. Please choose a different one.')
    def validate_phone_num(self, phone_num):
        check = phone_num.data
        if check.isdigit() != True:
            raise ValidationError("Only enter integers for phone number")
class ChangePasswordForm(FlaskForm):
    currentpassword = StringField('Enter Current Password',[validators.Length(max=100), validators.DataRequired()], widget=PasswordInput(hide_value=False))
    newpassword = StringField('Enter New Password',[validators.Length(min=8, max=100), validators.DataRequired(), validators.EqualTo('repassword', message="Passwords Must Match")] ,  widget=PasswordInput(hide_value=False))
    repassword = StringField('Re-enter New Password',[validators.Length(min=8, max=100), validators.DataRequired(), validators.EqualTo('newpassword', message="Passwords Must Match")] ,  widget=PasswordInput(hide_value=False))
    def validate_newpassword(self, newpassword):
        lower = 0
        upper = 0
        special = 0
        number = 0
        for char in newpassword.data:
            if char.isupper():
                upper += 1
            elif char.islower():
                lower += 1
            elif char.isalpha() == False and char.isnumeric() == False:
                special += 1
            elif char.isnumeric():
                number += 1
        if lower != 0 and upper != 0 and special != 0 and number != 0:
            pass
        else:
            raise ValidationError("Password should contain lowercase, uppercase, number and special characters")
class DeleteAccountForm(FlaskForm):
    password = StringField('Enter Password',[validators.Length(max=100), validators.DataRequired()], widget=PasswordInput(hide_value=False))
    checkbox = BooleanField("Yes, delete my account", [validators.DataRequired()])
@app.route('/')
def home():
    if current_user.is_authenticated == True:
        if current_user.id == 1:
            return redirect(url_for('admindashboard'))
        else:
            return redirect(url_for('dashboard'))
    else:
        return render_template('home.html')

def verify_recaptcha(token):
    secret_key = "6LdTJGgkAAAAAOuSwXjo-2lNNLbY5wFDSj9FGdR8"
    url = f"https://www.google.com/recaptcha/api/siteverify?secret={secret_key}&response={token}"
    time.sleep(3)
    try:
        response = requests.post(url)
        response.raise_for_status()
        result = response.json()
        score = result.get("score", 0)
        if result.get("success", False) and score < 0.5:
            return "reCAPTCHA score too low"
        elif result.get("success", False):
            return "success"
        else:
            return "reCAPTCHA verification failed"
    except Exception as e:
        print(f"Error while verifying reCAPTCHA: {e}")
        return "reCAPTCHA verification failed"

############################################### need to fix after done ~YX
@app.route('/LoginForm', methods=["GET", "POST"])
def login():
    create_login_form = LoginForm()
    if request.method == "POST" and create_login_form.validate():
        # token = request.form.get("g-captcha-response")
        # result = verify_recaptcha(token)
        # if result == "reCAPTCHA score too low":
        #     flash("reCAPTCHA score too low, try again")
        # elif result == "reCAPTCHA verification failed":
        #     flash("reCAPTCHA verification failed, try again")
        bruh = True
        if bruh == False:
            print("jkdsjfs")

        else:
            user = User.query.filter(func.lower(User.username) == func.lower(create_login_form.username.data)).first()
            if user:
                if bcrypt.check_password_hash(user.password, create_login_form.password.data):
                    if create_login_form.checkbox.data == True:
                        login_user(user,remember=True)
                        activity = LoginActivity(username=user.username, activity='login')
                        db.session.add(activity)
                        db.session.commit()
                        return redirect(url_for("dashboard"))
                    else:
                        login_user(user)
                        activity = LoginActivity(username=user.username, activity='login')
                        db.session.add(activity)
                        db.session.commit()
                        return redirect(url_for("dashboard"))
                else:
                    flash("Invalid Username/Password")
            else:
                flash("Invalid Username/Password")

    return render_template("Login.html", form=create_login_form)

@app.route('/dashboard',methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.id == 1:
        return redirect(url_for('admindashboard'))
    id = current_user
    username = current_user.username
    # flash(username)
    return render_template("dashboard.html")

@app.route('/admindashboard',methods=['GET', 'POST'])
@login_required
def admindashboard():
    if current_user.id != 1:
        return redirect(url_for('dashboard'))
    username = current_user.username
    # flash(username)
    return render_template("admindashboard.html")



@app.route('/profile', methods=["GET", "POST"])
@login_required
def profile():
    update_profile_form = ProfileForm(request.form)
    if request.method == "POST" and update_profile_form.validate():
        user = User.query.filter_by(username=current_user.username).first()
        user.username = update_profile_form.username.data
        user.first_name = update_profile_form.first_name.data
        user.last_name = update_profile_form.last_name.data
        user.email = update_profile_form.email.data
        user.phone_num = update_profile_form.phone_num.data
        db.session.commit()
        flash("Profile successfully updated")
        print("Profile successfully updated")
        return redirect(url_for('profile'))
    else:
        user = User.query.filter_by(username=current_user.username).first()
        update_profile_form.first_name.data = user.first_name
        update_profile_form.last_name.data = user.last_name
        update_profile_form.username.data = user.username
        update_profile_form.email.data = user.email
        update_profile_form.phone_num.data = user.phone_num


        return render_template("ChangeProfile.html", form=update_profile_form)


@app.route('/changepassword', methods=["GET", "POST"])
@login_required
def changepassword():
    change_password_form = ChangePasswordForm(request.form)
    if request.method == "POST" and change_password_form.validate():
        if bcrypt.check_password_hash(current_user.password,change_password_form.currentpassword.data):
            user = User.query.filter_by(username=current_user.username).first()
            hashed_password = bcrypt.generate_password_hash(change_password_form.newpassword.data)
            user.password = hashed_password
            db.session.commit()
            flash("Password successfully updated")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid Password!")
    return render_template("UpdatePassword.html", form=change_password_form)


@app.route('/deleteaccount', methods=["GET", "POST"])
@login_required
def deleteaccount():
    form = DeleteAccountForm(request.form)
    if request.method == "POST" and form.validate():
        user = User.query.filter_by(username=current_user.username).first()
        if bcrypt.check_password_hash(user.password, form.password.data):
            User.query.filter_by(id=current_user.id).delete()
            db.session.commit()
            logout_user()
            return redirect(url_for('home'))
        else:
            flash("Invalid password!")
    return render_template("AccountDelete.html", form=form)


@app.route('/logout')
@login_required
def logout():
    activity = LoginActivity(username=current_user.username, activity='logout')
    db.session.add(activity)
    db.session.commit()
    logout_user()
    return redirect(url_for("home"))


@app.route('/RegistrationForm', methods=['GET', 'POST'])
def create_user():
    create_user_form = CreateUserForm(request.form)
    if request.method == "POST" and create_user_form.validate():
        hashed_password = bcrypt.generate_password_hash(create_user_form.password.data)
        new_user = User(username=create_user_form.username.data, password=hashed_password,
                        first_name=create_user_form.first_name.data
                        , last_name=create_user_form.last_name.data, email=create_user_form.email.data,
                        phone_num=create_user_form.phone_num.data)

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))

    return render_template('Register.html', form=create_user_form)

mail = Mail(app)
@app.route('/forgotpassword', methods =["GET","POST"])
def forgotpassword():
    form = ForgotPasswordForm(request.form)
    if request.method == "POST" and form.validate():
        user = User.query.filter(func.lower(User.username) == func.lower(form.username.data)).first()
        if user:
            mailtoken = s.dumps(user.email)
            link = url_for('reset_password', mailtoken=mailtoken, _external=True)
            msg = Message("PokeImpact Password Reset",sender="pokeimpact@outlook.com",recipients=[user.email])
            msg.body = "Hi {}, here is the link to reset your password: {}".format(user.username,link)
            mail.send(msg)
            flash("An email has been sent to you to reset your password")
            return redirect(url_for('forgotpassword'))
        else:
            flash("Invalid Username!")
    return render_template("ForgotPassword.html",form=form)

@app.route('/ResetPassword/<mailtoken>', methods=['GET', 'POST'])
def reset_password(mailtoken):
    try:
        email = s.loads(mailtoken, max_age=300)
    except SignatureExpired:
        return redirect(url_for('expired'))
    form = ResetPasswordForm()
    user = User.query.filter_by(email=email).first()
    if request.method == 'POST' and form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash("Password resetted successfully")
        return redirect(url_for('login'))
    return render_template('ResetPassword.html', form=form)
@app.route('/expired')
def expired():
    flash("Your reset password token has expired, please resubmit another reset request")
    return redirect(url_for('forgotpassword'))
#End of Matthew's part



class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Numeric(precision=10,scale=2), nullable=False)
    rarity = db.Column(db.String(255), nullable=False)
    booster = db.Column(db.String(255), nullable=False)
    image = db.Column(LargeBinary)
    description = db.Column(db.String(255), nullable=True)

# jonath part start
@app.route('/addcard', methods=['GET', 'POST'])
@login_required
def add_card():
    if current_user.id != 1:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':

        name = request.form['name']
        type = request.form['type']
        price = request.form['price']
        rarity = request.form['rarity']
        url = request.files['img_file']
        description = request.form['description']
        if description == '':
            description = '<No description>'
        booster=request.form['booster']
        image_data = url.read()
        image_data = bytes(image_data)
        card = Card(name=name, type=type,
                        price=price,booster=booster
                        , rarity=rarity, image=image_data,
                        description=description)
        db.session.add(card)
        db.session.commit()



        return redirect(url_for('data'))
    return render_template('addcard.html')

@app.route('/image/<int:id>')
def image(id):
    card = Card.query.filter_by(id=id).first()
    image = card.image
    if image:
        return Response(image, content_type='image/jpeg')
    else:
        return 'Image Not Found', 404

@app.route('/updateCards/<int:id>')
@login_required
def update(id):
    if current_user.id != 1:
        return redirect(url_for('dashboard'))
    return redirect(url_for('update_page', id=id))

@app.route('/updateCards-page/<int:id>')
@login_required
def update_page(id):
    if current_user.id != 1:
        return redirect(url_for('dashboard'))
    card = Card.query.filter_by(id=id).first()
    return render_template('updatecards.html', data=card)

@app.route('/Cardsdata')
@login_required
def data():
    if current_user.id != 1:
        return redirect(url_for('dashboard'))
    carddata = Card.query.all()
    return render_template("retrievecard.html", data=carddata)

@app.route('/submit-update/<int:id>', methods=['POST'])
@login_required
def submit_update(id):
    if current_user.id != 1:
        return redirect(url_for('dashboard'))
    name = request.form['name']
    name=name.capitalize()
    type = request.form['type']
    price = request.form['price']
    rarity = request.form['rarity']
    description = request.form['description']
    if description == '':
        description = '<No description>'
    filecheck = request.form['check']
    booster=request.form['booster']
    card = Card.query.filter_by(id=id).first()
    if card:
        card.name = name
        card.type = type
        card.price = price
        card.rarity = rarity
        card.description = description
        card.booster=booster
        if filecheck != 'failed' and request.method == 'POST':
            url = request.files['img_file']
            image_data = url.read()
            image_data = bytes(image_data)
            card.image=image_data
        db.session.commit()
    # Redirect to the main page
    return redirect(url_for('data'))

@app.route('/filter',methods=['POST'])
@login_required
def filters():
    if current_user.id != 1:
        return redirect(url_for('dashboard'))
    rarity = request.form.get('filtergrp')
    filter_name = request.form.get('filter_name')
    if rarity == 'All' or rarity == None:
        rarity = 'All'
        filterdata = Card.query.filter(Card.name.contains(filter_name))
        return render_template("retrievecard.html", data=filterdata,rarity=rarity,query=filter_name)
    else:
        filterdata = Card.query.filter((Card.name.contains(filter_name)) & (Card.rarity.contains(rarity))).all()
    return render_template('retrievecard.html', data=filterdata,rarity=rarity,query=filter_name)

@app.route('/exportcard', methods=['POST'])
def export():
    if request.method == 'POST':
        cards = Card.query.all()
        if not cards:
            return "No Cards found"
        card = [(card.id, card.name, card.type,card.rarity,card.price,card.description,card.booster) for card in cards]
        df = pd.DataFrame(card, columns=['ID', 'Name', 'Type','Rarity','Price','Description','Series'])
        output = io.BytesIO()
        writer = pd.ExcelWriter(output, engine='xlsxwriter')
        df.to_excel(writer, index=False)
        writer.save()
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=cards.xlsx'
        response.headers['Content-type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response

@app.route('/resetfilter',methods=['POST'])
@login_required
def resetfilter():
    if current_user.id != 1:
        return redirect(url_for('dashboard'))
    rarity = 'All'
    filter_name = ''
    return render_template('retrievecard.html',data=Card.query.all(),rarity=rarity,query=filter_name)
@app.route('/deletecard/<int:id>',methods=['POST'])
@login_required
def delete(id):
    if current_user.id != 1:
        return redirect(url_for('dashboard'))
    delete = Card.query.filter_by(id=id).first()
    db.session.delete(delete)
    db.session.commit()
    return redirect(url_for('data'))

#End of Jonath's part
#Start Zheng Yi's part
@app.route('/gachadeletecard/<int:id>',methods=['POST'])
@login_required
def gachadelete(id):
    gachadelete = Card.query.filter_by(id=id).first()
    db.session.delete(gachadelete)
    db.session.commit()
    return redirect(url_for('gachastore'))

@app.route('/gachastore')
def gachastore():
    return render_template('gachastore.html')

@app.route('/crownzenith')
@login_required
def crownzenith():
    try:
        data = Card.query.filter_by(booster='Crown Zenith').all()
        temp = []
        for card in data:
            temp.append(card)
        size = len(temp)
        gacharate = random.randint(0, size-1)
        chosenvalue = temp[gacharate]
        return render_template('gachadisplay.html', chosenvalue=chosenvalue)

    except:
        return render_template('gachastock.html')

@app.route('/silvertempest')
@login_required
def silvertempest():
    try:
        data = Card.query.filter_by(booster='Silver Tempest').all()
        temp = []
        for card in data:
            temp.append(card)
        size = len(temp)
        gacharate = random.randint(0, size-1)
        chosenvalue = temp[gacharate]
        return render_template('gachadisplay.html', chosenvalue=chosenvalue)

    except:
        return render_template('gachastock.html')

@app.route('/lostorigin')
@login_required
def lostorigin():
    try:
        data = Card.query.filter_by(booster='Lost Origin').all()
        temp = []
        for card in data:
            temp.append(card)
        size = len(temp)
        gacharate = random.randint(0, size-1)
        chosenvalue = temp[gacharate]
        return render_template('gachadisplay.html', chosenvalue=chosenvalue)

    except:
        return render_template('gachastock.html')

@app.route('/astralradiance')
@login_required
def astralradiance():
    try:
        data = Card.query.filter_by(booster='Astral Radiance').all()
        temp = []
        for card in data:
            temp.append(card)
        size = len(temp)
        gacharate = random.randint(0, size-1)
        chosenvalue = temp[gacharate]
        return render_template('gachadisplay.html', chosenvalue=chosenvalue)

    except:
        return render_template('gachastock.html')

@app.route('/brilliantstars')
@login_required
def brilliantstars():
    try:
        data = Card.query.filter_by(booster='Brilliant stars').all()
        temp = []
        for card in data:
            temp.append(card)
        size = len(temp)
        gacharate = random.randint(0, size-1)
        chosenvalue = temp[gacharate]
        return render_template('gachadisplay.html', chosenvalue=chosenvalue)

    except:
        return render_template('gachastock.html')

@app.route('/celebrations')
@login_required
def celebrations():
    try:
        data = Card.query.filter_by(booster='Celebrations').all()
        temp = []
        for card in data:
            temp.append(card)
        size = len(temp)
        gacharate = random.randint(0, size-1)
        chosenvalue = temp[gacharate]
        return render_template('gachadisplay.html', chosenvalue=chosenvalue)

    except:
        return render_template('gachastock.html')

@app.route('/evolvingskies')
@login_required
def evolvingskies():
    try:
        data = Card.query.filter_by(booster='Evolving skies').all()
        temp = []
        for card in data:
            temp.append(card)
        size = len(temp)
        gacharate = random.randint(0, size-1)
        chosenvalue = temp[gacharate]
        return render_template('gachadisplay.html', chosenvalue=chosenvalue)

    except:
        return render_template('gachastock.html')

@app.route('/vividvoltage')
@login_required
def vividvoltage():
    try:
        data = Card.query.filter_by(booster='Vivid voltage').all()
        temp = []
        for card in data:
            temp.append(card)
        size = len(temp)
        gacharate = random.randint(0, size-1)
        chosenvalue = temp[gacharate]
        return render_template('gachadisplay.html', chosenvalue=chosenvalue)

    except:
        return render_template('gachastock.html')

@app.route('/sunmoon')
@login_required
def sunmoon():
    try:
        data = Card.query.filter_by(booster='Sun & moon').all()
        temp = []
        for card in data:
            temp.append(card)
        size = len(temp)
        gacharate = random.randint(0, size-1)
        chosenvalue = temp[gacharate]
        return render_template('gachadisplay.html', chosenvalue=chosenvalue)

    except:
        return render_template('gachastock.html')

#End of Zheng Yi's part

#Start of Dominic's part
#create modal
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=True)
    name = db.Column(db.String(255), nullable=False)
    reviews = db.Column(db.String(255), nullable=True)

@app.route('/createReview', methods=['GET', 'POST'])
@login_required
def create_review():
    create_review_form = CreateReviewForm(request.form)
    if request.method == 'POST' and create_review_form.validate():
        review = Review(rating=create_review_form.rating.data, name=current_user.username, reviews=create_review_form.reviews.data)
        db.session.add(review)
        db.session.commit()
        return redirect(url_for('retrieve_review'))
    return render_template('createReview.html', form=create_review_form)


@app.route('/retrieveReview')
def retrieve_review():
    reviews = Review.query.all()

    reviews_list = []
    for review in reviews:
        reviews_list.append(review)

    return render_template('retrieveReview.html', count=len(reviews_list), reviews_list=reviews_list)

@app.route('/updateReview/<int:id>/', methods=['GET', 'POST'])
@login_required
def update_review(id):
    update_review_form = UpdateReviewForm(request.form)
    if request.method == 'POST' and update_review_form.validate():
        review = Review(rating=update_review_form.rating.data, reviews=update_review_form.reviews.data)
        db.session.query(Review).filter(Review.id == id).update({Review.rating: review.rating, Review.reviews: review.reviews})
        db.session.commit()
        return redirect(url_for('retrieve_review'))
    return render_template('updateReview.html', form=update_review_form, id=id)

@app.route('/deleteReview/<int:id>/', methods=['POST'])
@login_required
def delete_review(id):
    db.session.query(Review).filter(Review.id == id).delete()
    db.session.commit()
    return redirect(url_for('myReview'))


@app.route('/myReview/', methods=['GET'])
def myReview():
    reviews = Review.query.filter_by(name=current_user.username).all()
    reviews_list = []
    for review in reviews:
        reviews_list.append(review)

    return render_template('myReview.html', count=len(reviews_list), reviews_list=reviews_list)


#End of Dominic's part



if __name__ == '__main__':
    app.run(debug=True)
