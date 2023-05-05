# Flask-WFT Option
from flask import Flask, render_template, url_for, redirect, flash, abort
from flask_gravatar import Gravatar
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import relationship
from flask_wtf import FlaskForm
from flask_ckeditor import CKEditor, CKEditorField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, URL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from datetime import datetime
from dotenv import load_dotenv
import os
import smtplib


app = Flask(__name__)
print(__name__)
app.secret_key = "secretkey"
load_dotenv()

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)


# CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(16), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="author")

    def __init__(self, email, password, name):
        self.email = email
        self.password = password
        self.name = name


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comments", back_populates="posts")


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    posts = relationship("BlogPost", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")
    body = db.Column(db.Text, nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired()])
    body = StringField("Blog Content", validators=[DataRequired()])
    post = SubmitField("Submit Post")


class CreateCommentForm(FlaskForm):
    body = StringField("Leave a comment", validators=[DataRequired()])
    comment = SubmitField("Submit Comment")


class ContactForm(FlaskForm):
    name = StringField(label="Name", validators=[DataRequired()])
    email = StringField(label="Email", validators=[DataRequired(), Email()])
    phone = StringField(label="Phone", validators=[DataRequired(), Length(min=8)])
    message = StringField(label="Message", validators=[DataRequired()])
    send = SubmitField(label="Send")


class CreateUserForm(FlaskForm):
    name = StringField(label="Name", validators=[DataRequired()])
    email = StringField(label="Email", validators=[DataRequired(), Email()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    register = SubmitField("Register")


class LoginUserForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired(), Email()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    login = SubmitField("Log in")


def send_email(my_gmail, password, name, email, phone, message):
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=my_gmail, password=password)
        message = f"Subject: {name} wants to reach out!\n\n"\
                  f"Name: {name}\n" \
                  f"Email: {email}\n" \
                  f"Phone: {phone}\n" \
                  f"Message: {message}\n"
        connection.sendmail(from_addr=my_gmail,
                            to_addrs=my_gmail,
                            msg=message.encode("utf-8"))


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return func(*args, **kwargs)
    return wrapper


@app.route('/register', methods=["GET", "POST"])
def register():
    form = CreateUserForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        hashed_and_salted_password = generate_password_hash(form.password.data,
                                                            method='pbkdf2:sha256',
                                                            salt_length=8)
        new_user = User(name=name, email=email, password=hashed_and_salted_password)
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            flash("You have already registered with this email")
            return redirect(url_for('register'))
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    admin = User.query.get(1)
    form = LoginUserForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                if user == admin:
                    current_user.is_admin = True
                return redirect(url_for("get_all_posts"))
            else:
                flash("Invalid Password")
        else:
            flash("There is no user with this email")
            return redirect(url_for("register"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/")
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CreateCommentForm()
    if form.validate_on_submit():
        new_comment = Comments(
            post_id=post_id,
            author_id=current_user.id,
            body=form.body.data
        )
        db.session.add(new_comment)
        db.session.commit()
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form,
                           gravatar=gravatar )


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_blog_post = BlogPost(
            title=form.title.data,
            author_id=current_user.id,
            subtitle=form.subtitle.data,
            img_url=form.img_url.data,
            body=form.body.data,
            date=datetime.now().strftime("%B %d, %Y")
        )
        db.session.add(new_blog_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    edit_form = CreatePostForm()
    requested_post = BlogPost.query.get(post_id)
    if edit_form.validate_on_submit():
        requested_post.title = edit_form.title.data
        requested_post.subtitle = edit_form.subtitle.data
        requested_post.img_url = edit_form.img_url.data
        requested_post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("edit-post.html", form=edit_form, post=requested_post, logged_in=current_user.is_authenticated)


@app.route("/delete-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def delete_post(post_id):
    deleted_post = BlogPost.query.get(post_id)
    delete_comments = Comments.query.filter_by(post_id=post_id).all()
    for comment in delete_comments:
        db.session.delete(comment)
    db.session.delete(deleted_post)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


@app.route('/about')
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        phone = form.phone.data
        message = form.message.data
        my_gmail = os.environ.get("MY_GMAIL")
        password = os.environ.get("PASSWORD")
        send_email(my_gmail=my_gmail, password=password, name=name, email=email,
                   phone=phone, message=message)
        form.name.data = ""
        form.email.data = ""
        form.phone.data = ""
        form.message.data = ""
        return render_template("contact.html", msg_sent=True, form=form)
    return render_template("contact.html", msg_sent=False, form=form, logged_in=current_user.is_authenticated)


if __name__ == "__main__":
        app.run(debug=True)



# HTML Form Option
# from flask import Flask, render_template, url_for, request
# import smtplib
# import requests
# app = Flask(__name__)
# print(__name__)
#
# api_url = "https://api.npoint.io/adb03464e44b7a6d858e"
# response = requests.get(api_url)
# blog_posts = response.json()
# print(blog_posts)
#
#
# def send_email(my_gmail, password, name, email, phone, message ):
#     with smtplib.SMTP("smtp.gmail.com") as connection:
#         connection.starttls()
#         connection.login(user=my_gmail, password=password)
#         message = f"Subject: {name} wants to reach out!\n\n"\
#                   f"Name: {name}\n" \
#                   f"Email: {email}\n" \
#                   f"Phone: {phone}\n" \
#                   f"Message: {message}\n"
#         connection.sendmail(from_addr=my_gmail,
#                             to_addrs=my_gmail,
#                             msg=message.encode("utf-8"))
#
#
# @app.route('/')
# def get_all_posts():
#     return render_template("index.html", blog_posts=blog_posts)
#
#
# @app.route('/about')
# def about():
#     return render_template("about.html")
#
#
# @app.route("/contact", methods=["GET", "POST"])
# def contact():
#     if request.method == "POST":
#         data = request.form
#         print(data["name"])
#         print(data["email"])
#         print(data["phone"])
#         print(data["message"])
#         my_gmail = "100daysofcodetestmail@gmail.com"
#         password = "uyldvesslcluxqyq"
#         send_email(my_gmail=my_gmail, password=password, name=data["name"], email=data["email"], phone=data["phone"], message=data["message"])
#         return render_template("contact.html", msg_sent=True)
#     return render_template("contact.html", msg_sent=False)
#
#
# @app.route("/post/<int:post_id>")
# def post(post_id):
#     post_id -= 1
#     print(post_id)
#     title = blog_posts[post_id]["title"]
#     subtitle = blog_posts[post_id]["subtitle"]
#     body = blog_posts[post_id]["body"]
#     date = blog_posts[post_id]["date"]
#     return render_template("post.html", title=title, subtitle=subtitle, body=body, date=date, id=post_id)
#
#
# if __name__ == "__main__":
#     app.run(debug=True)