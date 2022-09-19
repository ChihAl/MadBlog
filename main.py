from flask import Flask, render_template, redirect, request, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditor, CKEditorField
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
import smtplib
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

user_email = os.getenv('YAHOO_EMAIL')
password = os.getenv('YAHOO_PASSWORD')
main_email = os.getenv('MAIN_EMAIL')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///madblog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONFIGURE TABLE
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship('Comment', back_populates="author")


class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = relationship('User', back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship('Comment', back_populates="parent_post")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship('User', back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))
    parent_post = relationship('BlogPost', back_populates="comments")

# db.create_all()

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign me up!')


class LoginForm(FlaskForm):
    ename = EmailField('Email/Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Let me in')

class CommentForm(FlaskForm):
    body = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route("/")
def home():
    all_posts = BlogPost.query.all()
    return render_template("index.html", posts=all_posts, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    post = BlogPost.query.get(post_id)
    form = CommentForm()
    comments = Comment.query.all()
    if form.validate_on_submit():
        new_comment = Comment(text=form.body.data,
                              author_id=current_user.id,
                              post_id=post_id,)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", req_post=post, current_user=current_user, form=form)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        message = request.form["message"]
        with smtplib.SMTP("smtp.mail.yahoo.com") as connection:
            # make secure
            connection.starttls()
            connection.login(user=user_email, password=password)
            # send message
            connection.sendmail(from_addr=user_email,
                                to_addrs=main_email,
                                msg=f"Subject: New BBlog message\n\nName: {name.encode(encoding='windows-1251')}\nEmail: {email}\nPhone: {phone}\nMessage:{message.encode(encoding='windows-1251')}")
        return render_template("contact.html", msg_sent=True, current_user=current_user)
    return render_template("contact.html", msg_sent=False, current_user=current_user)


@app.route("/new-post", methods=["GET", "POST"], endpoint="create_post")
@login_required
def create_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(title=form.title.data,
                            subtitle=form.subtitle.data,
                            date=datetime.datetime.now().strftime("%B %d, %Y"),
                            body=form.body.data,
                            author_id=current_user.id,
                            img_url=form.img_url.data,)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('make-post.html', form=form, current_user=current_user)


@app.route("/edit-post/<post_id>", methods=["GET", "POST"], endpoint="edit")
def edit(post_id):
    post = BlogPost.query.get(post_id)
    print(current_user.id)
    print(post.author.id)
    if (current_user.id != post.author.id and current_user.id != 1) or not current_user.is_authenticated:
        return abort(403)
    form = CreatePostForm(title=post.title,
                          subtitle=post.subtitle,
                          img_url=post.img_url,
                          body=post.body
                          )
    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.img_url = form.img_url.data
        post.body = form.body.data
        db.session.commit()
        return redirect(url_for('show_post', post_id=post.id))
    return render_template('make-post.html', form=form, post=post, current_user=current_user)


@app.route("/delete/<post_id>", endpoint="delete")
@login_required
def delete(post_id):
    post = BlogPost.query.get(post_id)
    if not current_user.is_authenticated or (current_user.id != post.author.id and current_user.id != 1):
        return abort(403)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/deletecom/<comment_id>", endpoint="deletecom")
@login_required
def deletecom(comment_id):
    comment = Comment.query.get(comment_id)
    if (current_user.id != comment.author.id and current_user.id != 1) or not current_user.is_authenticated:
        return abort(403)
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for('show_post', post_id=comment.parent_post.id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # check email
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            flash('This email already exist, try log in.')
            return redirect(url_for('login'))

        # check username
        username = form.username.data
        user = User.query.filter_by(username=username).first()
        if user:
            flash('This username already exist, try log in.')
            return redirect(url_for('login'))

        # hash password
        password = form.password.data
        password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        new_user = User(email=email, username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('home'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        ename = form.ename.data
        password = form.password.data

        user = User.query.filter_by(email=ename).first()
        if not user:
            user = User.query.filter_by(username=ename).first()

        if not user:
            flash("This user wasn't found.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Wrong password.')
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for('home'))


    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
