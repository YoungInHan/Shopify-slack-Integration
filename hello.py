from flask import Flask, request, redirect, url_for, render_template, flash, session
from os import environ
import requests
from flask_sqlalchemy import SQLAlchemy
from rq import Queue
from rq.job import Job
from worker import conn
import json
import hmac
import hashlib
import base64

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/test.db"
app.secret_key = "SECRET_MISSION_SOFTWARE_IS_THE_BEST"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

q = Queue(connection=conn)

SHOPIFY_API_KEY = environ.get('SHOPIFY_API_KEY')
SHOPIFY_API_SECRET_KEY = environ.get('SHOPIFY_API_SECRET_KEY')
SCOPES = "write_orders,read_customers,read_products,write_products"

APP_SITE = "https://3d47e46c.ngrok.io"
ALL_WEBHOOKS = ["products/create", "products/update", "carts/create", "carts/update"]


class Shop(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    webhooks = db.relationship("Webhook", backref="shop", lazy="dynamic")

    def __repr__(self):
        return "<Shop %r>" % self.name


class Webhook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    webhook_id = db.Column(db.Integer, nullable=False)
    topic = db.Column(db.String(80), nullable=False)
    shop_id = db.Column(db.Integer, db.ForeignKey("shop.id"), nullable=False)


@app.route("/", methods=["GET"])
def start():
    return "hello world"


@app.route("/webhook/<category>/<action>", methods=["GET", "POST"])
def webhook(category, action):
    data = request.get_data()
    cur_hmac = request.headers.get("X-Shopify-Hmac-SHA256")

    signature = hmac.new(
        SHOPIFY_API_SECRET_KEY.encode("utf-8"), data, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(base64.b64encode(signature), cur_hmac.encode("utf-8")):
        return "Sorry webhook"

    webhook_topic = "{}/{}".format(category, action)
    if request.method == "GET":
        return "???"
    else:
        job = q.enqueue_call(
            func=webhook_task, args=(webhook_topic, ), result_ttl=5000
        )
        print("Job added with id: {}".format(job.get_id()))
        return "Webhook called"


def add_webhook(shop, webhook_topic):
    webhooks = shop.webhooks.filter_by(topic=webhook_topic)
    if webhooks.count() == 0:
        webhook_url = "https://{}/admin/api/2019-04/webhooks.json".format(shop.name)
        headers = {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": shop.token,
        }
        data = {
            "webhook": {
                "topic": webhook_topic,
                "address": "{}/webhook/{}".format(APP_SITE, webhook_topic),
                "format": "json",
            }
        }
        r = requests.post(webhook_url, headers=headers, data=json.dumps(data))
        content = json.loads(r._content.decode("utf-8"))["webhook"]
        webhook = Webhook(
            webhook_id=content["id"], topic=content["topic"], shop_id=shop.id
        )
        db.session.add(webhook)
        db.session.commit()


def remove_webhook(shop, webhook_topic):
    webhooks = shop.webhooks.filter_by(topic=webhook_topic)
    if webhooks.count() == 1:
        webhook = webhooks[0]
        webhook_url = "https://{}/admin/api/2019-04/webhooks/{}.json".format(
            shop.name, webhook.webhook_id
        )
        headers = {"X-Shopify-Access-Token": shop.token}
        r = requests.delete(webhook_url, headers=headers)

        if r.status_code == 200:
            db.session.delete(webhook)
            db.session.commit()
        else:
            print(
                "ERROR: could not remove webhook with webhook_id:{} and topic:{}".format(
                    webhook.webhook_id, webhook.topic
                )
            )


def manage_webhooks(shop, enabled_webhooks):
    disabled_webhooks = []
    for webhook in ALL_WEBHOOKS:
        if webhook not in enabled_webhooks:
            disabled_webhooks.append(webhook)

    for webhook in enabled_webhooks:
        add_webhook(shop, webhook)
    for webhook in disabled_webhooks:
        remove_webhook(shop, webhook)

def delete_shop(shop):
    for webhook_topic in ALL_WEBHOOKS:
        remove_webhook(shop, webhook_topic)
    
    db.session.delete(shop)
    db.session.commit()

@app.route("/settings", methods=["GET", "POST", "DELETE"])
def settings():
    if "name" not in session:
        return "Sorry settings"

    name = session["name"]
    shop = Shop.query.filter_by(name=name).first()
    if request.method == "GET":
        webhook_checkboxes = []
        enabled_webhooks = list(map(lambda x: x.topic, shop.webhooks))
        for webhook in ALL_WEBHOOKS:
            if webhook in enabled_webhooks:
                webhook_checkboxes.append((webhook, True))
            else:
                webhook_checkboxes.append((webhook, False))
        return render_template("settings.html", webhook_checkboxes=webhook_checkboxes)
    elif request.method == "POST":
        enabled_webhooks = list(request.form)

        manage_webhooks(shop, enabled_webhooks)

        flash("Your changes have been saved.")
        return redirect(url_for("settings"))
    elif request.method == "DELETE":
        delete_shop(shop)
        return "Shop deleted"


def check_hmac(cur_hmac, querystring):
    hmac_start = querystring.find("hmac")
    hmac_end = querystring.find("&", hmac_start)
    message = querystring[0:hmac_start] + querystring[hmac_end + 1 :]

    signature = hmac.new(
        SHOPIFY_API_SECRET_KEY.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    return cur_hmac == signature


@app.route("/install", methods=["GET"])
def install():
    cur_hmac = request.args.get("hmac")
    name = str(request.args.get("shop"))
    querystring = request.environ["QUERY_STRING"]

    if not check_hmac(cur_hmac, querystring):
        return "Sorry install"

    shop = Shop.query.filter_by(name=name).first()
    if shop:
        # redirect to settings
        session["name"] = name
        return redirect(url_for("settings"))
    else:
        api_key = SHOPIFY_API_KEY
        redirect_uri = "{}/generateToken".format(APP_SITE)
        # TODO: better nonce
        state = "bhaskar" + name
        scopes = SCOPES
        url = "https://{}/admin/oauth/authorize?client_id={}&scope={}&redirect_uri={}&state={}".format(
            name, api_key, scopes, redirect_uri, state
        )
        return redirect(url)


@app.route("/generateToken", methods=["GET"])
def generateToken():
    nonce = request.args.get("state")
    code = request.args.get("code")
    name = str(request.args.get("shop"))

    if nonce != "bhaskar" + name:
        return "badskar"

    cur_hmac = request.args.get("hmac")
    querystring = request.environ["QUERY_STRING"]
    if not check_hmac(cur_hmac, querystring):
        return "Sorry generateToken"

    # TODO: check hostname

    client_id = SHOPIFY_API_KEY
    client_secret = SHOPIFY_API_SECRET_KEY
    url = "https://{}/admin/oauth/access_token".format(name)
    r = requests.post(
        url, data={"client_id": client_id, "client_secret": client_secret, "code": code}
    )
    content = json.loads(r._content.decode("utf-8"))
    token = content["access_token"]
    shop = Shop(name=name, token=token)
    db.session.add(shop)
    db.session.commit()
    return "Shopify app successfully connected"

def webhook_task(topic):
    print("Webhook recieved for " + topic)
    job = q.enqueue_call(
        func=slack_integration, args=(topic, ), result_ttl=5000
    )
    print("Job added with id: {}".format(job.get_id()))


def slack_integration(topic):
    url = environ.get('SLACK_URL')
    text = "Your shopify shop updated {}".format(topic)
    headers = {"Content-Type": "application/json"}
    data = {"text": text}
    r = requests.post(
        url, headers=headers, data=json.dumps(data)
    )
    print(r)