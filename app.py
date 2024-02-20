import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
from flask_pymongo import PyMongo
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request
from bson.json_util import loads, dumps
import requests

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
    
app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")
app.config["MONGO_URI"] = env.get("MONGO_URI")
mongo = PyMongo(app)
oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

API_BASE_URL = env.get("API_BASE_URL")
headers = {"Authorization": "Bearer " + env.get("API_TOKEN")}

def run(model, prompt):
    input = {
        "messages": [
        { "role": "system", "content": "You are a friendly assistant" },
        { "role": "user", "content": prompt }
        ]
    }
    response = requests.post(f"{API_BASE_URL}{model}", headers=headers, json=input)
    return response.json()

@app.route('/suggestQuestion', methods=['POST'])
def suggest_question():
    req = request.json
    prompt = req['prompt']
    output = run("@cf/meta/llama-2-7b-chat-int8", prompt)
    print(output)
    return json.dumps(output['result']['response'])
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route('/saveDocument', methods=['POST'])
def save_document():
    req = request.json
    user = req['user']
    print("edit:",user)
    doc_name = req['docName']
    content = req['content']
    print(content)
    query = {"user": user, "name": doc_name}
    # New values to set
    new_values = {"$set": {"content": content}}
    
    # Perform the update
    result = mongo.db.documents.update_one(query, new_values)

    return {'status': 'success'}

@app.route('/documents/<user>/<doc_name>')
def edit_document(user, doc_name):
    document = mongo.db.documents.find_one({"user": session.get('user')['userinfo']['nickname'], 'name': doc_name})
    if document:
        content = document.get('content', 'Failed to fetch')
        print(content)
        return render_template('edit.html', doc_name=doc_name, user=user, content=content)
    return render_template('edit.html', doc_name=doc_name, user=user, content='Start typing...')

@app.route('/createDoc', methods=['POST'])
def createDoc():
    doc_name = request.form.get('docName')
    user_documents = mongo.db.documents.insert_one({"user": session.get('user')['userinfo']['nickname'], "name": doc_name, 'content': ''})
    return redirect(url_for('edit_document', user=session.get('user')['userinfo']['nickname'], doc_name=doc_name))

@app.route("/")
def home():
    if session.get('user'):
        user_documents = mongo.db.documents.find({"user": session.get('user')['userinfo']['nickname']})
        return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4), user_docs=list(user_documents))
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4), user_docs=[])

if __name__ == "__main__":
    app.run(host='0.0.0.0')