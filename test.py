from flask import Flask, request, render_template_string, send_file, make_response, render_template
import sqlite3
import os
import hashlib
import secrets
import xml.etree.ElementTree as ET
import lxml.etree
import pickle
import requests
import re

# Is an web service in Flask, can be vulnerable to various types of attacks such as RCE? if can, please give me a code example.
# regex DoS, RCE, path traversal, XSS, SQLi, unsafe hash, unsafe random, XXE, Xpathi, cookies without HttpOnly flag, cookies with Secure flag, serialization, SSRF, SSTI

app = Flask(__name__)

users = {}

@app.route('/sqli')
def sqli():
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    username = request.args.get('username')
    password = request.args.get('password')
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "';"
    c.execute(query)
    data = c.fetchall()
    if data:
        return 'Welcome, ' + data[0][0] + '!'
    else:
        return 'Invalid username or password.'

@app.route('/xss')
def xss():
    name = request.args.get('name')
    template = "<h1>Hello, {{ name }}!</h1>"
    return render_template_string(template, name=name)

@app.route('/path')
def download():
    filename = request.args.get('filename')
    return send_file(os.path.join('/home/user/files/', filename))

@app.route('/rce')
def rce():
    username = request.args.get('username')
    password = request.args.get('password')
    if username and password:
        command = "echo 'Welcome, {}!'".format(username)
        output = os.popen(command).read()
        return output
    else:
        return "Please provide a username and password."
    
@app.route('/hash')
def hash():
    username = request.args.get('username')
    password = request.args.get('password')
    if username and password:
        users[username] = hashlib.md5(password.encode()).hexdigest()
        return "User registered successfully."
    else:
        return "Please provide a username and password."


@app.route('/random')
def safe_random():
    return str(secrets.randbelow(10) + 1)



@app.route('/xxe', methods=['POST'])
def xxe_vulnerable():
    xml = request.data
    root = ET.fromstring(xml)
    return 'Success!'


@app.route('/xpathi', methods=['POST'])
def xpath_safe():
    xml = request.data
    xpath = request.args.get('xpath')
    
    # Validate the input parameter
    if not xpath or not isinstance(xpath, str):
        return 'Invalid input', 400
    
    # Sanitize the input parameter by removing any potential malicious code
    xpath = xpath.replace('/', '')
    
    root = lxml.etree.fromstring(xml)
    results = root.xpath(xpath)
    return str(results)


@app.route('/httponly')
def httponly():
    resp = make_response(render_template('index.html'))
    resp.set_cookie('username', 'admin', httponly=False)
    return resp

@app.route('/getcookie')
def getcookie():
    username = request.cookies.get('username')
    return 'Hello ' + str(username)


@app.route('/secure')
def secure():
    resp = make_response(render_template('index.html'))
    resp.set_cookie('username', 'admin', secure=False)
    return resp


@app.route('/serialize', methods=['POST'])
def serialize_input():
    input_data = request.form['input_data']
    serialized_data = pickle.dumps(input_data)
    return serialized_data



@app.route('/ssti', methods=['POST'])
def render_template():
    template = request.form.get('template')
    return render_template_string(template)




@app.route('/ssrf')
def ssrf():
    url = request.args.get('url')
    response = requests.get(url)
    return response.content


@app.route('/redos', methods=['POST'])
def regex_dos():
    pattern = request.form.get('pattern')
    text = request.form.get('text')
    try:
        re.compile(pattern, re.DOTALL)
        match = re.search(pattern, text)
        if match:
            return match.group(0)
        else:
            return 'No match'
    except re.error:
        return 'Invalid regex'




if __name__ == '__main__':
    app.run(debug=True)
