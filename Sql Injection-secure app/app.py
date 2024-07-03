# secure/app.py
from flask import Flask, request, render_template
import mysql.connector

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='test_db'
        )
        cursor = connection.cursor()
        query = "SELECT * FROM users WHERE username=%s AND password=%s"
        cursor.execute(query, (username, password))
        
        if cursor.fetchone():
            return "Login successful"
        else:
            return "Login failed"
    
    return render_template('login.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
