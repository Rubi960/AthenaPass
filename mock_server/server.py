from flask import Flask, jsonify 
from flask_cors import CORS 

app = Flask(__name__) 
CORS(app) 

PASSWORDS = [
    {"name": "GitHub", "password": "gh_T7xK2#mNpQ9r"},
    {"name": "Gmail", "password": "Gm4!lSecure2024"},
    {"name": "Netflix", "password": "nflx_p@ssW0rd99"},
    {"name": "AWS Console", "password": "Aws#Root_7yBn3$"},
    {"name": "Figma", "password": "fig_Design!42xZ"}
]

@app.route("/passwords", methods=["GET"])
def get_passwords():
    return jsonify(PASSWORDS)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
