from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/')
def home():
    return "Fake AWS Metadata. Try /latest/meta-data/"

@app.route('/latest/meta-data/')
def metadata():
    return jsonify(["ami-id", "instance-type", "iam/"])

@app.route('/latest/meta-data/iam/security-credentials/')
def iam_roles():
    return jsonify(["AdminRole"])

@app.route('/latest/meta-data/iam/security-credentials/AdminRole')
def admin_role():
    return jsonify({
        "Code": "Success",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "AWS_TOKEN_EXTRACTED",
        "Expiration": "2024-12-31T23:59:59Z"
    })

if __name__ == '__main__':
    print("Fake AWS Metadata: http://localhost:8080")
    app.run(host='0.0.0.0', port=8080)