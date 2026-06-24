from flask import Flask, render_template, request

app = Flask(__name__)

def check_url(url):
    suspicious_keywords = ['login', 'verify', 'bank', 'secure', 'account']

    if '@' in url:
        return "SUSPICIOUS"

    if len(url) > 75:
        return "SUSPICIOUS"

    if url.startswith("http://"):
        return "SUSPICIOUS"

    for word in suspicious_keywords:
        if word in url.lower():
            return "SUSPICIOUS"

    return "SAFE"

@app.route('/', methods=['GET', 'POST'])
def home():
    result = ""

    if request.method == 'POST':
        url = request.form['url']
        result = check_url(url)

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)