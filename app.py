# importing required libraries

import warnings

import joblib
import numpy as np
from flask import Flask, render_template, request

warnings.filterwarnings("ignore")
import history
from feature import FeatureExtraction
from url_guard import UnsafeURL, validate_url

gbc = joblib.load("model.pkl")

app = Flask(__name__)
history.init_db()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"].strip()
        try:
            validate_url(url)
        except UnsafeURL as e:
            return render_template("index.html", xx=-1, error=str(e), url=url)

        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        # predict_proba columns: [phishing (-1), safe (1)]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
        label = "aman" if y_pro_non_phishing >= 0.5 else "phishing"
        history.add_record(url, label, float(y_pro_non_phishing))

        return render_template("index.html", xx=round(y_pro_non_phishing, 2), url=url)
    return render_template("index.html", xx=-1)


@app.route("/history")
def show_history():
    ok, broken = history.verify_chain()
    return render_template(
        "history.html", records=history.list_records(), ok=ok, broken=broken
    )


if __name__ == "__main__":
    app.run(debug=True)
