from flask import Flask,render_template,request
import pickle
from feature_extraction import *

model = pickle.load(open('rf_model.pkl','rb'))

app = Flask(__name__, template_folder='templates')

"""Home Page"""
@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

"""Predict Method"""
@app.route("/predict", methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url']
        http_url = 'http://' + url
        # print(http_url)
        urlObj = feature_extraction(url)
        dict_url = urlObj.start_url()
        url_base_feature = urlObj.url_based_feature_extract(dict_url)
        domain_base_feature = urlObj.domain_based_feature_extract(dict_url)
        page_base_feature = urlObj.page_based_feature_extract(dict_url)
        content_base_feature = urlObj.content_based_features(dict_url)

        final_data = urlObj.get_all_features(url_base_feature, domain_base_feature, page_base_feature, content_base_feature)
        # print(final_data)

        prediction = model.predict([final_data])

        return render_template('index.html',URL = http_url, output = prediction[0])


if __name__ == '__main__':
    app.run(debug=True)




