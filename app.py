from flask import Flask,render_template,request
import pickle
from feature_extraction import *

model = pickle.load(open('Phishing-Domain-Detection/rf_model.pkl','rb'))

app = Flask(__name__, template_folder='templates')

@app.route('/')
def home():
    return render_template('index.html')

@app.route("/predict", methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url']
        print(url)
        urlObj = feature_extraction(url)
        dict_url = urlObj.start_url()
        url_base_feature = urlObj.url_based_feature_extract(dict_url)
        domain_base_feature = urlObj.domain_based_feature_extract(dict_url)
        page_base_feature = urlObj.page_based_feature_extract(dict_url)
        content_base_feature = urlObj.content_based_features(dict_url)

        final_data = urlObj.get_all_features(url_base_feature, domain_base_feature, page_base_feature, content_base_feature)
        # print(final_data)

        prediction = model.predict([final_data])

        # if prediction[0] == 0:
        #     legitimate = 'legitimate Website'
        # else:
        #     phishing = 'Phishing Website'

        return render_template('index.html',URL = url, output = prediction[0])


if __name__ == '__main__':
    app.run(debug=True)




