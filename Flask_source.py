from flask import Flask, render_template, request
from werkzeug import secure_filename
app = Flask(__name__)
app._static_folder = "C:\\Users\\Gang\\PycharmProjects\\gradulation_web_page\\thello\\static\\"

@app.route('/')
def hello_world():
    return render_template("default_page.html")

@app.route('/ksm',methods=['POST'])
def ksm():
    jsonData = request.files['file']
    print(jsonData)
    jsonData.save(secure_filename(jsonData.filename))
    return "<h1> sipal </h1>"



@app.route('/test')
def hi():
    return "test"

if __name__ == '__main__':
    app.run()
    #dataType:'list',
    #formData.append('files', fileList[uploadFileList[i]]);