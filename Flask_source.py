from flask import Flask, render_template, request, redirect,url_for
from werkzeug import secure_filename
import detect_packing
import yara_detect
import hashlib
import os
app = Flask(__name__)
result_dic = {}
gand_dic={}
lol_dic={}
wannacry_dic={}
static_folder = "C:\\Users\\Gang\\PycharmProjects\\gradulation_web_page\\thello\\static\\input_file\\"
###################################################################################################################
                                    #Flask 소스
###################################################################################################################

@app.route('/')
def hello_world():
    return render_template("default_page.html")

@app.route('/tes_page')
def test_page():
    print(result_dic)
    return render_template("test.html",result=result_dic)

@app.route('/hi')
def test_route():
    return "hi"

@app.route('/file_input',methods=['POST','GET'])
def file_input():
    filedata = request.files['file']
    filedata.save(static_folder+secure_filename(filedata.filename))
    result_packing=detect_packing_func(filedata.filename)
    if(result_packing==1):
        result_dic['name'] = filedata.filename
        result_dic['hash'] = extract_sha_256()
        result_dic['size'] = extract_file_size()    # byte단위
        rate_list=detect_yara_func(filedata.filename)
        result_dic['gand'] = rate_list[0]
        result_dic['wanna'] = rate_list[1]
        result_dic['lol'] = rate_list[2]
        return redirect(url_for("test_page"))
    elif(result_packing==-1):
        return "PE 아니야, 안돼 돌아가 !"
    elif(result_packing==-2):
        return "패킹이야 돌아가 ! "

###################################################################################################################
                                    #이외의 func
###################################################################################################################

# EXE 유무 및 패킹 탐지
def detect_packing_func(filename):
    packing = detect_packing.filtering()
    packing_result=packing.filter(filename)
    return packing_result

# 야라룰 탐지 결과 확인 및 저장
def detect_yara_func(filename):
    tmp_list=[]
    yara_obj = yara_detect.match_yara()
    yara_obj.yara_match(filename)
    tmp_list.append(len(yara_obj.gand_yara_list))
    tmp_list.append(len(yara_obj.wanna_yara_list))
    tmp_list.append(len(yara_obj.lollipop_yara_list))

    if(max(tmp_list)==len(yara_obj.gand_yara_list)):
        result_dic['yara_count']= len(yara_obj.gand_yara_list)
        for count,dic in enumerate(yara_obj.gand_yara_list):
            result_dic[count]="["+str(dic['rule'])+"]"+str(dic['match_name'])
            result_dic[count+10]=dic['content']

    elif(max(tmp_list)==len(yara_obj.wanna_yara_list)):
        result_dic['yara_count'] = len(yara_obj.wanna_yara_list)
        for count, dic in enumerate(yara_obj.wanna_yara_list):
            result_dic[count] = "[" + str(dic['rule']) + "]" + str(dic['match_name'])
            result_dic[count + 10] = dic['content']

    elif(max(tmp_list)==len(yara_obj.lollipop_yara_list)):
        result_dic['yara_count'] = len(yara_obj.lollipop_yara_location)
        for count, dic in enumerate(yara_obj.lollipop_yara_location):
            result_dic[count] = "[" + str(dic['rule']) + "]" + str(dic['match_name'])
            result_dic[count + 10] = dic['content']

    gand_rate = (len(yara_obj.gand_yara_list)/sum(tmp_list)*100)
    wannacry_rate = (len(yara_obj.wanna_yara_list) / sum(tmp_list) * 100)
    lollipop_rate = (len(yara_obj.lollipop_yara_list) / sum(tmp_list) * 100)

    return_list = [gand_rate,wannacry_rate,lollipop_rate]
    return return_list



def extract_sha_256():
    string=open(static_folder+result_dic['name'],'rb')
    sha=hashlib.new('sha256')
    sha.update(string.read())
    string.close()
    return sha.hexdigest()

def extract_file_size():
    return os.path.getsize(static_folder+result_dic['name'])


if __name__ == '__main__':
    app.run(debug=True)
