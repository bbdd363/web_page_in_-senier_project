import yara
import os

class match_yara:
    def __init__(self):
        self.yara_location = "C:\\Users\\Gang\\PycharmProjects\\gradulation_web_page\\thello\static\\gand_yara.yar"
        self.path = "C:\\Users\\Gang\\Desktop\\Ä¸½ºÅæ\\2ÇÐ±â\\mal\\°µµåÅ©·¦\\"
        self.result_dic = {}

    def yara_match(self):
        files = os.listdir(self.path)
        rules = yara.compile(filepath=self.yara_location)
        for file in files:
            with open(self.path+file, 'rb') as f:
                rules.match(data=f.read(), callback=self.mycallback)

    def mycallback(self,match_data):
        if(match_data['matches']==True):
            self.result_dic['rule']= match_data['rule']
            self.result_dic['match_name'] = match_data['strings'][0][1]
            self.result_dic['content'] = match_data['strings'][0][2]
            test_list.append(self.result_dic)
            self.result_dic={}
        yara.CALLBACK_CONTINUE


if __name__=="__main__":
    test_list = []
    test_obj=match_yara()
    test_obj.yara_match()
    print(len(test_list))
    for dic in test_list:
        print(dic['match_name'])

