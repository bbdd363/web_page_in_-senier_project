import yara
import os

class match_yara:
    def __init__(self):
        self.gand_yara_location = "C:\\Users\\Gang\\PycharmProjects\\gradulation_web_page\\thello\\static\\yara_rule\\gand_yara.yar"
        self.wannacry_yara_location = "C:\\Users\\Gang\\PycharmProjects\\gradulation_web_page\\thello\\static\\yara_rule\\wanncry_yar.yar"
        self.lollipop_yara_location = "C:\\Users\\Gang\\PycharmProjects\\gradulation_web_page\\thello\\static\\yara_rule\\lol_yara.yar"
        self.input_path = "C:\\Users\\Gang\\PycharmProjects\\gradulation_web_page\\thello\\static\\input_file"
        self.analysis_file = ""
        self.gand_dic = {}
        self.wannacry_dic = {}
        self.lol_dic = {}
        self.gand_yara_list = []
        self.wanna_yara_list =[]
        self.lollipop_yara_list =[]

    def yara_match(self,filename):
        self.analysis_file=os.path.join(self.input_path, filename)

        gnad_rules = yara.compile(filepath=self.gand_yara_location)
        with open(self.analysis_file, 'rb') as f:
            gnad_rules.match(data=f.read(), callback=self.gand_callback)

        wann_rules = yara.compile(filepath=self.wannacry_yara_location)
        with open(self.analysis_file, 'rb') as f:
            wann_rules.match(data=f.read(), callback=self.wanna_callback)

        lollo_rules = yara.compile(filepath=self.lollipop_yara_location)
        with open(self.analysis_file, 'rb') as f:
            lollo_rules.match(data=f.read(), callback=self.lolli_callback)



    def gand_callback(self,match_data):
        if(match_data['matches']==True):
            self.gand_dic['rule']= match_data['rule']
            self.gand_dic['match_name'] = match_data['strings'][0][1]
            self.gand_dic['content'] = match_data['strings'][0][2]
            self.gand_yara_list.append(self.gand_dic)
            self.gand_dic={}
        yara.CALLBACK_CONTINUE

    def wanna_callback(self, match_data):
        if (match_data['matches'] == True):
            self.wannacry_dic['rule'] = match_data['rule']
            self.wannacry_dic['match_name'] = match_data['strings'][0][1]
            self.wannacry_dic['content'] = match_data['strings'][0][2]
            self.wanna_yara_list.append(self.wannacry_dic)
            self.wannacry_dic = {}
        yara.CALLBACK_CONTINUE

    def lolli_callback(self, match_data):
        if (match_data['matches'] == True):
            self.lol_dic['rule'] = match_data['rule']
            self.lol_dic['match_name'] = match_data['strings'][0][1]
            self.lol_dic['content'] = match_data['strings'][0][2]
            self.lollipop_yara_list.append(self.lol_dic)
            self.lol_dic = {}
        yara.CALLBACK_CONTINUE

#
# if __name__=="__main__":
#     test_list = []
#     test_obj=match_yara()
#     test_obj.yara_match()
#     print(len(test_list))
#     for dic in test_list:
#         print(dic['match_name'])

