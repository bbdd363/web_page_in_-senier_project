import os
import pefile

class filtering():
    def __init__(self):
        self.input_malware = "C:\\Users\\Gang\\PycharmProjects\\gradulation_web_page\\thello\\static\\input_file\\"

    def filter(self,file_name):
        if(self.signature_confirm(file_name) == 1 and self.UPX_Packing_confirm(file_name) == 1):
            return 1
        elif(self.signature_confirm(file_name) == 0):
            return -1
        elif(self.UPX_Packing_confirm(file_name) == 0):
            return -2

    def signature_confirm(self,target_file):
        try:
            #PE인지 아닌지 확인
            pe=pefile.PE(os.path.join(self.input_malware, target_file))
            pe.close()
            return 1
        except:
            return 0

    def UPX_Packing_confirm(self,target_file):
        try:
            pe=pefile.PE(os.path.join(self.input_malware, target_file))
            for section_count in range(0,pe.FILE_HEADER.NumberOfSections):
                if("UPX" in str(pe.sections[section_count].Name)):
                    pe.close()
                    return 0
                else:
                    return 1
        except:
            print("Packing detect error")

