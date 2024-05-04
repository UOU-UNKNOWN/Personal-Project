"""

VirusTotal API Python과 CustomTkinter을 활용한 GUI 프로그램

pip install vt-py
pip install customtkiner

해주셔야 사용하실 수 있습니다.

Virustotal API를 활용하는 것이기 때문에 virustotal api키가 있어야합니다.

"""
import vt
import customtkinter as ctk 
from tkinter import messagebox

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.initWidget()

    def initUI(self):
        self.geometry("700x400")
        self.title("URL SCANNING")
        self.resizable(False,False)


    def initWidget(self):
        self.api_input_area = ctk.CTkEntry(self,placeholder_text="Input your Virustotal API key!",width=500)
        self.api_input_area.pack(side="top",pady = 20)

        self.target_url_area = ctk.CTkEntry(self,placeholder_text="Input your Target URL",width=500)
        self.target_url_area.pack(side="top")
        
        self.submitBtn = ctk.CTkButton(self,text="Request Analysis",command=self.urlScan)
        self.submitBtn.pack(side="top",pady = 20)

        self.analysis_result_area = ctk.CTkTextbox(self,state="disable",width=500)
        self.analysis_result_area.pack(side="bottom",pady = 50)

        self.result_txt = ctk.CTkLabel(self,text="Analysis Result")
        self.result_txt.place(x=300,y=185)

    def urlScan(self):
        self.target_url = self.target_url_area.get()
        self.user_api = self.api_input_area.get()

        try:
            self.client = vt.Client(self.user_api)
            self.target_url_id = vt.url_id(self.target_url)
            self.response = self.client.get_object("/urls/{}".format(self.target_url_id))
            
            self.scanInfo = self.response.last_analysis_results

            self.analysis_result_area.configure(state="normal")
            self.analysis_result_area.delete('1.0',ctk.END)
            self.analysis_result_area.insert(ctk.END,"%s -> %s\n"%("Engine Name","Result"))
            self.analysis_result_area.insert(ctk.END,"="*50+"\n")
            for engine_name in self.scanInfo.keys():
                self.analysis_result_area.insert(ctk.END,"%s -> %s\n"%(engine_name,self.scanInfo[engine_name]["result"]))
            self.analysis_result_area.insert(ctk.END,self.response.last_analysis_stats)
            self.analysis_result_area.configure(state="disable")

        except:
            messagebox.showwarning("Warning","Invaild API Key or URL")

        finally:
            self.client.close()

        
if __name__ == "__main__":
    app = App()
    app.mainloop()
