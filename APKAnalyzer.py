import subprocess
import hashlib
import argparse
import zipfile
from fileinput import filename
from xml.dom import minidom
from xml.dom.minidom import parse, parseString
import axmlparserpy.axmlprinter as axmlprinter
import axmlparserpy.apk as apk
import os
import sys
import time
import re
import axmlparserpy.apk as apk
import urllib
import urllib2
import json
import requests
import webbrowser
import timeit
import argparse
import shutil

#This part needs to be modified in order to have the script running successfully 
string_exe_file="C:\\strings.exe"  #using strings.exe from Microsoft Sysinternals 



#Timer:
tic = time.clock()

# Create target directory that shall store all related analysis files, and shall be deleted later on after the analysis is done.
# No need to modify this as all files shall be dropped in the temp folder 
dirName = 'C:\\Windows\\Temp\AppAnalysis'
os.makedirs(dirName)   
unz = dirName + '\\unzipped\\'
os.makedirs(unz)
txt_file_path= dirName + '\\txt_files\\'
os.makedirs(txt_file_path)
#----------------------


#initialzaion 
apps_path = sys.argv[1]  #receiving the path of APKs from the user

path = apps_path + '\\'

#initialzaion 
url_list=[]






#Reporting format
f = open('report.html','w')
f.write("""<html>""")
f.write("""<head> <h1> Mobile App Technical Analysis: Report </h1>
            < br>
            <p> Starting the process  in seconds: """+str(tic)+"""

        <style>
            table, th, td {
                border: 1px solid black;
                          }
        </style></head>>""")
f.write("""<body>""")





def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def print_hash_local():
	
    output_txt_file = dirName + 'output.txt'

    f.write("""<table><tr><h1 style="color:red;">Hashing the applications locally and comparing hashes to the ones on the device :</h1></tr>
             <tr>
             <th>App Names</th>
             <th>Hash Value</th>
             <th><p style="color:red;"> Match or Not Match</p></th>
             </tr>""")


    for filename in os.listdir(path):
        if "apk" in filename:
            file_path=path+filename
            f.write("<tr>")
            hash_value=(md5(file_path))
            f.write("""<th>"""+ filename + """</th>"""
                """<th>"""+ hash_value+"""</th>""")
            if hash_value in open(output_txt_file).read():
                f.write("<th> match</th>")
            else:
                 f.write("<th> Not match</th>")
            f.write("</tr>")



    f.write("""</table>""")

def extract_zip(input_zip,path):

    time.sleep(3)

    fh = open(input_zip, 'rb')
    z = zipfile.ZipFile(fh)
    for name in z.namelist():
        z.extract(name, path)
    fh.close()


def unpack_apps():

    for filename in os.listdir(path):
        if 'apk'in filename:
            p=(path+filename)
            s=os.makedirs(unz+filename)
            unz_path= (unz+filename)
            extract_zip(p,unz_path)
            unz_path= (unz+filename)
            time.sleep(4)
            print ("Currently, the program is unzipping this apk" + filename)



def converting_files_to_string():
     for filename in os.listdir(unz):
         full_path= unz +filename
         txtfile=txt_file_path+filename
         s=os.system(string_exe_file+' -s '+full_path+' >'+txtfile+".txt")


def unique(list1): 
      
    # insert the list to the set 
    list_set = set(list1) 
    # convert the set to the list 
    unique_list = (list(list_set)) 
    for x in unique_list:
        f.write("""<tr><th><p>"""+x+"""</p></th></tr>""")		

		
def filtering_links(txt_file):
 f.write("""<tr><th><h1 style="color:blue;">HTTPs links</h1></th></tr>""")
 url_list = []   
 txt_file=open(txt_file,'rb')
 for urls in txt_file:
    if re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+' , urls):
        url_list.append("http"+ urls.split("http",1)[-1])
 unique(url_list)
 txt_file.close()


def filtering_emails(txt_file):
 txt_file=open(txt_file,'rb')
 f.write("""<tr><th><h1 style="color:blue;">Emails :</h1></th></tr>""")
 email_list = []
 for email in txt_file:
    if re.search(r'\w+[.|\w]\w+@\w+[.]\w+[.|\w+]\w+' , email):
        email_list.append(email.split("*")[-1] )
 unique(email_list)
 txt_file.close()



def filtering_ips(txt_file):
 txt_file=open(txt_file,'rb')
 ip_list = []
 f.write("""<tr><th><h1 style="color:blue;">IP addresses:</h1></th></tr>""")

 for ip in txt_file:
    if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' , ip):
        ip_list.append(ip.split("*")[-1])
 unique(ip_list)
 txt_file.close()

def reading_txt_files():



    for filename in os.listdir(txt_file_path):
        f.write("""<table>""")
        f.write("<br><br>")

        if "txt"in filename:
            f.write("""<tr>""")
            f.write("""<th><h1 style="color:red;"> Actionable information of this app :"""+filename+"""</h1></th>""")
            full_path=txt_file_path+filename
            filtering_links(full_path)
            filtering_emails(full_path)
            filtering_ips(full_path)
            f.write("""</tr>""")
        f.write("""</table>""")



def print_permission():

      f.write("""<table><tr><h1 style="color:red;">Printing the permissions of each app :</h1></tr>
      <tr>
      <th>App Names</th>
      <th>permissions</th>
      </tr>""")




      for filename in os.listdir(path):
         if "apk" in filename:
             f.write("<tr>")
             f.write("""<th>"""+ filename + """</th>""")
             perm = apk.APK(path+filename)
             f.write("""<th>"""+ str(perm.get_permissions()) +"""</th>""")
             f.write("</tr>")
      f.write("""</table>""")


def upload_file(filename):
    baseurl = "https://www.virustotal.com/vtapi/v2/"
    api = "******************Enter your VT API HERE****************"

    url = baseurl + "file/scan"
    f = open(filename, "rb")
    files = {"file": f}
    values = {"apikey":api}
    r = requests.post(url, values, files=files)
    result=(r.json())
    return ("""%s  """
               % (result['permalink']))


def print_virustotal():
	
      f.write("""<table><tr><h1 style="color:red;">Printing Virus Total Links of this app  :</h1></tr>
      <tr>
      <th>App Names</th>
      <th>Links</th>
      </tr>""")
      for filename in os.listdir(path):
         if "apk" in filename:
             f.write("""<tr>""")
             f.write("""<th>"""+ filename + """</th>""")
             f.write("""<th> <a href="""""+upload_file(path+filename)+""">Click here to see the result of virus total </a></th>""")
             f.write("""</tr>""")
         continue
      f.write("</table>")



#print (print_virustotal())


def design_html_page():

    tac = time.clock()
    total_time=tac-tic
    f.write("""<h1 style="color:red;">Total processing time in seconds is """+str(total_time)+"</h1>""")
    f.write(



    """
    </body>
    </html>""")
    f.close()

    webbrowser.open_new_tab('report.html')

#this function is to delete the related files and artifcats 
def remove_directory():
	shutil.rmtree(dirName)
	
	
unpack_apps()
converting_files_to_string()
print_permission()
print_virustotal()
reading_txt_files()

design_html_page()
remove_directory()

