# APKanalysis

This script is created to help to automate the analysis process for APK files. The script can analyze multiple APKs at the same time.
The script is capable of doing the following:
1. unzipping apk file
2. converting files to strings 
3. search through the files for actionable information (emails, urls, IPs) 
4. Extracting apps permissions 
5. uplading the apk to VT
6. Generate a Report




Requirements :
Python 2.7 
Strings.exe from Microsoft sysinternals placed in C:\
Virustotal API or remove the function 

Packages:
pip install AxmlParserPY
pip install requests

Command Example:

"python.exe C:\Users\H\Download\APKAnalyzer.py C:\Users\H\Downloads\apps"
