'''
Akond Rahman 
Bugzilla miner
Sep 14, 2018 
'''
import pandas as pd 
import numpy as np
import json 
import requests 

def getBugData(df_param):
    bugIDs = np.unique( df_param['BUG_ID'].tolist() )
    for bugID  in bugIDs:
        req_url  = 'https://bugzilla.mozilla.org/rest/bug/' + str(bugID).strip()    
        bug_data = requests.get(req_url)           
        bug_dict = bug_data.json()
        print bug_dict 
        print '*'*50


if __name__=='__main__':
   bug_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/2018.bug.crash.mapping.csv'
   bug_df = pd.read_csv(bug_file)
   getBugData(bug_df)