'''
Akond Rahman 
Bugzilla miner
Sep 14, 2018 
'''
import pandas as pd 
import numpy as np
import json 
import requests
import cPickle as pickle 


def processDict(dict_p):
    data_list = []
    if 'bugs' in dict_p:
       bug_data = dict_p['bugs']
       for bug_ in bug_data:
           
           alias          = bug_['alias']
           if 'cve' in alias:
               print 'Alias:', alias 
           involved_count = len(bug_['cc']) + 1 # cc people + assigned 
           comment_count  = bug_['comment_count']
           component      = bug_['component']           
           create_ts      = bug_['creation_time']

           priority       = bug_['priority']
           product        = bug_['product']           
           resolution     = bug_['resolution']           

           severity       = bug_['severity']           
           status         = bug_['status'] 
           summary        = bug_['summary']  
           if 'cve' in summary:
               print 'Summary:', summary 
           url            = ''
           if 'url' in bug_:
              url = bug_['url']

           data_list = [alias, involved_count, comment_count, component, create_ts, priority, product, resolution, severity, status, summary, url]
    
    return data_list



def getBugData(df_param):
    all_bug_data = {}
    bugIDs = np.unique( df_param['BUG_ID'].tolist() )
    for bugID  in bugIDs:
        req_url  = 'https://bugzilla.mozilla.org/rest/bug/' + str(bugID).strip()    
        bug_data = requests.get(req_url)           
        bug_dict = bug_data.json()
        # print bug_dict 
        data_for_bug = processDict(bug_dict)
        # print bugID, data_for_bug
        if bugID not in all_bug_data:
           all_bug_data[bugID] = data_for_bug
        # print '*'*50
    return all_bug_data

def getSecBugData(lis_par):
    all_bug_data = {}
    for bugID  in lis_par:
        req_url  = 'https://bugzilla.mozilla.org/rest/bug/' + str(bugID).strip()    
        bug_data = requests.get(req_url)           
        bug_dict = bug_data.json()
        # print bug_dict 
        data_for_bug = processDict(bug_dict)
        # print bugID, data_for_bug
        if bugID not in all_bug_data:
           all_bug_data[bugID] = data_for_bug
        # print '*'*50
    return all_bug_data


if __name__=='__main__':
#    bug_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2018/2018.bug.crash.mapping.csv'
#    bug_df = pd.read_csv(bug_file)
#    all_bug_dict = getBugData(bug_df)
#    pickle.dump( all_bug_dict, open('/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2018/2018.NEEDED.BUG.DETAILS.PKL', 'wb')) 
#    print all_bug_dict  

     sec_bug_pkl = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/SECU_BUG_IDS.PKL'
     lis = pickle.load(open(sec_bug_pkl, 'rb')) 
     sec_bug_dic = getSecBugData(lis)
     pickle.dump( sec_bug_dic, open('/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/SEC_BUG_PROP.PKL', 'wb'))      