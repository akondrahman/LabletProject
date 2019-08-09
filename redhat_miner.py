'''
Akond Rahman 
RedHat miner
Jul 22, 2019 
'''
import os 
import pandas as pd 
import numpy as np
import json 
import requests
import cPickle as pickle 

api_token = ''

def processDict(dict_p):
    data_list = []
    if 'bugs' in dict_p:
       bug_data = dict_p['bugs']
       for bug_ in bug_data:
           
           alias          = bug_['alias']

           involved_count = len(bug_['cc']) + 1 # cc people + assigned 

           component      = bug_['component']           
           create_ts      = bug_['creation_time']

           priority       = bug_['priority']
           product        = bug_['product']           
           resolution     = bug_['resolution']           

           severity       = bug_['severity']           
           status         = bug_['status'] 
           summary        = bug_['summary']  
           creator        = bug_['creator']
           if 'cve' in summary:
               print 'Summary:', summary 
           url            = ''
           if 'url' in bug_:
              url = bug_['url']

           data_list = [alias, involved_count, component, create_ts, priority, product, resolution, severity, status, summary, url, creator]
    
    return data_list

def getBugData(df_param):
    all_bug_data = {}
    bugIDs = np.unique( df_param['BugID'].tolist() )
    # existing_dict = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUG_DETAILS.PKL', 'rb'))
    existing_dict = {}    
    for bugID  in bugIDs:
        if bugID not in existing_dict:
            print 'Analyzing:', bugID 
            req_url  = 'https://bugs.gentoo.org/rest/bug/' + str(bugID).strip()    
            bug_data = requests.get(req_url, params={'api_key': api_token })           
            bug_dict = bug_data.json()
            # print bug_dict 
            data_for_bug = processDict(bug_dict)
            # print bugID, data_for_bug
            if bugID not in all_bug_data:
               all_bug_data[bugID] = data_for_bug
            # print '*'*50
            pickle.dump( all_bug_data, open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_BUG_DETAILS.PKL', 'wb')) 
    return all_bug_data

if __name__=='__main__':
    # cve_bug_file  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/RedHat-CVE-BUGIDs.csv'
    # cve_bug_df    = pd.read_csv(cve_bug_file) 
    # bug_info_dict = getBugData(cve_bug_df)

    # cve_bug_file  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/Gentoo-CVE-BUGIDs.csv'
    # cve_bug_df    = pd.read_csv(cve_bug_file) 
    # bug_info_dict = getBugData(cve_bug_df)
    # pickle.dump( bug_info_dict, open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_GENTOO_BUG_DETAILS.PKL', 'wb')) 
    # print 'Dumped {} bugs'.format(len(bug_info_dict))      

    # bug_info_dict = {}

    # bug_dict1 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUG_DETAILS_1.PKL', 'rb'))
    # bug_dict2 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUG_DETAILS_2.PKL', 'rb'))
    # for k_, v_ in bug_dict1.iteritems():
    #     bug_info_dict[k_] = v_

    # for k_, v_ in bug_dict2.iteritems():
    #     bug_info_dict[k_] = v_

    # pickle.dump( bug_info_dict, open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_REDHAT_BUG_DETAILS.PKL', 'wb')) 
    # print 'Dumped {} bugs'.format(len(bug_info_dict))   

    # cve_bug_file  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/LibreOffice-CVE-BUGIDs.csv'
    # cve_bug_df    = pd.read_csv(cve_bug_file) 
    # bug_info_dict = getBugData(cve_bug_df)
    # pickle.dump( bug_info_dict, open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_LIBREOFFICE_BUG_DETAILS.PKL', 'wb')) 
    # print 'Dumped {} bugs'.format(len(bug_info_dict))          