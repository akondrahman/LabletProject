'''
Akond Rahman 
Bugzilla miner
Sep 14, 2018 
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
        bug_data = requests.get(req_url, params={'api_key': api_token })           
        bug_dict = bug_data.json()
        # print bug_dict 
        data_for_bug = processDict(bug_dict)
        # print bugID, data_for_bug
        if bugID not in all_bug_data:
           all_bug_data[bugID] = data_for_bug
        # print '*'*50
    return all_bug_data

def getSecBugData(lis_par):
    print 'Need to process:', len(lis_par)
    all_bug_data = {}
    already = []
    # already = pickle.load(open('TMP_SEC_CMT_1.PKL', 'rb'))
    print 'Already processed:', len(already)
    for bugIDTuple  in lis_par:
        bugID, bugSeverity = bugIDTuple
        if bugID not in already:
            req_url  = 'https://bugzilla.mozilla.org/rest/bug/' + str(bugID).strip()    
            bug_data = requests.get(req_url, params={'api_key': api_token })  
            print bugID , bugSeverity
            # print bug_data         
            bug_dict = bug_data.json()
            # print bug_dict 
            data_for_bug = processDict(bug_dict)
            # print bugID, data_for_bug
            if bugID not in all_bug_data:
               all_bug_data[bugID] = data_for_bug
            # print '*'*50
            pickle.dump( all_bug_data, open('TMP_SEC_CMT.PKL', 'wb'))      
    return all_bug_data

def dumpContentIntoFile(strP, fileP):
  strP = strP.encode('utf-8')
  fileToWrite = open( fileP, 'w')
  fileToWrite.write(strP )
  fileToWrite.close()
  return str(os.stat(fileP).st_size)

def filterText(msg_commit):
    msg_commit = msg_commit.replace('\n', ' ')
    msg_commit = msg_commit.replace(',',  ';')    
    msg_commit = msg_commit.replace('\t', ' ')
    msg_commit = msg_commit.replace('&',  ';')  
    msg_commit = msg_commit.replace('#',  ' ')
    msg_commit = msg_commit.replace('=',  ' ')      

    return msg_commit

def createMozillaCSV(prop_file, bugID_file, cmt_file, out_file_csv):
    full_data_list = []
    props_dict = pickle.load(open(prop_file, 'rb'))
    bugID_list = pickle.load(open(bugID_file, 'rb'))
    comm_list  = pickle.load(open(cmt_file, 'rb'))
    bug_component, bug_date, bug_title, bug_alias = '', '', '', ''
    full_str = ''

    for comment_ in comm_list:
        bugID      = comment_[0]
        bugTag     = comment_[1]
        commentTxt = comment_[2]
        # commentTxt = commentTxt.encode("utf-8")     
        # 1306628: [u'CVE-2016-9894', 15, 36, u'Graphics', u'2016-09-30T14:43:12Z', u'--', u'Core', u'FIXED', u'normal', u'RESOLVED', u'Heap-buffer-overflow in AAHairlineBatch::onPrepareDraws', u'']
        if bugID in props_dict:
           bug_props = props_dict[bugID]   
           bug_alias = bug_props[0]
           if bug_alias != None:
              bug_alias = bug_alias.lower()            
              if 'cve' in bug_alias:
                bug_component = bug_props[3] 
                bug_date      = bug_props[4] 
                bug_title     = bug_props[10]

                full_str = full_str + str(bugID) + ',' + bugTag + ',' + commentTxt + ',' + bug_alias + ',' + bug_component + ',' + bug_date + ',' + bug_title + '\n'
                full_data_list.append( (bugID, bugTag, commentTxt, bug_alias, bug_component, bug_date, bug_title) )
            
    bytes_ = dumpContentIntoFile(full_str, out_file_csv) 
    pickle.dump(full_data_list, open(out_file_csv+ '.PKL', 'wb')) 
    print 'Dumped a file of {} bytes'.format(bytes_) 

if __name__=='__main__':
    #    bug_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2018/2018.bug.crash.mapping.csv'
    #    bug_df = pd.read_csv(bug_file)
    #    all_bug_dict = getBugData(bug_df)
    #    pickle.dump( all_bug_dict, open('/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2018/2018.NEEDED.BUG.DETAILS.PKL', 'wb')) 
    #    print all_bug_dict  

    # sec_bug_pkl = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/MOZI_2019_SECU_BUG_IDS.PKL'
    # lis = pickle.load(open(sec_bug_pkl, 'rb')) 
    # sec_bug_dic = getSecBugData(lis)
    # pickle.dump( sec_bug_dic, open('/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/MOZI_2019_SEC_BUG_PROP.PKL', 'wb'))  
    #   
    # 

    # moz_prop_file     = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_NEEDED_MOZI_FILES/MOZI_2019_SEC_BUG_PROP.PKL'
    # moz_bug_id_file   = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_NEEDED_MOZI_FILES/MOZI_2019_SECU_BUG_IDS.PKL'
    # moz_bug_cmt_file  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_NEEDED_MOZI_FILES/MOZI_2019_SECU_COMMENTS.PKL'
    # out_file          = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_NEEDED_MOZI_FILES/MOZI_ONLY2019_CSV.csv'

    moz_prop_file     = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_NEEDED_MOZI_FILES/UPTO_2018_MOZILLA_SEC_BUG_PROP.PKL'
    moz_bug_id_file   = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_NEEDED_MOZI_FILES/UPTO_2018_MOZILLA_SECU_BUG_IDS.PKL'
    moz_bug_cmt_file  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_NEEDED_MOZI_FILES/UPTO_2018_MOZILLA_SECU_COMMENTS.PKL'
    out_file          = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_NEEDED_MOZI_FILES/UPTO_2018_MOZILLA_FULL_CSV.csv'

    createMozillaCSV(moz_prop_file, moz_bug_id_file, moz_bug_cmt_file, out_file) 