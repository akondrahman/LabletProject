'''
Akond Rahman 
Oct 20 2018 
Get bugs with CVEs 
needed reffs: https://wiki.mozilla.org/Bugzilla:REST_API
'''
import requests 
import json 
import cPickle as pickle 
import numpy as np 
import os 
api_token = 'mWYEjiA4nOsii23LqFSuhotZyXJic5hRmMc5bFdm'

def getSecurityBugIDs():
    lis = []
    kws2look = ['sec-moderate', 'sec-critical', 'sec-high', 'sec-low']
    for kw_ in kws2look:
       url2look = 'https://bugzilla.mozilla.org/rest/bug?keywords=' + kw_ 
       bug_ID_data = requests.get( url2look , params={'api_key': api_token } )
       bug_dict    = bug_ID_data.json()
       bug_list    = bug_dict['bugs']
       for bug_json in bug_list:
           bugID = bug_json['id']
           lis.append((bugID, kw_))
       print 'Bugs gathered so far:{}, processed:{}'.format(len(lis), kw_)
    return lis 
   

def getComments(lis_par):
    list_ = []

    existing_ls1 = pickle.load(open('TMP_CMT_1.PKL', 'rb'))
    existing_ls2 = pickle.load(open('TMP_CMT_2.PKL', 'rb'))
    existing_ls3 = pickle.load(open('TMP_CMT_3.PKL', 'rb'))
    #existing_ls4 = pickle.load(open('TMP_CMT_4.PKL', 'rb'))
    existing_ls  = existing_ls1 + existing_ls2 + existing_ls3    
    existing_id  = [x_[0] for x_ in existing_ls]
    print 'So far analyzed:', len(np.unique(existing_id))
    for tup in lis_par:
        id_, sev = tup 
        if id not in existing_id:
            cmt_url     = 'https://bugzilla.mozilla.org/rest/bug/' + str(id_)  + '/comment' 
            cmt_url_dat = requests.get( cmt_url , params={'api_key': api_token } )
            cmt_dic     = cmt_url_dat.json()        
            cmt_lis     = cmt_dic['bugs'][str(id_)]['comments']

            for cmt in cmt_lis:
                if 'text' in cmt:
                   cmt_txt = cmt['text']
                   list_.append((id_, sev, cmt_txt))
            pickle.dump(list_, open('TMP_CMT.PKL', 'wb'))
            print id_ , len(cmt_lis)
            print '='*50         
    return list_ 

def dumpContentIntoFile(strP, fileP):
  strP = strP.encode('utf-8')
  fileToWrite = open( fileP, 'w')
  fileToWrite.write(strP )
  fileToWrite.close()
  return str(os.stat(fileP).st_size)


def dumpComment(prop_dict1, prop_dict2, comment_lis):        
    fullStr = ''
    index = 0 
    alias_dict = {}
    for k_, v_ in prop_dict1.iteritems():
        alias = v_[0]
        if alias != None:
            alias = alias.lower() 
            if 'cve' in alias:
               if alias not in alias_dict:
                  alias_dict[k_] = alias 
    for k_, v_ in prop_dict2.iteritems():
        alias = v_[0]
        if alias != None:
            alias = alias.lower() 
            if 'cve' in alias:
               if alias not in alias_dict:
                  alias_dict[k_] = alias 
    print 'No of comments to go through:', len(comment_lis)
    print 'No. of bugs with CVEs:', len(alias_dict)
    for tup_ in comment_lis:
        alias = 'NOT_MENTIONED'
        bugID   = tup_[0]    
        sec_tag = tup_[1]    
        coment  = tup_[2]    
        if bugID in alias_dict:
            alias = alias_dict[bugID]

            str0_ = 'INDEX:' + str(index) + '\n' + '-'*10 + '\n' 
            str1_ = 'BUG_ID:' + str(bugID) + '\n' + '-'*10 + '\n'
            str2_ = 'TAG:' + sec_tag + '\n' + '-'*10 + '\n'
            str3_ = 'CVE:' + alias + '\n' + '-'*10 + '\n'
            str4_ = coment + '\n' + '-'*10 + '\n'
            
            fullStr = fullStr + str0_ + str1_ + str2_ + str3_ + str4_ + '\n' + '='*50

        # if bugID in prop_dict1:
        #    alias = prop_dict1[bugID][0]
        # elif bugID in prop_dict2:
        #    alias = prop_dict2[bugID][0]
        # else:
        #    alias = 'NOT_MENTIONED' 
        # if alias==None: 
        #    alias = 'NOT_MENTIONED' 
        

        if (index % 5000 == 0):
           print 'Processed:', index
        index += 1 
    print fullStr
    dumpContentIntoFile(fullStr , '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/ALL_SEC_BUG_REPORT_COMMENTS.txt')

        

if __name__=='__main__':
   pkl_fil = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/SECU_BUG_IDS.PKL'
   cmt_pkl_ = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/SECU_COMMENTS.PKL'

   #secu_bug_IDs = getSecurityBugIDs()   
   #pickle.dump( secu_bug_IDs, open(pkl_fil, 'wb')) 

   #bugID_list = pickle.load(open(pkl_fil, 'rb') )
   #cmts = getComments(bugID_list)

   #pickle.dump(cmts, open(cmt_pkl_, 'wb'))

   sec_bug_prop_pkl1 = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/TMP_SEC_BUG_PROP_1.PKL'
   sec_bug_prop_dat1 = pickle.load(open(sec_bug_prop_pkl1, 'rb'))

   sec_bug_prop_pkl2 = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/TMP_SEC_BUG_PROP_2.PKL'
   sec_bug_prop_dat2 = pickle.load(open(sec_bug_prop_pkl2, 'rb'))    

   sec_bug_comm_pkl = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/SECU_COMMENTS.PKL'
   sec_bug_comm_dat = pickle.load(open(sec_bug_comm_pkl, 'rb'))   

   dumpComment(sec_bug_prop_dat1, sec_bug_prop_dat2, sec_bug_comm_dat)