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
api_token = ''

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

        

if __name__=='__main__':
   pkl_fil = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/SECU_BUG_IDS.PKL'
   cmt_pkl_ = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/SECU_COMMENTS.PKL'

   #secu_bug_IDs = getSecurityBugIDs()   
   #pickle.dump( secu_bug_IDs, open(pkl_fil, 'wb')) 

   bugID_list = pickle.load(open(pkl_fil, 'rb') )
   cmts = getComments(bugID_list)

   pickle.dump(cmts, open(cmt_pkl_, 'wb'))