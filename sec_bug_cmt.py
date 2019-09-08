'''
Akond Rahman 
Oct 20 2018 
Get bugs with CVEs 
needed reffs: https://wiki.mozilla.org/Bugzilla:REST_API
'''
import pandas as pd 
import requests 
import json 
import cPickle as pickle 
import numpy as np 
import os 

api_token = ''

def getSecurityBugIDs(specialFlag=False): 
    lis, lines_txt = [], []
    if  specialFlag:
        with open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/ALL_NEEDED_MOZI_FILES/2019_MOZILLA_CVE_BUG_IDs.txt') as f_:
            lines_txt = f_.read().splitlines()
        lis = [(int(x_), 'has-cve') for x_ in lines_txt if x_ != '\n' and len(x_) > 0 ] 
    else:
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
    list_, existing_id = [], []

    # existing_ls1 = pickle.load(open('TMP_CMT_1.PKL', 'rb'))
    # existing_ls2 = pickle.load(open('TMP_CMT_2.PKL', 'rb'))
    # existing_ls3 = pickle.load(open('TMP_CMT_3.PKL', 'rb'))
    # existing_ls4 = pickle.load(open('TMP_CMT_4.PKL', 'rb'))
    # existing_ls  = existing_ls1 + existing_ls2 + existing_ls3    
    # existing_id  = [x_[0] for x_ in existing_ls]
    # print 'So far analyzed:', len(np.unique(existing_id))
    for tup in lis_par:
        id_, sev = tup 
        if id not in existing_id:
            cmt_url     = 'https://bugzilla.mozilla.org/rest/bug/' + str(id_)  + '/comment' 
            cmt_url_dat = requests.get( cmt_url , params={'api_key': api_token } )
            cmt_dic     = cmt_url_dat.json() 
            if 'bugs' in cmt_dic:       
                cmt_lis     = cmt_dic['bugs'][str(id_)]['comments']

                for cmt in cmt_lis:
                    if 'text' in cmt:
                        cmt_txt = cmt['text']
                        list_.append((id_, sev, cmt_txt))
                        pickle.dump(list_, open('TMP_CMT.PKL', 'wb'))
                        print id_ , len(cmt_lis)
                        print '='*50         
    return list_ 

def getRedHatBugComments(lis_par, alreadyList):
    forbidden_list = [1719503, 1679545]
    list_ = []
    for id_ in lis_par:
        if (id_ not in alreadyList) and (id_ not in forbidden_list):
            print 'Analyzing:', id_ 
            cmt_url     = 'https://bugzilla.redhat.com/rest/bug/' + str(id_)  + '/comment' 
            cmt_url_dat = requests.get( cmt_url , params={'api_key': api_token } )
            cmt_dic     = cmt_url_dat.json() 
            if 'bugs' in cmt_dic:       
                cmt_lis     = cmt_dic['bugs'][str(id_)]['comments']

                for cmt in cmt_lis:
                    if 'text' in cmt:
                        cmt_txt = cmt['text']
                        list_.append((id_, cmt_txt))
            pickle.dump(list_, open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/REDHAT_BUGS_CMT.PKL', 'wb'))
            print 'Comments processed:', len(cmt_lis)
            print '='*50         
    return list_ 

def getGen2BugComments(lis_par, alreadyList=[]):
    forbidden_list = [] 
    list_ = []
    for id_ in lis_par:
        if (id_ not in alreadyList) and (id_ not in forbidden_list):
            print 'Analyzing:', id_ 
            # bug description: https://bugs.gentoo.org/rest/bug/659288 
            # bug comment:     https://bugs.gentoo.org/rest/bug/659288/comment
            cmt_url     = 'https://bugs.gentoo.org/rest/bug/' + str(id_)  + '/comment' 
            cmt_url_dat = requests.get( cmt_url , params={'api_key': api_token } )
            cmt_dic     = cmt_url_dat.json() 
            if 'bugs' in cmt_dic:       
                cmt_lis     = cmt_dic['bugs'][str(id_)]['comments']
                for cmt in cmt_lis:
                    if 'text' in cmt:
                        cmt_txt = cmt['text']
                        list_.append((id_, cmt_txt))
            pickle.dump(list_, open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_GEN2_BUGS_CMT.PKL', 'wb'))
            print 'Comments processed:', len(cmt_lis)
            print '='*50         
    return list_ 

def getLibreBugComments(lis_par, alreadyList=[]):
    forbidden_list = [] 
    list_ = []
    for id_ in lis_par:
        if (id_ not in alreadyList) and (id_ not in forbidden_list):
            print 'Analyzing:', id_ 
            # bug description: 
            # bug comment:     
            cmt_url     = 'https://bugs.documentfoundation.org/rest/bug/' + str(id_)  + '/comment' 
            cmt_url_dat = requests.get( cmt_url , params={'api_key': api_token } )
            cmt_dic     = cmt_url_dat.json() 
            if 'bugs' in cmt_dic:       
                cmt_lis     = cmt_dic['bugs'][str(id_)]['comments']
                for cmt in cmt_lis:
                    if 'text' in cmt:
                        cmt_txt = cmt['text']
                        list_.append((id_, cmt_txt))
            pickle.dump(list_, open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_LIBRE_BUGS_CMT.PKL', 'wb'))
            print 'Comments processed:', len(cmt_lis)
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
    # print fullStr
    dumpContentIntoFile(fullStr , '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/ALL_SEC_BUG_REPORT_COMMENTS.txt')

def preprocessText(str_single_val):

    str_single_val = str_single_val.lower() 
    msg_commit = str_single_val.replace('\n', ' ' )
    msg_commit = msg_commit.replace(',',  ' ')    
    msg_commit = msg_commit.replace('\t', ' ')
    msg_commit = msg_commit.replace('&',  ' ')  
    msg_commit = msg_commit.replace('#',  ' ')
    msg_commit = msg_commit.replace('=',  ' ')      

    return msg_commit

def dumpExtraCreditData(file_name, oracle_file):
    ls_ = pickle.load(open(file_name, 'rb') )
    df_ = pd.DataFrame(ls_, columns=['BUGID', 'PRIORITY', 'COMMENT', 'CVE', 'COMPONENT', 'TIME', 'BUGTITLE'])
    # print df_.head()
    df_['COMMENT']     = df_['COMMENT'].apply(preprocessText)
    df_['CVE']         = df_['CVE'].apply(preprocessText)
    df_['BUGTITLE']    = df_['BUGTITLE'].apply(preprocessText)
    df_['COMPONENT']   = df_['COMPONENT'].apply(preprocessText)

    print df_.head() 
    df_.to_csv(oracle_file, encoding='utf-8', index = False, columns=['BUGID', 'PRIORITY', 'COMMENT', 'CVE', 'COMPONENT', 'TIME', 'BUGTITLE'])

def dumpSanityData(file_name, sanity_file):
    ls_ = pickle.load(open(file_name, 'rb') )
    df_ = pd.DataFrame(ls_, columns=['BUGID', 'COMMENT'])
    df_['COMMENT']     = df_['COMMENT'].apply(preprocessText)
    df_.to_csv(sanity_file, encoding='utf-8', index = False, columns=['BUG', 'COMMENT'])
    print df_.head() 

def getBugCount(file_name):
    print file_name
    ls_ = pickle.load(open(file_name, 'rb') )
    # df_ = pd.DataFrame(ls_, columns=['BUGID', 'PRIORITY', 'COMMENT', 'CVE', 'COMPONENT', 'TIME', 'BUGTITLE'])
    df_ = pd.DataFrame(ls_, columns=['BUGID', 'COMMENT'])
    print len(np.unique( df_['BUGID'] ) )
    print '*'*25


if __name__=='__main__':
#    '''
#    MOZILLA
#    '''
#    pkl_fil = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/MOZI_2019_SECU_BUG_IDS.PKL'
#    cmt_pkl_ = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/MOZI_2019_SECU_COMMENTS.PKL'

#    secu_bug_IDs = getSecurityBugIDs(True)    
#    pickle.dump( secu_bug_IDs, open(pkl_fil, 'wb')) 

#    bugID_list = pickle.load(open(pkl_fil, 'rb') )
#    cmts = getComments(bugID_list)

#    pickle.dump(cmts, open(cmt_pkl_, 'wb'))

    '''
    REDHAT
    '''

    # redhat_csv_file        = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/RedHat-CVE-BUGIDs.csv'
    # redhat_df              = pd.read_csv(redhat_csv_file) 
    # redhat_bug_ID_list     = np.unique( redhat_df['BugID'].tolist() )
    # print 'Total bugs with CVEs for Redhat:', len(redhat_bug_ID_list) 
    # already_visited_list1  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_1.PKL', 'rb'))
    # already_visited_list2  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_2.PKL', 'rb'))
    # already_visited_list3  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_3.PKL', 'rb'))
    # already_visited_list4  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_4.PKL', 'rb'))
    # already_visited_list5  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_5.PKL', 'rb'))
    # already_visited_list6  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_6.PKL', 'rb'))
    # already_visited_list7  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_7.PKL', 'rb'))
    # already_visited_list8  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_8.PKL', 'rb'))
    # already_visited_list9  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_9.PKL', 'rb'))
    # already_visited_list10 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_10.PKL', 'rb'))
    # already_visited_list11 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_11.PKL', 'rb'))
    # already_visited_list12 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_12.PKL', 'rb'))

    # already_visited_list   = already_visited_list1 + already_visited_list2 + already_visited_list3 + already_visited_list4 + already_visited_list5 + already_visited_list6 + already_visited_list7 + already_visited_list8 + already_visited_list9 + already_visited_list10 + already_visited_list11 + already_visited_list12
    # already_visited_list   = [x_[0] for x_ in already_visited_list] 
    # already_visited_list   = list(np.unique(already_visited_list) ) 
    # print 'So far got comments for:', len(already_visited_list) 
    # bug_comments           = getRedHatBugComments(redhat_bug_ID_list, already_visited_list) 
    # full_bug_str           = ''
    # already_visited_list1  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_1.PKL', 'rb'))
    # already_visited_list2  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_2.PKL', 'rb'))
    # already_visited_list3  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_3.PKL', 'rb'))
    # already_visited_list4  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_4.PKL', 'rb'))
    # already_visited_list5  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_5.PKL', 'rb'))
    # already_visited_list6  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_6.PKL', 'rb'))
    # already_visited_list7  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_7.PKL', 'rb'))
    # already_visited_list8  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_8.PKL', 'rb'))
    # already_visited_list9  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_9.PKL', 'rb'))
    # already_visited_list10 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_10.PKL', 'rb'))
    # already_visited_list11 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_11.PKL', 'rb'))
    # already_visited_list12 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_12.PKL', 'rb'))
    # already_visited_list13 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_13.PKL', 'rb'))

    # bug_comments           = already_visited_list1 + already_visited_list2 + already_visited_list3 + already_visited_list4 + already_visited_list5 + already_visited_list6 + already_visited_list7 + already_visited_list8 + already_visited_list9 + already_visited_list10 + already_visited_list11 + already_visited_list12 + already_visited_list13

    # for x_ in bug_comments:
    #     bugID, comment_    = x_
    #     full_bug_str       = full_bug_str + str(bugID) + ',' + comment_ + ',' + '\n' 
    # dumpContentIntoFile(full_bug_str, '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/REDHAT_BUG_COMMENTS.csv') 
    # pickle.dump(bug_comments, open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/REDHAT_BUGS_CMT.PKL', 'wb'))


#    sec_bug_prop_pkl1 = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/TMP_SEC_BUG_PROP_1.PKL'
#    sec_bug_prop_dat1 = pickle.load(open(sec_bug_prop_pkl1, 'rb'))

#    sec_bug_prop_pkl2 = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/TMP_SEC_BUG_PROP_2.PKL'
#    sec_bug_prop_dat2 = pickle.load(open(sec_bug_prop_pkl2, 'rb'))    

#    sec_bug_comm_pkl = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/SECU_COMMENTS.PKL'
#    sec_bug_comm_dat = pickle.load(open(sec_bug_comm_pkl, 'rb'))   

#    dumpComment(sec_bug_prop_dat1, sec_bug_prop_dat2, sec_bug_comm_dat)



    '''
    GENTOO
    '''

    # gen2_csv_file        = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/Gentoo-CVE-BUGIDs.csv'
    # gen2_df              = pd.read_csv(gen2_csv_file) 
    # gen2_bug_ID_list     = np.unique( gen2_df['BugID'].tolist() )
    # print 'Total bugs with CVEs for Gentoo:', len(gen2_bug_ID_list) 

    # already_visited_list1  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_1.PKL', 'rb'))
    # already_visited_list2  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_2.PKL', 'rb'))
    # already_visited_list3  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_3.PKL', 'rb'))
    # already_visited_list4  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_4.PKL', 'rb'))
    # already_visited_list5  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_5.PKL', 'rb'))
    # already_visited_list6  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_6.PKL', 'rb'))
    # already_visited_list7  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_7.PKL', 'rb'))
    # already_visited_list8  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_8.PKL', 'rb'))
    # already_visited_list9  = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_9.PKL', 'rb'))
    # already_visited_list10 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_10.PKL', 'rb'))
    # already_visited_list11 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_11.PKL', 'rb'))
    # already_visited_list12 = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/TEMP_REDHAT_BUGS_CMT_12.PKL', 'rb'))

    # already_visited_list   = already_visited_list1 + already_visited_list2 + already_visited_list3 + already_visited_list4 + already_visited_list5 + already_visited_list6 + already_visited_list7 + already_visited_list8 + already_visited_list9 + already_visited_list10 + already_visited_list11 + already_visited_list12
    # already_visited_list   = [x_[0] for x_ in already_visited_list] 
    # already_visited_list   = list(np.unique(already_visited_list) ) 
    # print 'So far got comments for:', len(already_visited_list) 

    # bug_comments           = getGen2BugComments(gen2_bug_ID_list) 
    # pickle.dump(bug_comments, open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/GEN2_BUGS_CMT.PKL', 'wb'))    

    '''
    LibreOffice 
    '''
    # libre_csv_file        = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/LibreOffice-CVE-BUGIDs.csv'
    # libre_df              = pd.read_csv(libre_csv_file) 
    # libre_bug_ID_list     = np.unique( libre_df['BugID'].tolist() )
    # print 'Total bugs with CVEs for LibreOffice:', len(libre_bug_ID_list)     
    # bug_comments          = getLibreBugComments(libre_bug_ID_list) 
    # pickle.dump(bug_comments, open('/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/LIBRE_BUGS_CMT.PKL', 'wb'))        

    '''
    Get comments for extra credit and sanity check 
    '''
    # comment_dataset = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/UPTO_2018_MOZILLA_FULL_CSV.csv.PKL'
    # oracle_dataset  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/ORACLE_MOZILLA.csv'

    # comment_dataset = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/LIBRE_BUGS_CMT.PKL'
    # oracle_dataset  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/SANITY_LIBRE.csv'

    # comment_dataset = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/FINAL_GEN2_BUGS_CMT.PKL'
    # oracle_dataset  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/SANITY_GEN2.csv'

    # comment_dataset = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/FINAL_REDHAT_BUGS_CMT.PKL'
    # oracle_dataset  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/SANITY_REDHAT.csv'

    # dumpSanityData(comment_dataset, oracle_dataset)

    '''
    Get bug report count 
    '''
    # comment_dataset = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/UPTO_2018_MOZILLA_FULL_CSV.csv.PKL'
    # comment_dataset = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/MOZI_ONLY2019__FULL.PKL'
    # comment_dataset = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/LIBRE_BUGS_CMT.PKL'
    # comment_dataset = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/FINAL_GEN2_BUGS_CMT.PKL'
    # comment_dataset = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/FINAL_REDHAT_BUGS_CMT.PKL'


    getBugCount(comment_dataset)    
    