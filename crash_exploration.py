'''
Akond Rahman 
Oct 05, 2018 
Vulnerability Exploration 
'''
import cPickle as pickle
import pandas as pd  
import numpy as np 
import csv 
from collections import Counter 

def getAdvData(file_):
    adv_dic = pickle.load(open(file_, 'rb'))
    return adv_dic 

def getAdvBugData(fil_):
    dic_   = {} 
    df_    = pd.read_csv(fil_) 
    advIDs = np.unique( df_['Advisory'].tolist() )
    for advID in advIDs:
        if advID not in dic_:
           bugs = list(np.unique(df_[df_['Advisory']==advID]['BugReport'].tolist()))
           dic_[advID] = bugs
    return dic_

def getBugCrash(file_):
    dict2Ret={}
    with open(file_, 'rU') as bug_cra_fil:
      reader_ = csv.reader(bug_cra_fil)
      next(reader_, None)
      for row_ in reader_:
        crash_list = []
        bug_       = row_[0]
        crash_urls = row_[1]
        filtered_crashes = crash_urls.split(' ')
        filtered_crashes = [x_ for x_ in filtered_crashes if len(x_) > 0 ]
        filtered_crashes = [x_.replace('"', '') for x_ in filtered_crashes]
        if bug_ not in dict2Ret:
           dict2Ret[bug_] = filtered_crashes
        else: 
           dict2Ret[bug_] = dict2Ret[bug_] + filtered_crashes



    return dict2Ret        

def getAdvBugCrashData(dic_, fil_):
    final_list = []
    bug_cra_dic = getBugCrash(fil_)
    for advisory, bugs in dic_.iteritems():
        bugIDs = [x_.split('=')[1] for x_ in bugs ]
        for bugID in bugIDs:
            if bugID in bug_cra_dic:
               crashes = bug_cra_dic[bugID]
               for crashLink in crashes:
                   tuple_add = (advisory, bugID, crashLink)
                   final_list.append(tuple_add)
    return final_list
    
def getCrashDetails(fil_, cra_lis):
    final_ls = []
    crash_meta_data = pickle.load(open(fil_, 'rb'))   
    for tup_ite in cra_lis:
        advisoryID = tup_ite[0]
        bugID      = tup_ite[1]        
        crashLink  = tup_ite[2]
        if crashLink in crash_meta_data:
            sign, prod, reason, os, install_age, tot_vm, ava_vm, sys_mem_usg = '', '', '', '', '', '', '', ''
            list_of_tuples = crash_meta_data[crashLink]
            for tup_ in list_of_tuples:
                key_ = tup_[0]
                val_ = tup_[1]
                if (key_=='Signature'):
                   sign =  val_
                elif (key_=='Product'):
                    prod = val_
                elif(key_=='Crash Reason'):
                    reason = val_
                elif (key_=='OS'):
                    os = val_
                elif(key_=='Install Age'):
                    install_age = val_  
                    install_age = install_age.replace(' ', '') 
                    install_age = install_age.replace(',', '')  
                    install_age = install_age.split('s')[0]
                elif (key_=='Total Virtual Memory'):
                    tot_vm = val_
                    tot_vm = tot_vm.replace(',', '')
                    tot_vm = tot_vm.replace(' ', '')
                    tot_vm = tot_vm.split('b')[0]
                elif(key_=='Available Virtual Memory'):
                    ava_vm = val_                         
                    ava_vm = ava_vm.replace(',', '')
                    ava_vm = ava_vm.replace(' ', '')
                    ava_vm = ava_vm.split('b')[0]
                elif(key_=='System Memory Use Percentage'):
                    sys_mem_usg = val_     
        tup_track = (crashLink, advisoryID, bugID, sign, prod, reason, os, install_age, tot_vm, ava_vm, sys_mem_usg)  
        final_ls.append(tup_track)
    return final_ls                

def getCrashAgeBySign(prod_df, signs, prod):
    signs = np.unique(signs)
    for sign in signs:
        sign_prod_df = prod_df[prod_df['CRASH_SIGN']==sign]
        age_list = sign_prod_df['INSTALL_AGE'].tolist()
        age_dis  = dict(Counter(age_list))
        print 'Product:{}, Signature:{}, Age distribution:{}'.format(prod, sign, age_dis)
        print '='*10
    

def doReasonAnalysis(df_p):
    prod_list = np.unique( df_p['PRODUCT'].tolist() )         
    for prod in prod_list: 
        prod_full_df = df_p[df_p['PRODUCT']==prod]
        prod_full_df_len, prod_full_df_cols = prod_full_df.shape 
        reason_list = prod_full_df['CRASH_REASON'].tolist()
        reason_freq = dict(Counter(reason_list))
        sign_list   = prod_full_df['CRASH_SIGN'].tolist()
        sign_freq   = dict(Counter(sign_list))
        print '-'*50
        print prod 
        print 'Crash count:', prod_full_df_len 
        print '*'*25
        print 'Distribution of crash reasons:', reason_freq
        print '*'*25
        print 'Distribution of crash signs:', sign_freq
        print '*'*25
        getCrashAgeBySign(prod_full_df, sign_list, prod)
        print '*'*25
        print '-'*50



if __name__=='__main__':
   '''
   Dataframe construction 
   '''
   adv_vul_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017.Advisory.Severity.PKL'
   adv_cve_dic = getAdvData(adv_vul_dat)
   #print adv_cve_dic
   adv_bug_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017.Advisory.Bug.Mapping.csv'
   adv_bug_dic = getAdvBugData(adv_bug_dat)
   #print adv_bug_dic
   bug_cra_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017.bug.crash.mapping.csv'
   adv_bug_cra = getAdvBugCrashData(adv_bug_dic, bug_cra_dat)
   print 'Number of crashes with vulnerabilities:', len(adv_bug_cra)
   crash_dat   = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017_CRASH_METADATA.PKL'
   crash_lis   = getCrashDetails(crash_dat, adv_bug_cra)
   #print crash_lis
   df_cols = ['CRASH', 'ADVISORY', 'BUGID', 'CRASH_SIGN', 'PRODUCT', 'CRASH_REASON', 'OS', 'INSTALL_AGE', 'TOTAL_VM_BYTES', 'AVAILABLE_VM_BYTES', 'SYS_MEM_USG_PER']
   detailed_crash_df = pd.DataFrame(crash_lis, columns=df_cols)
   #print detailed_crash_df.shape
   print detailed_crash_df.head()
   '''
   Dataframe analysis
   '''
   doReasonAnalysis(detailed_crash_df)
   