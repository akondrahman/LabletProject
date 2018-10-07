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

def getDetailedAdvData(file_):
    # not used 
    dict_ret={}
    adv_dic = pickle.load(open(file_, 'rb'))
    for adv_, cve_details in adv_dic.iteritems():
        for cve_detail in cve_details:
            cve_name   = cve_detail[0]
            cve_impact = cve_detail[1]
            bug_ids    = cve_detail[2]
            if 'buglist.cgi' in bug_ids:
                bugs = bug_ids.split('=')[1]
                bug_lis = bugs.split('%')
                bug_lis = [x_.replace('2C', '') for x_ in bug_lis]
                bug_lis = [int(x_) for x_ in bug_lis if len(x_) > 0]
                for bug_ in bug_lis:
                    if bug_ not in dict_ret:
                        dict_ret[bug_] = (adv_, cve_name, cve_impact)
            else: 
                bug = bug_ids.split('=')[1]
                bug = bug.replace(' ', '')
                bug = int(bug)
                if bug not in dict_ret:
                    dict_ret[bug] = (adv_, cve_name, cve_impact)

    return dict_ret 

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
    
def getCrashDetails(fil_, cra_lis, bug_det_dic, bug_cve_dict):
    final_ls = []
    crash_meta_data = pickle.load(open(fil_, 'rb'))   
    for tup_ite in cra_lis:
        advisoryID = tup_ite[0]
        bugID      = tup_ite[1]        
        crashLink  = tup_ite[2]

        bugID      = int(bugID)
        severity   = 'NOT_FOUND'
        if bugID in bug_det_dic:
           bug_det  = bug_det_dic[bugID]
           severity = bug_det[8]

        cve_name, cve_impact = 'NOT_FOUND', 'NOT_FOUND'
        bugID      = str(bugID)
        if bugID in bug_cve_dict:
           cve_name, cve_impact   = bug_cve_dict[bugID]

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

        tup_track = (crashLink, advisoryID, bugID, sign, prod, reason, os, install_age, tot_vm, ava_vm, sys_mem_usg, severity, cve_name, cve_impact)  
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

def mapBug2CVE(cve_bug_fil):
    dict2Ret={}
    with open(cve_bug_fil, 'rU') as file_:
      reader_ = csv.reader(file_)
      next(reader_, None)
      for row_ in reader_:
        bug_      = row_[0]
        cveID     = row_[1]
        cveImpact = row_[2]
        cveDesc   = row_[3]

        if bug_ not in dict2Ret:
           dict2Ret[bug_] = (cveID, cveImpact)

    return dict2Ret

def constructFullDataFrameForAnalysis(year_para):
   adv_vul_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/' + year_para + '/'+ year_para +'.Advisory.Severity.PKL'
   adv_cve_dic = getAdvData(adv_vul_dat)
   #print adv_cve_dic  ## this is a dict where the key is advisory name 
   adv_bug_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/' + year_para + '/'+ year_para + '.Advisory.Bug.Mapping.csv'
   adv_bug_dic = getAdvBugData(adv_bug_dat)
   #print adv_bug_dic
   bug_cra_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/' + year_para + '/'+ year_para +'.bug.crash.mapping.csv'
   adv_bug_cra = getAdvBugCrashData(adv_bug_dic, bug_cra_dat)

   bug_det_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/' + year_para + '/'+ year_para +'.NEEDED.BUG.DETAILS.PKL'
   bug_det_dic = pickle.load(open(bug_det_dat, 'rb'))

   bug_cve_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/' + year_para + '/'+ year_para +'.BUG.CVE.MAPPING.csv'
   bug_cve_dic = mapBug2CVE(bug_cve_dat)

   crash_dat   = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/' + year_para + '/'+ year_para +'_CRASH_METADATA.PKL'
   crash_lis   = getCrashDetails(crash_dat, adv_bug_cra, bug_det_dic, bug_cve_dic)
   #print crash_lis

   df_cols = ['CRASH', 'ADVISORY', 'BUGID', 'CRASH_SIGN', 'PRODUCT', 'CRASH_REASON', 'OS', 'INSTALL_AGE', 'TOTAL_VM_BYTES', 'AVAILABLE_VM_BYTES', 'SYS_MEM_USG_PER', 'BUG_SEVERITY', 'CVE_NAME', 'CVE_IMPACT']
   detailed_crash_df = pd.DataFrame(crash_lis, columns=df_cols)

   detailed_crash_df = detailed_crash_df[detailed_crash_df['TOTAL_VM_BYTES'] != '']

   return detailed_crash_df    


if __name__=='__main__':
   detailed_crash_df_2017 = constructFullDataFrameForAnalysis('2017')
   detailed_crash_df_2018 = constructFullDataFrameForAnalysis('2018')
   detailed_crash_df_full = pd.concat(detailed_crash_df_2017, detailed_crash_df_2018)
   #print detailed_crash_df_full.shape
   print detailed_crash_df_full.head()
   
   detailed_crash_df_full.to_csv('/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017.DETAILED.CRASH.DF.csv')
   unique_bug_IDs_with_cve = list(np.unique(detailed_crash_df_full[detailed_crash_df_full['CVE_NAME']!='NOT_FOUND']['BUGID'].tolist()))
   df_with_cve = detailed_crash_df_full[detailed_crash_df_full['CVE_NAME']!='NOT_FOUND']
   print 'Dataframe size with CVEs:', df_with_cve.shape 
   print 'Number of bug IDs with CVE:', len(unique_bug_IDs_with_cve)
   '''
   Dataframe analysis
   '''
   #doReasonAnalysis(detailed_crash_df_full)
   