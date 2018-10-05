'''
Akond Rahman 
Oct 05, 2018 
Vulnerability Exploration 
'''
import cPickle as pickle
import pandas as pd  
import numpy as np 
import csv 
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
    
    

if __name__=='__main__':
   adv_vul_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017.Advisory.Severity.PKL'
   adv_cve_dic = getAdvData(adv_vul_dat)
   #print adv_cve_dic
   adv_bug_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017.Advisory.Bug.Mapping.csv'
   adv_bug_dic = getAdvBugData(adv_bug_dat)
   #print adv_bug_dic
   bug_cra_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017.bug.crash.mapping.csv'
   adv_bug_cra = getAdvBugCrashData(adv_bug_dic, bug_cra_dat)
   print adv_bug_cra
