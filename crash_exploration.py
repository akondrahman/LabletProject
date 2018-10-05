'''
Akond Rahman 
Oct 05, 2018 
Vulnerability Exploration 
'''
import cPickle as pickle
import pandas as pd  
import numpy as np 
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

if __name__=='__main__':
   adv_vul_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017.Advisory.Severity.PKL'
   adv_cve_dic = getAdvData(adv_vul_dat)
   #print adv_cve_dic
   adv_bug_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017.Advisory.Bug.Mapping.csv'
   adv_bug_dic = getAdvBugData(adv_bug_dat)
   print adv_bug_dic
