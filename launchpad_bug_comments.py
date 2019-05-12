'''
This program takes a list oif bug IDs as input 
and gets comments from lanucpad bugs 
Akond Rahman 
May 11, 2019 
reff: https://help.launchpad.net/API/launchpadlib 
reff: https://launchpad.net/+apidoc/1.0.html#bug
'''

from launchpadlib.launchpad import Launchpad 
launchpad = Launchpad.login_anonymously('just testing', 'production') 
import numpy as np 
import os 
import time 
import cPickle as pickle 

def dumpContentIntoFile(strP, fileP):
  strP = strP.encode('utf-8')
  fileToWrite = open( fileP, 'w')
  fileToWrite.write(strP )
  fileToWrite.close()
  return str(os.stat(fileP).st_size)

def getCommentForBug(bugID):
    bugStr = ''
    csvStr = ''
    comment_index = 0 
    the_bug      = launchpad.bugs[bugID]  
    bug_comments = the_bug.messages
    bug_cve      = the_bug.title  
    if len(bug_comments) > 0 : 
        # print 'Analyzing {} comments for bug#{}'.format(len(bug_comments), bugID)
        print bugID 
        for comment_obj in bug_comments:
                str1_ = 'BUG_ID:' + str(bugID) + '\n' + '-'*10 + '\n'
                str2_ = 'CVE:' + bug_cve + '\n' + '-'*10 + '\n'
                comment_content = comment_obj.content 
                if comment_obj.subject is not None:
                    comment_subject = comment_obj.subject 
                    comment_owner   = comment_obj.owner 
                    str3_ = 'SUBJECT:' + comment_subject + '\n' + '-'*10 + '\n'                    
                    str4_ = 'COMMENT_INDEX:' + str(comment_index) + '\n' + comment_content + '\n' + '-'*10 + '\n'
                
                    bugStr = bugStr  + str1_ + str2_ + str3_ + str4_ + '\n' + '='*50
                    csvStr = csvStr + str(bugID) + ',' + bug_cve +  ',' + str(comment_index) + ',' + str(comment_owner ) + '\n'
                    comment_index += 1 
                
    else: 
        print 'No comments found  for bug#', bugID 
    # print bugStr
    return bugStr, csvStr

def getBugComments(file_name, out_file, out_csv_file, pkl_out_file): 
    pkl_dict = {}
    full_str = '' 
    complete_csv_str = ''
    bug_pro_ind = 0 
    with open(file_name, 'rU') as f_:
         lines = f_.readlines()
    ID_list = [int(x_) for x_ in lines if x_!= '\n']
    unique_IDs = np.unique(ID_list) 
    print 'Bugs to analyze:', len( unique_IDs )
    print '*'*50 
    for bugID in unique_IDs: 
        bug_str, csv_str  = getCommentForBug(bugID)
        # print bug_str
        full_str = full_str + '\n' + bug_str
        complete_csv_str = complete_csv_str + csv_str 
        bug_pro_ind += 1 
        pkl_dict[bugID] = (bug_str, csv_str) 
    
        if ((bug_pro_ind%100)==0):
            dumpContentIntoFile(full_str, str(bug_pro_ind) + '_UBUNTU_TMP_BUG_REPORT.txt')
            dumpContentIntoFile(complete_csv_str, str(bug_pro_ind) + '_UBUNTU_TMP_BUG_REPORT_MAPPING.csv')      
            pickle.dump(pkl_dict, open(str(bug_pro_ind) + '_UBUNTU_TMP_BUG_CVE_MAP.PKL', 'wb'))   
    
    dumpContentIntoFile(full_str, out_file) 
    dumpContentIntoFile(complete_csv_str, out_csv_file)  
    pickle.dump(pkl_dict, open(pkl_out_file, 'wb'))   



if __name__=='__main__':
    # bugID_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/dataset-bugreport-synthesis/ost-with-cves-only/OST_BUG_IDS_RES.txt' 
    # output_comment_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/OSTK_CVE_BUG_REPORT_COMMENTS.txt'
    # output_csv_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/OSTK_CVE_BUG_REPORT_COMMENT_MAP.csv'
    # output_pkl_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/OSTK_CVE_BUG_REPORT_COMMENT_ALL.PKL'

    bugID_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/dataset-bugreport-synthesis/ubuntu-with-cves-only/UBU_BUG_IDS_RES.txt' 
    output_comment_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/UBUNTU_CVE_BUG_REPORT_COMMENTS.txt'
    output_csv_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/UBUNTU_CVE_BUG_REPORT_COMMENT_MAP.csv'
    output_pkl_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/UBUNTU_CVE_BUG_REPORT_COMMENT_ALL.PKL'

    getBugComments(bugID_file, output_comment_file, output_csv_file, output_pkl_file)  