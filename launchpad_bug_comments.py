'''
This program takes a list oif bug IDs as input 
and gets comments from lanucpad bugs 
Akond Rahman 
May 11, 2019 
'''
from launchpadlib.launchpad import Launchpad 
launchpad = Launchpad.login_anonymously('just testing', 'production') 
import numpy as np 

def dumpContentIntoFile(strP, fileP):
  strP = strP.encode('utf-8')
  fileToWrite = open( fileP, 'w')
  fileToWrite.write(strP )
  fileToWrite.close()
  return str(os.stat(fileP).st_size)

def getCommentForBug(bugID):
    bugStr = ''
    if bugID in launchpad.bugs: 
        the_bug = launchpad.bugs[bug]  
        bug_comments = the_bug.messages
        bug_cves     = the_bug.cves 
        if len(bug_comments) > 0 : 
            for comment in bug_comments:
                for cve_ in bug_cves:
                    str1_ = 'BUG_ID:' + str(bugID) + '\n' + '-'*10 + '\n'
                    str3_ = 'CVE:' + cve_ + '\n' + '-'*10 + '\n'
                    str4_ = comment + '\n' + '-'*10 + '\n'
                
                    bugStr = bugStr  + str1_ + str2_ + str3_ + str4_ + '\n' + '='*50
    else: 
        print 'Did not find bug#', bugID
    return bugStr

def getBugComments(file_name, out_file):
    full_str = '' 
    with open(file_name, 'rU') as f_:
         lines = f_.readlines()
    ID_list = [int(x_) for x_ in lines if x_!= '\n']
    unique_IDs = np.unique(ID_list) 
    for bugID in unique_IDs: 
        bug_str = getCommentForBug(bugID)
        full_str = full_str + '\n' + bug_str
    dumpContentIntoFile(full_str, out_file) 
    


if __name__=='__main__':
    bugID_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/dataset-bugreport-synthesis/ost-with-cves-only/OST_BUG_IDS_RES.txt' 
    output_comment_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/OSTK_CVE_BUG_REPORT_COMMENTS.txt'

    getBugComments(bugID_file, output_comment_file) 