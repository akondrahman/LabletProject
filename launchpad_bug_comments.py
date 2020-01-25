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
import _pickle  as pickle 
import pandas as pd 
import time 
import  datetime 

def dumpContentIntoFile(strP, fileP):
  strP = strP.encode('utf-8')
  fileToWrite = open( fileP, 'w')
  fileToWrite.write(strP )
  fileToWrite.close()
  return str(os.stat(fileP).st_size)

def getCommentForBug(bugID):
    bugStr = ''
    bugTupleList = []
    csvStr = ''
    comment_index = 0 
    the_bug      = launchpad.bugs[bugID]  
    bug_comments = the_bug.messages
    bug_cve      = the_bug.title  
    bug_date     = the_bug.date_created
    bug_date_str = bug_date.strftime('%Y-%m-%dT%H-%M-%S') ## date with time 
    if len(bug_comments) > 0 : 
        # print 'Analyzing {} comments for bug#{}'.format(len(bug_comments), bugID)
        # print bugID 
        for comment_obj in bug_comments:
                str1_ = 'BUG_ID:' + str(bugID) + '\n' + '-'*10 + '\n'
                str2_ = 'CVE:' + bug_cve + '\n' + '-'*10 + '\n'
                comment_content = comment_obj.content 
                if comment_obj.subject is not None:
                    comment_subject = comment_obj.subject 
                    comment_owner   = comment_obj.owner 
                    comment_date    = comment_obj.date_created
                    com_date_str    = comment_date.strftime('%Y-%m-%dT%H-%M-%S') ## date with time 
                    str3_ = 'SUBJECT:' + comment_subject + '\n' + '-'*10 + '\n'                    
                    str4_ = 'COMMENT_INDEX:' + str(comment_index) + '\n' + comment_content + '\n' + '-'*10 + '\n'
                
                    bugStr = bugStr  + str1_ + str2_ + str3_ + str4_ + '\n' + '='*50
                    bugTupleList.append( (bugID, bug_cve, comment_index, comment_subject, comment_owner, bug_date_str, com_date_str) )
                    csvStr = csvStr + str(bugID) + ',' + bug_cve +  ',' + str(comment_index) + ',' + comment_subject + ',' + str(comment_owner ) + ',' + bug_date_str + ',' + com_date_str   + '\n'
                    comment_index += 1 
    # print bugStr
    return bugTupleList, csvStr

def getSoFar():
    with open('SO_FAR_UBUNTU.txt', 'rU') as f_:
         lines = f_.readlines()
    ID_list = [int(x_) for x_ in lines if x_!= '\n']
    unique_IDs = np.unique(ID_list)     
    return unique_IDs 

def getBugComments(file_name, out_file, out_csv_file, pkl_out_file): 
    all_details = []
    complete_csv_str = ''
    with open(file_name, 'rU') as f_:
         lines = f_.readlines()
    ID_list = [int(x_) for x_ in lines if x_!= '\n']
    unique_IDs = np.unique(ID_list) 
    # print 'Total bugs to analyze:', len( unique_IDs )
    # print '*'*50 
    for bugID in unique_IDs: 
            bug_details, csv_str  = getCommentForBug(bugID)
            complete_csv_str = complete_csv_str + csv_str 
            all_details = all_details + bug_details 
 
    all_df = pd.DataFrame(all_details)

    dumpContentIntoFile(complete_csv_str, out_csv_file)  
    

def getOpenstackEmails(df_, out_file):
    emailList = []
    bugIDs = np.unique( df_['BUGID'].tolist() )
    for bugID in bugIDs:
        bugDF          = df_[df_['BUGID']==bugID] 
        cve            = bugDF['CVE'].tolist()[0] 
        the_bug        = launchpad.bugs[bugID]  
        the_owner      = the_bug.owner
        owner_name     = the_owner.name 
        owner_emails   = the_owner.preferred_email_address_link
        owner_link     = 'https://launchpad.net/~' + owner_name 
        tuple_         = (bugID, cve, owner_name, owner_emails, owner_link)
        print(tuple_)   
        emailList.append( tuple_ )
    email_df = pd.DataFrame( emailList )
    email_df.to_csv(out_file, header=['BUGID', 'CVE' , 'NAME', 'EMAIL', 'URL' ], index=False, encoding='utf-8')






if __name__=='__main__':
    bugID_file          = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/dataset-bugreport-synthesis/ost-with-cves-only/OST_BUG_IDS_RES.txt' 
    output_comment_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/OSTK_CVE_BUG_REPORT_COMMENTS.txt'
    output_csv_file     = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/FULL_OST_CSV.csv'
    output_pkl_file     = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/FULL_OST_PKL.pkl'


    # bugID_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/dataset-bugreport-synthesis/ubuntu-with-cves-only/UBU_BUG_IDS_RES.txt' 
    # output_comment_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/UBUNTU_CVE_BUG_REPORT_COMMENTS.txt'
    # output_csv_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/UBUNTU_CVE_BUG_REPORT_COMMENT_MAP.csv'
    # output_pkl_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/UBUNTU_CVE_BUG_REPORT_COMMENT_ALL.PKL'

    # getBugComments(bugID_file, output_comment_file, output_csv_file, output_pkl_file)  

    '''
    TO GET EMAILS 
    '''
    # BUG_ID_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/SurveyWork/SurveyEmailList/LOCKED-OPENSTACK-MAPPING-FINAL.csv'
    # OUT_FILE    = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/SurveyWork/SurveyEmailList/OPENSTACK-EMAILS.csv'
    # BUG_ID_DF   = pd.read_csv(BUG_ID_FILE) 
    # getOpenstackEmails(BUG_ID_DF, OUT_FILE)
 