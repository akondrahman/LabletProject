'''
Akond Rahman 
July 04, 2019 
Mine chrome bugs 
'''
import os 
import numpy as np 
import pandas as pd 
import json
from ijson import items
import shutil
import cPickle as pickle 
import time
import datetime

def findAllJSONFiles(dir_name):
    all_json_files = []
    for root_, dirs, files_ in os.walk(dir_name):
       for file_ in files_:
           if file_.endswith('.json')  :  # checkign extension requires dot 
              all_json_files.append(os.path.join(root_, file_)) 
    return all_json_files

def getJSONData(file_list):
    full_data_list = []
    '''
    keys in bug report dict: 
    [u'owner_modified', u'cc', u'labels', u'id', u'component_modified', u'projectId', u'comments', 
     u'state', u'etag', u'closed', u'status', u'updated', u'stars', u'canComment', u'status_modified', 
     u'kind', u'author', u'summary', u'components', u'published', u'title', u'starred', u'canEdit']
    '''
    cve_cnt , cve_comment_cnt , cve_comment_compo_cnt = 0, 0, 0 
    for file_ in file_list:
        if os.path.exists(file_):
            with open(file_, 'rU') as json_file: 
                dict_list = json.load(json_file)
                # print dict_list
                for dict_ in dict_list:
                    if 'labels' in dict_:
                        bug_labels = dict_['labels']
                        for bug_label in bug_labels:
                            if 'cve' in bug_label.lower():
                                if (('id' in dict_) and ('summary' in dict_) and ('comments' in dict_) and ('components' in dict_)):
                                    bug_comments   = dict_['comments']
                                    bug_components = dict_['components']
                                    '''
                                    keys in comment dict: 
                                    [u'kind', u'canDelete', u'author', u'is_description', u'content', u'updates', u'published', u'id']
                                    '''
                                    if len(bug_comments) > 0 :
                                        cve_comment_cnt += 1
                                        for comment_ in bug_comments:
                                            if len(bug_components) > 0:
                                                cve_comment_compo_cnt += 1 
                                                for bug_compo in bug_components:
                                                    # print comment_.keys()
                                                    commentContent, commentDate, commentID, commentAuthor = comment_['content'] , comment_['published'], comment_['id'], comment_['author']['htmlLink']
                                                    bugReportTitle, bugReportSummary, bugReportDate, bugReportID, bugReportAuthor = dict_['title'] , dict_['summary'] , dict_['published'], dict_['id'], dict_['author']['htmlLink']
                                                    commentContent = commentContent.encode("utf-8")
                                                    print 'Comment text:', commentContent
                                                    print 'Comment date:', commentDate
                                                    print 'Bug report title:', bugReportTitle
                                                    print 'Bug report summary:', bugReportSummary
                                                    print 'Bug report date:', bugReportDate
                                                    print 'Bug report label:', bug_label 
                                                    print 'Bug report component:', bug_compo
                                                    print 'Bug report ID:', bugReportID
                                                    print '*'*10            
                                                    full_data_list.append( (bugReportID, bugReportDate, bugReportTitle, bugReportSummary, bug_label, bugReportAuthor, commentID, commentContent, commentDate, commentAuthor, bug_compo)  )

                                    cve_cnt += 1
    print '='*50 
    print 'Total bug reports:', len(dict_list) 
    # print 'Bug reports with CVEs:', cve_cnt
    # print 'Bug reports with CVEs and non-zero comment:', cve_comment_cnt
    # print 'Bug reports with CVEs and non-zero comment and non zero components:', cve_comment_compo_cnt
    return full_data_list

def giveTimeStamp():
  tsObj = time.time()
  strToret = datetime.datetime.fromtimestamp(tsObj).strftime('%Y-%m-%d %H:%M:%S')
  return strToret


def getBugCount(file_name):
    print file_name
    ls_ = pickle.load(open(file_name, 'rb') )
    df_ = pd.DataFrame(ls_, columns=['BUG_ID', 'BUG_DATE', 'BUG_TITLE', 'BUG_SUMMARY', 'BUG_CVE', 'BUG_AUTHOR', 'COMMENT_ID', 'COMMENT_TEXT', 'COMMENT_DATE', 'COMMENT_AUTHOR', 'BUG_COMPO'])
    print len(np.unique( df_['BUG_ID'] ) )
    print '*'*25

def getCVE(bug_txt):
    cve_val = 'NOT_FOUND'
    splitted_txt = bug_txt.split(' ')
    for txt_ in splitted_txt:
        if (('cve' in bug_txt) and ('-' in bug_txt) ):
            cve_val = txt_ 
    return cve_val
        

def getExtraChromeBugs():
    all_chrome_bugs = []
    extra_bug_file_input = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/UNPROCESSED_CHROME_2016_2019/ALL_UNPROCESSED_2016_2019.csv'
    csv_out_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/UNPROCESSED_CHROME_2016_2019/ALL_CHROME_PROCESSED_2016_2019.csv'
    extra_bug_df = pd.read_csv(extra_bug_file_input) 

    unique_bugs = np.unique(extra_bug_df['ID'].tolist())
    for bugID in unique_bugs:
        the_cve = 'NOT_FOUND'
        bug_df = extra_bug_df[extra_bug_df['ID']==bugID]
        bug_summary = bug_df['Summary'].tolist()[0].tolower() 	
        bug_labels  = bug_df['AllLabels'].tolist()[0].tolower()
        if 'cve' in bug_summary:
            the_cve = getCVE(bug_summary)
        elif 'cve' in bug_labels:
            the_cve = getCVE(bug_labels)  	
        bug_link = 'https://bugs.chromium.org/p/chromium/issues/detail?id=' + str(bugID)
        bug_component = bug_df['Component'].tolist()[0].tolower() 	
        bug_status = bug_df['Status'].tolist()[0].tolower() 	
        bug_owber = bug_df['Owner'].tolist()[0].tolower() 	
        bug_OS = bug_df['OS'].tolist()[0].tolower() 	
        bug_date = bug_df['Modified'].tolist()[0].tolower() 	
        
        dat_ = (bugID, bug_summary, bug_component, bug_status, bug_OS, bug_date, bug_link)
        all_chrome_bugs.append(dat_) 
    full_df = pd.DataFrame(all_chrome_bugs) 
    full_df.to_csv(csv_out_file, header=['BUG_ID', 'BUG_SUMMARY', 'BUG_COMPONENT', 'BUG_STATUS', 'BUG_OS', 'BUG_DATE', 'BUG_LINK' ], index=False, encoding='utf-8')    


 
if __name__=='__main__':
    t1 = time.time()
    print 'Started at:', giveTimeStamp()
    print '*'*100

    bug_repor_dir     = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/chrome-bug-reports/bugs'
    dataset_csv_name  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/FULL_CHROME_CSV.csv'
    pickle_csv_name   = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/StrategyMining/LOCKED_DATASETS/FULL_CHROME_PKL.pkl'

    # all_json_files = findAllJSONFiles(bug_repor_dir)
    # # print all_json_files
    # full_list = getJSONData(all_json_files)
    # full_df   = pd.DataFrame(full_list)
    # full_df.to_csv(dataset_csv_name, header=['BUG_ID', 'BUG_DATE', 'BUG_TITLE', 'BUG_SUMMARY', 'BUG_CVE', 'BUG_AUTHOR', 'COMMENT_ID', 'COMMENT_TEXT', 'COMMENT_DATE', 'COMMENT_AUTHOR', 'BUG_COMPO'], index=False)
    # pickle.dump(full_df, open(pickle_csv_name, 'wb'))       

    # getBugCount(pickle_csv_name) 

    getExtraChromeBugs()

    print '*'*100
    print 'Ended at:', giveTimeStamp()
    print '*'*100
    t2 = time.time()
    time_diff = round( (t2 - t1 ) / 60, 5) 
    print "Duration: {} minutes".format(time_diff)
    print '*'*100  
