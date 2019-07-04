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
    cve_cnt = 0 
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
                                if (('id' in dict_) and ('summary' in dict_) and ('comments' in dict_)):
                                    bug_comments = dict_['comments']
                                    '''
                                    keys in comment dict: 
                                    [u'kind', u'canDelete', u'author', u'is_description', u'content', u'updates', u'published', u'id']
                                    '''
                                    if len(bug_comments) > 0 :
                                        for comment_ in bug_comments:
                                            # print comment_.keys()
                                            commentContent, commentDate, commentID, commentAuthor = comment_['content'] , comment_['published'], comment_['id'], comment_['author']['htmlLink']
                                            bugReportTitle, bugReportSummary, bugReportDate, bugReportID, bugReportAuthor = dict_['title'] , dict_['summary'] , dict_['published'], dict_['id'], dict_['author']['htmlLink']
                                            print 'Comment text:', commentContent
                                            print 'Comment date:', commentDate
                                            print 'Bug report title:', bugReportTitle
                                            print 'Bug report summary:', bugReportSummary
                                            print 'Bug report date:', bugReportDate
                                            print 'Bug report label:', bug_label 
                                            print 'Bug report ID:', bugReportID
                                            print '*'*10            
                                            full_data_list.append( (bugReportID, bugReportDate, bugReportTitle, bugReportSummary, bug_label, bugReportAuthor, commentID, commentContent, commentDate, commentAuthor)  )

                                    cve_cnt += 1
    print '='*50 
    print cve_cnt
    return full_data_list


if __name__=='__main__':
    bug_repor_dir     = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/chrome-bug-reports/bugs'
    dataset_csv_name  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/FULL_CHROME_CSV.csv'
    pickle_csv_name   = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/FULL_CHROME_PKL.pkl'

    all_json_files = findAllJSONFiles(bug_repor_dir)
    # print all_json_files
    full_list = getJSONData(all_json_files)
    full_df   = pd.DatFrame(full_list, header=['BUG_ID', 'BUG_DATE', 'BUG_TITLE', 'BUG_SUMMARY', 'BUG_CVE', 'BUG_AUTHOR', 'COMMENT_ID', 'COMMENT_TEXT', 'COMMENT_DATE', 'COMMENT_AUTHOR'])
    full_df.to_csv(dataset_csv_name,  index=False)
    pickle.dump(full_df, open(pickle_csv_name, 'wb'))       
