'''
Answer to RQ2: Frequency 
Akond Rahman 
Dec 31, 2019 
Tuesday 
'''
import pandas as pd 
import numpy as np 
from collections import Counter 

def mergeDataFrame(nvd_df, mapping_df):
    mapping_df['CVE'] =  mapping_df['CVE'].str.upper() 
    # print(mapping_df.head())
    merged_df   =  nvd_df.merge(mapping_df, left_on='ID', right_on='CVE')
    filtered_df =  merged_df[merged_df['SEVERITY']!='NOT_FOUND']
    return filtered_df 

def getTacticProportion(full_df):
    all_tactics = full_df['TACTIC'].tolist() 
    unique_tactics = np.unique(all_tactics) 
    for tact in unique_tactics:
        tact_list = [z for z in all_tactics if z==tact] 
        print('ALL:{},TACTIC_NAME:{},TACTIC_COUNT:{},TACTIC_PROP:{}'.format(len(all_tactics), tact, len(tact_list), float(len(tact_list))/float(len(all_tactics))))
        print('-'*25) 


def getCVEProportion(full_df):
    all_tactics    = full_df['TACTIC'].tolist() 
    unique_tactics = np.unique(all_tactics) 
    unique_cves    = np.unique(full_df['CVE'].tolist())
    for tact in unique_tactics:
        tact_df       =  full_df[full_df['TACTIC']==tact]
        cve_tact_list =  np.unique(tact_df['CVE'].tolist() )
        print('CVE_COUNT:{},TACTIC_NAME:{},CVE_PROP:{}'.format(len(unique_cves), tact, float(len(cve_tact_list))/float(len(unique_cves))))
        print('-'*25) 


def splitOnCateg(df_, name_, categ_):
    payload_subcateg_list, diagnos_subcateg_list = [], [] 
    subcateg_list = []
    emptyDict = {} 
    bug_content_file, bug_content_txt = '', ''
    if 'MOZILLA' in name_:
        bug_content_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/MOZILLA-SUBCATEGORY-MAPPING.csv'
        payload_subcateg_list = ['MULTIMEDIA', 'SOURCECODE', 'SOURCECODE', 'SOURCECODE', 'SOURCECODE', 'SOURCECODE', 'SOURCECODE'] ### handle non-existent values manually for mozilla 
        diagnos_subcateg_list = ['SOURCECODE', 'SOURCECODE', 'SOURCECODE', 'SOURCECODE', 'SOURCECODE', 'SOURCECODE', 'SOURCECODE', 'SOURCECODE'] ### handle non-existent values manually for mozilla 
    elif 'CHROME' in name_:
        bug_content_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/CHROME1-SUBCATEGORY-MAPPING.csv'
        for _ in range(384):
            payload_subcateg_list.append( 'SOURCECODE' ) 
        for _ in range(8):
            payload_subcateg_list.append( 'MULTIMEDIA' ) 
        for _ in range(3):
            payload_subcateg_list.append( 'CERTIFICATE' ) 
        for _ in range(38):
            payload_subcateg_list.append( 'BINARY' ) 

        for _ in range(48):
            diagnos_subcateg_list.append( 'SOURCECODE' ) 
        for _ in range(8):
            diagnos_subcateg_list.append( 'BUILD' )
    elif 'ECLIPSE' in name_:
        bug_content_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/ECLIPSE-SUBCATEGORY-MAPPING.csv'

        for _ in range(16):
            payload_subcateg_list.append( 'SOURCECODE' ) 
        for _ in range(1):
            payload_subcateg_list.append( 'BINARY' ) 

        for _ in range(14):
            diagnos_subcateg_list.append( 'SOURCECODE' ) 
        for _ in range(1):
            diagnos_subcateg_list.append( 'BUILD' ) 

    elif 'MOBY' in name_:
        bug_content_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/MOBY-SUBCATEGORY-MAPPING.csv'

        for _ in range(1):
            payload_subcateg_list.append( 'SOURCECODE' ) 
        for _ in range(1):
            payload_subcateg_list.append( 'BINARY' ) 

        for _ in range(2):
            diagnos_subcateg_list.append( 'SOURCECODE' ) 
    elif 'OPENSTACK' in name_:
        bug_content_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/OPENSTACK-SUBCATEGORY-MAPPING.csv'

        for _ in range(3):
            payload_subcateg_list.append( 'SOURCECODE' ) 
        for _ in range(1):
            payload_subcateg_list.append( 'BINARY' ) 

        for _ in range(15):
            diagnos_subcateg_list.append( 'SOURCECODE' ) 
        for _ in range(4):
            diagnos_subcateg_list.append( 'BUILD' )
    elif 'PHP' in name_:
        bug_content_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/PHP-SUBCATEGORY-MAPPING.csv'

        for _ in range(56):
            payload_subcateg_list.append( 'SOURCECODE' ) 
        for _ in range(7):
            payload_subcateg_list.append( 'BINARY' ) 

        for _ in range(7):
            diagnos_subcateg_list.append( 'SOURCECODE' ) 
        for _ in range(3):
            diagnos_subcateg_list.append( 'BUILD' )    


    categ_df = df_[df_['TACTIC']==categ_]
    for bugID in np.unique( categ_df['BUGID'].tolist() ):
        SUBCATEG = ''
        bug_content_df   = pd.read_csv(bug_content_file) 
        content_ls       = bug_content_df[bug_content_df['BUGID']==bugID]['CONTENT'].tolist()
        if len(content_ls) > 0:
            bug_content_txt  = content_ls[0].lower()
            # print(bugID, bug_content_txt) 
            if categ_=='PAYLOAD':
                if ('pdf' in bug_content_txt and 'file' in bug_content_txt) or ('.exe' in bug_content_txt): 
                    SUBCATEG = 'BINARY'
                elif('cert' in bug_content_txt): 
                    SUBCATEG = 'CERTIFICATE' 
                elif(('mp3' in bug_content_txt) or ('mp4' in bug_content_txt) or ('audio' in bug_content_txt) or ('video' in bug_content_txt)) : 
                    SUBCATEG = 'MULTIMEDIA'
                else:
                    SUBCATEG = 'SOURCECODE'  
            else:
                if(('build' in bug_content_txt and 'log' in bug_content_txt) ) : 
                    SUBCATEG = 'BUILD'
                else:
                    SUBCATEG = 'SOURCECODE'              
            subcateg_list.append(SUBCATEG) 
        else:
            subcateg_list.append('NOTFOUND')
            if bugID not in emptyDict: 
                emptyDict[bugID] =''
    if categ_=='PAYLOAD':
        # print(len(payload_subcateg_list))
        subcateg_list = subcateg_list + payload_subcateg_list
    else:
        # print(len(diagnos_subcateg_list))
        subcateg_list = subcateg_list + diagnos_subcateg_list 
    if len(emptyDict) > 0 and ('MOZILLA' not in name_) and ('CHROME' not in name_) and ('ECLIPSE' not in name_) and ('MOBY' not in name_) and ('OPENSTACK' not in name_) and ('PHP' not in name_): ## mozilla, chrome, eclipse, moby, openstack, php  has already been handled so nothing to show 
        print('!'*10)
        print(categ_)
        print(emptyDict)
        print(len(emptyDict) )
        print('!'*10)
    subcateg_list = [x_ for x_ in subcateg_list if x_!='NOTFOUND' ]
    return subcateg_list
        



def printSubCateg(ls, name_):
    the_dict = dict(Counter(ls))
    total_ = len(ls)
    for k_, v_ in the_dict.items():
        prop = round( float(v_)/float(total_) , 5)
        print('CATEG:{}, COUNT:{}, SUB_CATEG:{}, SUB_CATEG_CNT:{} PROP:{}'.format(name_, total_, k_, v_, prop))
        print('*'*25)



def printSubCategFreq(full_df, name_):
    ls = splitOnCateg(full_df, name_, 'PAYLOAD')
    printSubCateg(ls, 'PAYLOAD')
    print('#'*50)
    ls = splitOnCateg(full_df, name_, 'DIAGNOSTICS')
    printSubCateg(ls, 'DIAGNOSTICS')
    print('#'*50)


def printMultiTacticFreq(df_, name):
    cve_tactic_ls = [] 
    unique_cves = np.unique( df_['ID'].tolist() )
    for cve_ in unique_cves:
        cve_df       = df_[df_['ID']==cve_]
        cve_tactics  = np.unique( cve_df['TACTIC'].tolist()  )
        cve_tactic_string = ''
        for tactic_ in cve_tactics:
            cve_tactic_string = cve_tactic_string + tactic_ + '+'     
        cve_tactic_ls.append(cve_tactic_string)            
    tactic_counter_dict = dict(Counter(cve_tactic_ls))
    total_cve_count     = len(cve_tactic_ls)  
    for key_, val_ in tactic_counter_dict.items():
        perc = round(float(val_)/float(total_cve_count), 5)
        print('TOTAL_VULN_COUNT:{}, TACTC_COMBO:{}, TACTIC_COMBO_OCCURRENCE:{}, TACTIC_COMBO_PERCENTAGE:{}'.format(total_cve_count, key_, val_, perc))
        print('-'*50)
    print('*'*100)     

def makeMonth(time_single_val):
    if 'T' in time_single_val:
        date_     = time_single_val.split('T')[0] 
    else:
        date_     = time_single_val
    date_list = date_.split('-')
    month = date_list[0] + '-' + date_list[1] 
    return month 

def printBugReportSummary(full_df): 
    all_bugID_list =  np.unique( full_df['BUGID'].tolist()  ) 
    unique_cves = np.unique( full_df['ID'].tolist() )
    full_df['MONTH'] = full_df['TIMESTAMP'].apply(makeMonth)
    all_months =  np.unique( full_df['MONTH'].tolist() ) 

    print('TOTAL BUGS:', len(all_bugID_list))
    print('='*100)
    print('TOTAL CVEs:', len(unique_cves))
    print('='*100)
    print('TIME RANGE:{}---{}'.format( min(all_months) , max(all_months) ) )
    print('='*100)    

if __name__=='__main__':
    '''
    THE FOLLWOING WILL BE EXCLUDED FROM PAPER 
    '''
    # #LIBREOFFICE  
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-LIBREOFFICE-MAPPING-FINAL.csv'    
    # #GENTOO   
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-GENTOO-MAPPING-FINAL.csv'
    # #HTTPD     
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-HTTPD-MAPPING-FINAL.csv'
    # #REDHAT  
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-REDHAT-MAPPING-FINAL.csv'
    '''
    '''

    ###NVD FILE
    FULL_NVD_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/FINAL_NVD_CVE_DATA_FULL.csv'
    ###TACTIC MAPPING FILE

    # # #CHROME  
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-CHROME-MAPPING-FINAL.csv'
    # #ECLIPSE  
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-ECLIPSE-MAPPING-FINAL.csv'
    # #MOBY    
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-MOBY-MAPPING-FINAL.csv'
    # # #MOZILLA 
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-MOZILLA-MAPPING-FINAL.csv' 
    #OPENSTACK 
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-OPENSTACK-MAPPING-FINAL.csv'    
    # #PHP 
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-PHP-MAPPING-FINAL.csv'    



    NVD_DF       = pd.read_csv(FULL_NVD_FILE)
    DATASET_DF   = pd.read_csv(DATASET_FILE) 
    DATASET_NAME = DATASET_FILE.split('/')[-1]
    merged_dataframe = mergeDataFrame(NVD_DF, DATASET_DF)
    # print(merged_dataframe.tail())   
    print('ANALYZING:', DATASET_NAME)
    print('='*100)
    ## Proportion of tactics 
    # getTacticProportion(merged_dataframe)     
    # print('='*100)
    
    # ## Proportion of CVEs
    # getCVEProportion(merged_dataframe) 
    
    ## Get Sub category proportion 
    printSubCategFreq(merged_dataframe, DATASET_NAME)   
    
    ## Proportion of co-occurring tactics 
    # printMultiTacticFreq(merged_dataframe, DATASET_NAME)    

    ## Bug Report Summary used in RQ2 
    # printBugReportSummary(merged_dataframe)          