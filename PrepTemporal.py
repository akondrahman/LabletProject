'''
Akond Rahman 
Jan 01, 2020 
Prepare Temporal Data 
'''
import numpy as np 
import pandas as pd 
import os 
import datetime 

def makeYear(time_single_val):
    if 'T' in time_single_val:
        date_     = time_single_val.split('T')[0] 
    else:
        date_     = time_single_val
    date_list = date_.split('-')
    year      = date_list[0] 
    return year    


def dumpContentIntoFile(strP, fileP):
    fileToWrite = open( fileP, 'w')
    fileToWrite.write(strP)
    fileToWrite.close()
    return str(os.stat(fileP).st_size)

def makeMonth(time_single_val):
    if 'T' in time_single_val:
        date_     = time_single_val.split('T')[0] 
    else:
        date_     = time_single_val
    date_list = date_.split('-')
    month = date_list[0] + '-' + date_list[1] 
    return month 


def makeYearWiseDataset(df_param, ds_name):
    str_builder  = ''
    df_param['YEAR'] = df_param['TIMESTAMP'].apply(makeYear)
    all_years =  np.unique( df_param['YEAR'].tolist() ) 
    for per_year in all_years: 
            per_year_df      = df_param[df_param['YEAR']==per_year]
            per_year_tactics = per_year_df['TACTIC'].tolist() 
            per_year_tot_tactic_cnt       = len(per_year_tactics)
            for tac in np.unique(per_year_tactics): 
                per_yr_tactic_df = per_year_df[per_year_df['TACTIC']==tac]
                per_yr_indi_tac  =  per_yr_tactic_df['TACTIC'].tolist() 
                indi_tac_cnt     = len(per_yr_indi_tac) 
                tac_perc         = round(float(indi_tac_cnt)/float(per_year_tot_tactic_cnt) , 5) * 100 
                str_builder = str_builder + per_year + ',' + tac + ',' + str(tac_perc) + '\n' 
    dump_file_name =  '../RESULTS/FSE2020/' + ds_name + '_YEAR_TEMPORAL.csv' 
    str_builder = 'YEAR,TACTIC_NAME,TACTIC_PERC' + '\n' + str_builder
    dumpContentIntoFile(str_builder, dump_file_name)
     
def getChromeDate(df_):
    complete_list = []
    date_file='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/chromium-issues-for-dates.csv'
    date_df=pd.read_csv(date_file)
    all_bugs = np.unique( df_['BUGID'].tolist() )
    for bugID in all_bugs:
        cve     = df_[df_['BUGID']==bugID]['CVE'].tolist()[0] 
        existing_ts = df_[df_['BUGID']==bugID]['TIMESTAMP'].tolist()[0] 
        tactic  = df_[df_['BUGID']==bugID]['TACTIC'].tolist()[0] 
        if '2019-12-31T' in existing_ts:
            time_ls = date_df[date_df['ID']==bugID]['OpenedTimestamp'].tolist() 
            if(len(time_ls) > 0):
                timesta =  time_ls[0]
            else: 
                timesta = 0000000000        
                print(bugID) 
            date_time_str =  datetime.datetime.fromtimestamp(  timesta ).strftime('%Y-%m-%dT%H:%M:%S')
        else:        
            date_time_str =  existing_ts 

        complete_list.append((bugID, date_time_str, cve, tactic))       
    final_df = pd.DataFrame(complete_list)
    final_df.to_csv('CHROME_WITH_TIMESTAMP.csv', header=['BUGID', 'TIMESTAMP', 'CVE', 'TACTIC' ], index=False, encoding='utf-8')    


def makeMonthWiseDataset(df_param, ds_name):
    str_builder  = ''
    df_param['MONTH'] = df_param['TIMESTAMP'].apply(makeMonth)
    all_months =  np.unique( df_param['MONTH'].tolist() ) 
    for per_mon in all_months: 
            per_mon_df      = df_param[df_param['MONTH']==per_mon ]
            per_mon_tactics = per_mon_df['TACTIC'].tolist() 
            per_mon_tot_tactic_cnt       = len(per_mon_tactics)
            for tac in np.unique(per_mon_tactics): 
                per_mon_tactic_df = per_mon_df[per_mon_df['TACTIC']==tac]
                per_mon_indi_tac  =  per_mon_tactic_df['TACTIC'].tolist() 
                indi_tac_cnt     = len(per_mon_indi_tac) 
                tac_perc         = round(float(indi_tac_cnt)/float(per_mon_tot_tactic_cnt) , 5) * 100 
                str_builder = str_builder + per_mon + ',' + tac + ',' + str(tac_perc) + '\n' 
    dump_file_name =  '../RESULTS/FSE2020/' + ds_name + '_MONTH_TEMPORAL.csv' 
    str_builder = 'MONTH,TACTIC_NAME,TACTIC_PERC' + '\n' + str_builder
    dumpContentIntoFile(str_builder, dump_file_name)


if __name__=='__main__':
    # # #CHROME  
    DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-CHROME-MAPPING-FINAL.csv'
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


    full_df = pd.read_csv(DATASET_FILE) 
    DATASET_NAME = DATASET_FILE.split('/')[-1].split('-')[1]
    makeYearWiseDataset(full_df, DATASET_NAME)    
    makeMonthWiseDataset(full_df, DATASET_NAME)        


