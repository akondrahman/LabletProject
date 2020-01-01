'''
Akond Rahman 
Jan 01, 2020 
Prepare Temporal Data 
'''
import numpy as np 
import pandas as pd 
import os 


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