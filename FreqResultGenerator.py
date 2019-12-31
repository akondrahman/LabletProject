'''
Answer to RQ2: Frequency 
Akond Rahman 
Dec 31, 2019 
Tuesday 
'''
import pandas as pd 
import numpy as np 

def mergeDataFrame(nvd_df, mapping_df):
    mapping_df['CVE'] =  mapping_df['CVE'].str.upper() 
    # print(mapping_df.head())
    merged_df  =  nvd_df.merge(mapping_df, left_on='ID', right_on='CVE')
    return merged_df 

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
        cve_tact_list = tact_df['CVE'].tolist()
        print('CVE_COUNT:{},TACTIC_NAME:{},CVE_PROP:{}'.format(len(unique_cves), tact, float(len(cve_tact_list))/float(len(unique_cves))))
        print('-'*25) 

if __name__=='__main__':

    ###NVD FILE
    FULL_NVD_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/FINAL_NVD_CVE_DATA_FULL.csv'
    ###TACTIC MAPPING FILE
    # #MOZILLA 
    DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-MOZILLA-MAPPING-FINAL.csv' 


    NVD_DF = pd.read_csv(FULL_NVD_FILE)
    DATASET_DF  = pd.read_csv(DATASET_FILE) 
    merged_dataframe = mergeDataFrame(NVD_DF, DATASET_DF)
    # print(merged_dataframe.tail())   
    ## Proportion of tactics 
    getTacticProportion(merged_dataframe)     
    ## Proportion of CVEs
    getCVEProportion(merged_dataframe)        