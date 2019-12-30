'''
Akond Rahman 
Dec 30, 2019 
Monday 
Script to merge mapping data and nvd cve data 
'''
import pandas as pd 
import numpy as np 
from collections import Counter 

def mergeDataFrame(nvd_df, mapping_df):
    mapping_df['CVE'] =  mapping_df['CVE'].str.upper() 
    # print(mapping_df.head())
    merged_df  =  nvd_df.merge(mapping_df, left_on='ID', right_on='CVE')
    return merged_df 

def printMappedCWEs(full_loaded_df):
    tactics = np.unique(full_loaded_df['TACTIC'].tolist())
    for tactic in tactics:
        tactic_df   = full_loaded_df[full_loaded_df['TACTIC']==tactic]
        tactic_cwes = tactic_df['CWE'].tolist() 
        tactic_cwes = [x_ for x_ in tactic_cwes if x_!='NVD-CWE-Other' ]
        tactic_cwe_dist = dict(Counter(tactic_cwes)) 
        for k_, v_ in tactic_cwe_dist.items():
            print('TACTIC:{}, CWE:{}, COUNT:{}', tactic, k_, v_ )) 
            print('*'*50)


if __name__=='__main__':
    FULL_NVD_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/FINAL_NVD_CVE_DATA_FULL.csv'
    NVD_DF = pd.read_csv(FULL_NVD_FILE)

    #MOZILLA MAPPING FILE
    FULL_MOZILLA_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-MOZILLA-MAPPING-FINAL.csv'
    MOZI_DF = pd.read_csv(FULL_MOZILLA_FILE) 
    
    merged_dataframe = mergeDataFrame(NVD_DF, MOZI_DF)
    # print(merged_dataframe.tail()) 

    ###RQ: What source code weaknesses are exploited with the identified tactics 
    printMappedCWEs(merged_dataframe) 

    




