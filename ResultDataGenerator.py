'''
Akond Rahman 
Dec 30, 2019 
Monday 
Script to merge mapping data and nvd cve data 
'''
import pandas as pd 
import numpy as np 

def mergeDataFrame(nvd_df, mapping_df):
    mapping_df =  mapping_df['CVE'] = mapping_df['CVE'].str.upper() 
    merged_df  =  nvd_df.merge(mapping_df, left_on='ID', right_on='CVE')
    return merged_df 



if __name__=='__main__':
    FULL_NVD_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/FINAL_NVD_CVE_DATA_FULL.csv'
    NVD_DF = pd.read_csv(FULL_NVD_FILE)

    #MOZILLA MAPPING FILE
    FULL_MOZILLA_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-MOZILLA-MAPPING-FINAL.csv'
    MOZI_DF = pd.read_csv(FULL_MOZILLA_FILE) 
    
    merged_dataframe = mergeDataFrame(NVD_DF, MOZI_DF)
    print(merged_dataframe.tail()) 
    




