'''
Answer to RQ2: Frequency 
Akond Rahman 
Dec 31, 2019 
Tuesday 
'''


if __name__=='__main__':

    ###NVD FILE
    FULL_NVD_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/FINAL_NVD_CVE_DATA_FULL.csv'
    ###TACTIC MAPPING FILE
    # #MOZILLA 
    DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-MOZILLA-MAPPING-FINAL.csv' 


    NVD_DF = pd.read_csv(FULL_NVD_FILE)
    DATASET_DF  = pd.read_csv(DATASET_FILE) 
    merged_dataframe = mergeDataFrame(NVD_DF, DATASET_DF)
    print(merged_dataframe.tail())        