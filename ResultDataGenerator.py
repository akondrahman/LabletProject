'''
Akond Rahman 
Dec 30, 2019 
Monday 
Script to merge mapping data and nvd cve data 
'''
import pandas as pd 
import numpy as np 
from collections import Counter 
import csv 

def giveDeprecatedCWE():
    file_name = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/DEPRECATED-CWE.csv'
    deprecated_cwes = pd.read_csv(file_name)['CWE-ID'].tolist() 
    deprecated_list = ['CWE-' + str(x_) for x_ in deprecated_cwes] 
    return deprecated_list 


def mergeDataFrame(nvd_df, mapping_df):
    mapping_df['CVE'] =  mapping_df['CVE'].str.upper() 
    # print(mapping_df.head())
    merged_df  =  nvd_df.merge(mapping_df, left_on='ID', right_on='CVE')
    return merged_df 

def getCWENames():
    cwe_dict = {}
    research_cwes_file      = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/CWE_RESEARCH_CONCEPTS.csv'
    development_cwes_file   = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/CWE_DEVELOPMENT_CONCEPTS.csv'
    architectural_cwes_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/CWE_ARCHI_CONCEPTS.csv'

    with open(research_cwes_file) as file_:
        readCSV = csv.reader(file_, delimiter=',')
        for row_ in readCSV:
            if row_[0] not in cwe_dict:
                cweID = 'CWE-' + str(row_[0])
                cwe_dict[cweID]= row_[1]

    with open(development_cwes_file) as file_:
        readCSV = csv.reader(file_, delimiter=',')
        for row_ in readCSV:
            if row_[0] not in cwe_dict:
                cweID = 'CWE-' + str(row_[0])
                cwe_dict[cweID]= row_[1]

    with open(architectural_cwes_file) as file_:
        readCSV = csv.reader(file_, delimiter=',')
        for row_ in readCSV:
            if row_[0] not in cwe_dict:
                cweID = 'CWE-' + str(row_[0])
                cwe_dict[cweID]= row_[1]

    return cwe_dict


def printMappedCWEs(full_loaded_df):
    depreacted_list = giveDeprecatedCWE() 
    cwe_names_dict  = getCWENames()
    print('Count of CWEs with names:', len(cwe_names_dict))
    tactics = np.unique(full_loaded_df['TACTIC'].tolist())
    for tactic in tactics:
        tactic_df   = full_loaded_df[full_loaded_df['TACTIC']==tactic]
        tactic_cwes = tactic_df['CWE'].tolist() 
        tactic_cwes = [x_ for x_ in tactic_cwes if x_!='NVD-CWE-Other' and x_!='NVD-CWE-noinfo' and x_ not in depreacted_list]
        tactic_cwe_dist = dict(Counter(tactic_cwes)) 
        for k_, v_ in tactic_cwe_dist.items():
            weakness_name = 'UNASSIGNED' 
            if k_ in cwe_names_dict:
                weakness_name = cwe_names_dict[k_] 
            print('TACTIC:{}, WEAKNESS-ID:{}, WEAKNESS-NAME:{}, COUNT:{}'.format( tactic, k_, weakness_name ,  v_ ) )
            print('*'*25)
        print('='*50) 


if __name__=='__main__':
    # ###RQ: What source code weaknesses are exploited with the identified tactics ... will not be used in paper: printMappedCWEs(merged_dataframe) 

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
    DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-PHP-MAPPING-FINAL.csv'    



    NVD_DF = pd.read_csv(FULL_NVD_FILE)
    DATASET_DF  = pd.read_csv(DATASET_FILE) 
    merged_dataframe = mergeDataFrame(NVD_DF, DATASET_DF)
    # print(merged_dataframe.tail()) 


    '''
    THE FOLLOWIGN DATSETS WILL NOT BE USED IN PAPER 
    '''
    # #LIBREOFFICE  
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-LIBREOFFICE-MAPPING-FINAL.csv'    
    # #GENTOO   
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-GENTOO-MAPPING-FINAL.csv'    
    # #HTTPD     
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-HTTPD-MAPPING-FINAL.csv'    
    # #REDHAT  
    # DATASET_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-REDHAT-MAPPING-FINAL.csv'    