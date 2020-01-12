'''
Akond Rahman 
Jan 12, 2020 
Prep for severity plots 
'''
import pandas as pd 
import numpy as np 
from collections import Counter 


def printTacticSeverityMapping(full_df): 
    cve_tactic_dict = {}
    unique_cves = np.unique( full_df['ID'].tolist() )
    for cve_ in unique_cves:
        cve_df       = full_df[full_df['ID']==cve_]
        cve_severity = cve_df['SEVERITY'].tolist()[0] 
        cve_tactics  = np.unique( cve_df['TACTIC'].tolist()  )
        cve_tactic_string = ''
        for tactic_ in cve_tactics:
            cve_tactic_string = cve_tactic_string + tactic_ + '+'
        # print(cve_, cve_severity, cve_tactic_string) 
        if cve_severity not in cve_tactic_dict:
            cve_tactic_dict[cve_severity] = [cve_tactic_string]  
        else:
            cve_tactic_dict[cve_severity] = cve_tactic_dict[cve_severity] +  [cve_tactic_string]                  
    for k_, v_ in cve_tactic_dict.items():
        if k_!='NOT_FOUND':
            tactic_counter_dict = dict(Counter(v_))
            total_tactic_count  = len(v_) 
            for key_, val_ in tactic_counter_dict.items():
                perc = round(float(val_)/float(total_tactic_count), 4)
                print('SEVERITY:{}, TOTAL_VULN_COUNT:{}, TACTC_COMBO:{}, TACTIC_COMBO_OCCURRENCE:{}, TACTIC_COMBO_PERCENTAGE:{}'.format(k_, len(v_), key_, val_, perc))
                print('-'*50)
            print('*'*100) 

def dumpSeverityPlottingData(full_df, ds_name):
    dump_file_name =  '../RESULTS/FSE2020/' + ds_name + '_PLOTDATA_SEVERITY.csv' 
    dumpList       = []
    severity_list  = np.unique( full_df['SEVERITY'].tolist() )
    for severity in severity_list:
        severity_df    = full_df[full_df['SEVERITY']==severity] 
        severity_cves  = np.unique( severity_df['ID'].tolist() )
        severity_tactics = np.unique( severity_df['TACTIC'].tolist()  )
        for tactic in severity_tactics: 
            tactic_severity_df   = severity_df[severity_df['TACTIC']==tactic] 
            tactic_severity_cves = np.unique( tactic_severity_df['ID'].tolist()  )
            cve_count            = len(tactic_severity_cves) 
            cve_prop             = float(cve_count)/float(len(severity_cves)) 
            tup2dump             = (severity, tactic, len(severity_cves) , cve_count, cve_prop) 
            dumpList.append( tup2dump )
    severity_df = pd.DataFrame(dumpList) 
    severity_df.to_csv(dump_file_name, header=['SEVERITY', 'STRATEGY', 'STARTEGY_ALL', 'COUNT_PER_STRATEGY', 'PERC_PER_STRATEGY' ], index=False, encoding='utf-8')    





if __name__=='__main__':
    ###NVD FILE
    FULL_NVD_FILE='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/FINAL_NVD_CVE_DATA_FULL.csv'

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



    full_df = pd.read_csv(DATASET_FILE) 
    DATASET_NAME = DATASET_FILE.split('/')[-1].split('-')[1]    

    NVD_DF = pd.read_csv(FULL_NVD_FILE)
    DATASET_DF  = pd.read_csv(DATASET_FILE) 
    merged_dataframe = mergeDataFrame(NVD_DF, DATASET_DF)
    # print(merged_dataframe.tail()) 


    ###RQ: What is the mapping of vulnerability severity and identified tactics? 
    printTacticSeverityMapping(merged_dataframe)   
    dumpSeverityPlottingData(merged_dataframe) 
