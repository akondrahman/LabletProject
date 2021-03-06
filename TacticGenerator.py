'''
From manual analysis finalize tactic to CVE mapping
Akond Rahman 
Dec 29, 2019 
Sunday 
'''
import pandas as pd 
import numpy as np 
import math
import datetime
import _pickle as pickle 

'''
For Openstack 
'''
from launchpadlib.launchpad import Launchpad 
launchpad = Launchpad.login_anonymously('just testing', 'production') 

def renameStrategy(name_):
    dict_ = {'SourceCodeExploration/SourceCodeWeakness': 'DIAGNOSTICS', 
             'PayloadInjection':'PAYLOAD', 
             'SystemUsage':'EXECUTION' , 
             'SystemConfigurationTuning':'TUNING' , 
             'UX':'EXECUTION' ,
             'Diagnostics':'DIAGNOSTICS', 
             'CommandInput':'PAYLOAD' , 
             'Outdated-Dependnecy':'DIAGNOSTICS', 
             'PayloadManipulation':'PAYLOAD', 
             'ScriptInjection':'PAYLOAD' , 
             'SecurityScanningTool':'DIAGNOSTICS', 
             'SystemConfiguration':'TUNING',
             'SystemConfigurationFlag':'TUNING' , 
             'SystemConfigurationInput':'TUNING' , 
             'Command exploration':'PAYLOAD', 
             'Outdated dependency':'DIAGNOSTICS', 
             'Source code analysis':'DIAGNOSTICS', 
             'Source code exploration':'DIAGNOSTICS', 
             'System Configuration ':'TUNING', 
             'System Configuration Flag':'TUNING' , 
             'SystemConfiguration ':'TUNING' , 
             'SytemUsage':'EXECUTION', 
             'HardwareUsage':'EXECUTION', 
             'PaylaodInjection':'PAYLOAD' , 
             'SourcecodeWeakness':'DIAGNOSTICS', 
             'OutdatedDependency':'DIAGNOSTICS', 
             'SourceCodeExploration':'DIAGNOSTICS', 
             'Fuzzer':'PAYLOAD', 
             'Sourcecode':'DIAGNOSTICS', 
             'SourceCodeWeakness':'DIAGNOSTICS', 
             'SourceCode':'DIAGNOSTICS', 
             'InputManipulation':'PAYLOAD', 
             'ConfigurationManipulation':'TUNING'
            }
    return dict_[name_] 
    

def finalizeDataFrame(df_param, old_flag = True ):
    BUG_ID_LIST = np.unique(df_param['BUGID'].tolist()) 
    BUG_ID_LIST = [int(x_) for x_ in BUG_ID_LIST if ( math.isnan(float(x_)) == False ) ]
    complete_list = []
    for bugID in BUG_ID_LIST:
        final_strategy_ls = []
        # print(bugID)
        cve = df_param[df_param['BUGID']==bugID]['CVE'].tolist()[0]
        '''
        check if old categorization exist 
        '''
        if old_flag:
            old_strategy = df_param[df_param['BUGID']==bugID]['STRATEGY'].tolist()[0]
            if isinstance(old_strategy, str): 
               if 'SourceCodeExploration/SourceCodeWeakness' in old_strategy:
                   final_strategy_ls.append( renameStrategy(old_strategy) )
        
        new_strategy = df_param[df_param['BUGID']==bugID]['AKOND'].tolist()[0]
        date_time = df_param[df_param['BUGID']==bugID]['TIMESTAMP'].tolist()[0]

        

        # print(new_strategy )
        if isinstance(new_strategy, str): 
            if '+' in new_strategy:
                new_strategy_ls = new_strategy.split('+') 
                # print(new_strategy_ls)
                for name in new_strategy_ls:
                    if ' ' not in name:
                        final_strategy_ls.append(  renameStrategy(name) )
            else:
                if ' ' not in new_strategy:
                    final_strategy_ls.append(  renameStrategy(new_strategy)  )
        # print(bugID, cve, final_strategy_ls) 
        for tactic in final_strategy_ls:
            complete_list.append((bugID, date_time, cve, tactic))
    final_df = pd.DataFrame(complete_list)
    return final_df


def getOpenstackBugTime(bugID):
    the_bug      = launchpad.bugs[bugID]  
    bug_date     = the_bug.date_created
    return bug_date 


def getBugDetails(dic, ID): 
    cve, date_ = 'NOT_FOUND', 'NOT_FOUND' 
    cve_option_1, cve_option_2 = '', ''
    if ID in dic: 
        if (len(dic[ID]) > 0):
            if len(dic[ID][0]) > 0:
               cve_option_1 = dic[ID][0][0].lower()
            cve_option_2 = dic[ID][9].split(' ')[0].lower() 
            if 'cve' in cve_option_1:
               cve = cve_option_1
            elif 'cve' in cve_option_2:
               cve = cve_option_2
            date_ = dic[ID][3]
    return cve, date_ 

def finalizeRedHatDataFrame(df_param, pkl_ ): 
    BUG_ID_LIST = np.unique(df_param['BUGID'].tolist()) 
    BUG_ID_LIST = [int(x_) for x_ in BUG_ID_LIST if ( math.isnan(float(x_)) == False ) ]
    complete_list = []
    WHOLE_BUG_DICT = pkl_
    for bugID in BUG_ID_LIST:
        final_strategy_ls = []
        # print(bugID)
        cve , date_time = getBugDetails(WHOLE_BUG_DICT, bugID )  
        old_strategy = df_param[df_param['BUGID']==bugID]['STRATEGY'].tolist()[0]
        if isinstance(old_strategy, str): 
               if 'SourceCodeExploration/SourceCodeWeakness' in old_strategy:
                   final_strategy_ls.append( renameStrategy(old_strategy) )
        
        new_strategy = df_param[df_param['BUGID']==bugID]['AKOND'].tolist()[0]
        # print(new_strategy )
        if isinstance(new_strategy, str): 
            if '+' in new_strategy:
                new_strategy_ls = new_strategy.split('+') 
                # print(new_strategy_ls)
                for name in new_strategy_ls:
                    if ' ' not in name:
                        final_strategy_ls.append(  renameStrategy(name) )
            else:
                if ' ' not in new_strategy:
                    final_strategy_ls.append(  renameStrategy(new_strategy)  )
        # print(bugID, cve, final_strategy_ls) 
        for tactic in final_strategy_ls:
            complete_list.append((bugID, date_time, cve, tactic))
    final_df = pd.DataFrame(complete_list)
    return final_df

def finalizeOpenstackDataFrame(df_param ):
    BUGLINKS = df_param['Link'].tolist()
    complete_list = []
    for bug_ in BUGLINKS:
        # print(bug_)
        if isinstance(bug_, str): 
            bugID = bug_.split('/')[-1] 
            final_strategy_ls = []
            # print(bugID)
            cve = df_param[df_param['Link']==bug_]['CVE'].tolist()[0]
            
            new_strategy = df_param[df_param['Link']==bug_]['Strategy'].tolist()[0]
            # print(new_strategy )
            if isinstance(new_strategy, str): 
                if '+' in new_strategy:
                    new_strategy_ls = new_strategy.split('+') 
                    # print(new_strategy_ls)
                    for name in new_strategy_ls:
                        if ' ' not in name:
                            final_strategy_ls.append(  renameStrategy(name) )
                else:
                        final_strategy_ls.append(  renameStrategy(new_strategy)  )

            date_time = getOpenstackBugTime(bugID) 
            date_time_str = date_time.strftime('%Y-%m-%dT%H-%M-%S')

            # date_time_str = '2019-12-31T12:00:00'

            print(bugID, date_time_str , cve, final_strategy_ls) 
            for tactic in final_strategy_ls:
                complete_list.append((bugID, date_time_str, cve, tactic))
    final_df = pd.DataFrame(complete_list)
    return final_df


if __name__=='__main__':
    # #### MOZILLA 
    # DS_NAME='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-MOZILLA-MAPPING-SEMIFINAL.csv'
    # OUT_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-MOZILLA-MAPPING-FINAL.csv'
    # DS_FRAME = pd.read_csv(DS_NAME) 
    # final_df =finalizeDataFrame(DS_FRAME)


    #### OPENSTACK 
    DS_NAME='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-OPENSTACK-MAPPING-SEMIFINAL.csv'
    OUT_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-OPENSTACK-MAPPING-FINAL.csv'
    DS_FRAME = pd.read_csv(DS_NAME) 
    final_df =finalizeOpenstackDataFrame(DS_FRAME)

    #### CHROME 
    # DS_NAME='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-CHROME-MAPPING-SEMIFINAL.csv'
    # OUT_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-CHROME-MAPPING-FINAL.csv'
    # DS_FRAME = pd.read_csv(DS_NAME) 
    # final_df =finalizeDataFrame(DS_FRAME)

    # #### ECLIPSE 
    # DS_NAME='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-ECLIPSE-MAPPING-SEMIFINAL.csv'
    # OUT_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-ECLIPSE-MAPPING-FINAL.csv'
    # DS_FRAME = pd.read_csv(DS_NAME) 
    # final_df =finalizeDataFrame(DS_FRAME)

    # #### HTTPD  
    # DS_NAME='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-HTTPD-MAPPING-SEMIFINAL.csv'
    # OUT_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-HTTPD-MAPPING-FINAL.csv'
    # DS_FRAME = pd.read_csv(DS_NAME) 
    # final_df =finalizeDataFrame(DS_FRAME)

    #### MOBY  
    # DS_NAME='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-MOBY-MAPPING-SEMIFINAL.csv'
    # OUT_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-MOBY-MAPPING-FINAL.csv'
    # DS_FRAME = pd.read_csv(DS_NAME) 
    # final_df =finalizeDataFrame(DS_FRAME)


    # #### GENTOO
    # DS_NAME='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-GENTOO-MAPPING-SEMIFINAL.csv'
    # OUT_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-GENTOO-MAPPING-FINAL.csv'
    # DS_FRAME = pd.read_csv(DS_NAME) 
    # final_df =finalizeDataFrame(DS_FRAME)

    # #### REDHAT
    # DS_NAME  ='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-REDHAT-MAPPING-SEMIFINAL.csv'
    # PKL_FILE ='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/FINAL_REDHAT_BUG_DETAILS.PKL'
    # OUT_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-REDHAT-MAPPING-FINAL.csv'
    # DS_FRAME = pd.read_csv(DS_NAME) 
    # PKL_DAT  = pickle.load(open(PKL_FILE, 'rb'), encoding="latin1")
    # final_df =finalizeRedHatDataFrame(DS_FRAME, PKL_DAT)


    #### LIBREOFFICE
    # DS_NAME  ='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-LIBREOFFICE-MAPPING-SEMIFINAL.csv'
    # PKL_FILE ='/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/RAW/ALL_LIBREOFFICE_BUG_DETAILS.PKL'
    # OUT_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/LOCKED_DATASETS/TACTIC-MAPPING/LOCKED-LIBREOFFICE-MAPPING-FINAL.csv'
    # DS_FRAME = pd.read_csv(DS_NAME) 
    # PKL_DAT  = pickle.load(open(PKL_FILE, 'rb'), encoding="latin1")
    # final_df =finalizeRedHatDataFrame(DS_FRAME, PKL_DAT)

    final_df.to_csv(OUT_FILE, header=['BUGID', 'TIMESTAMP', 'CVE', 'TACTIC' ], index=False, encoding='utf-8')