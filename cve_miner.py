'''
Akond Rahman 
July 05, 2019 
Get CVE details 
'''
import os
from os.path import isfile, join
import zipfile
import json
from ijson import items
import shutil
import pandas as pd 
import cPickle as pickle 


def findAllZipFiles(dir_name):
    all_json_files = []
    for root_, dirs, files_ in os.walk(dir_name):
       for file_ in files_:
           if file_.endswith('.zip')  :  # checkign extension requires dot 
            #   print 'Processing:', file_
              zip_file = os.path.join(root_, file_)
              zip_ref = zipfile.ZipFile(zip_file, 'r')
              zip_ref.extractall(dir_name) 
              zip_ref.close()        
    for root_, dirs, files_ in os.walk(dir_name):
       for file_ in files_:
           if file_.endswith('.json')  :
              all_json_files.append(os.path.join(root_, file_))            
    return all_json_files

def exploreImpactDict(d_, k_ = 'baseMetricV3'):
    cve_complex, cve_conf, cve_inte, cve_ava, cve_sco, cve_sev = 'NOT_FOUND', 'NOT_FOUND', 'NOT_FOUND', 'NOT_FOUND', 'NOT_FOUND', 'NOT_FOUND'
    cve_exp_score, cve_impact_score = 'NOT_FOUND', 'NOT_FOUND'
    if k_ in d_:
        cve_exp_score, cve_impact_score = d_[k_]['exploitabilityScore'], d_[k_]['impactScore']
        if 'cvssV3' in d_[k_]: 
            cve_complex, cve_conf, cve_inte, cve_ava, cve_sco, cve_sev = d_[k_]['cvssV3']['attackComplexity'], d_[k_]['cvssV3']['confidentialityImpact'], d_[k_]['cvssV3']['integrityImpact'], d_[k_]['cvssV3']['availabilityImpact'], d_[k_]['cvssV3']['baseScore'], d_[k_]['cvssV3']['baseSeverity']
    return cve_exp_score, cve_impact_score, cve_complex, cve_conf, cve_inte, cve_ava, cve_sco, cve_sev

def mineCVEs(file_list, final_output_file):
    all_cve_data_list = []
    for cve_file in file_list:
        if os.path.exists(cve_file): 
            print ' Mining: ', cve_file
            with open(cve_file, 'rU') as json_file: 
                dict_ = json.load(json_file)
                # print dict_.keys() -> [u'CVE_data_timestamp', u'CVE_data_version', u'CVE_Items', u'CVE_data_format', u'CVE_data_numberOfCVEs', u'CVE_data_type']
                if 'CVE_Items' in dict_:
                    cve_dic_lis = dict_['CVE_Items'] 
                    for cve_dic in cve_dic_lis:
                        cve_id, cve_assigner, cve_desc_str, cve_cwe = 'NOT_FOUND', 'NOT_FOUND', 'NOT_FOUND', 'NOT_FOUND'
                        cve_vendor_name, cve_product_name, cve_desc_str, cve_cwe = 'NOT_FOUND', 'NOT_FOUND', 'NOT_FOUND', 'NOT_FOUND'
                        # print cve_dic.keys() -> [u'impact', u'lastModifiedDate', u'publishedDate', u'cve', u'configurations']
                        cve_impact_dict  = cve_dic['impact']
                        cve_date         = cve_dic['publishedDate']
                        cve_details_dict = cve_dic['cve']
                        # print 'impact->',  cve_impact_dict.keys()  -> # [u'baseMetricV3', u'baseMetricV2']
                        # print 'details->', cve_details.keys() # [u'description', u'data_type', u'affects', u'data_format', u'problemtype', u'data_version', u'references', u'CVE_data_meta']
                        cve_exp_score, cve_impact_score, cve_complex, cve_conf, cve_inte, cve_ava, cve_sco, cve_sev = exploreImpactDict(cve_impact_dict)
                        
                        if 'CVE_data_meta' in cve_details_dict:
                            cve_id, cve_assigner = cve_details_dict['CVE_data_meta']['ID'], cve_details_dict['CVE_data_meta']['ASSIGNER']
                        if 'description' in cve_details_dict:
                            cve_desc_dict = cve_details_dict['description']
                            if 'description_data' in cve_desc_dict:
                                cve_desc_dict_list = cve_desc_dict['description_data']
                                for desc_ in cve_desc_dict_list:
                                    if 'value' in desc_:
                                        cve_desc_str = desc_['value']
                        if 'problemtype' in cve_details_dict:  
                            cve_problem_dict = cve_details_dict['problemtype']
                            for problem_data_dict in cve_problem_dict['problemtype_data']:
                                for problem_data_desc in problem_data_dict['description']: 
                                    cve_cwe = problem_data_desc['value']
                        if 'affects' in cve_details_dict:  
                            if 'vendor' in cve_details_dict['affects']: 
                                if 'vendor_data' in cve_details_dict['affects']['vendor']: 
                                    for vendor_detail_dict in cve_details_dict['affects']['vendor']['vendor_data']: 
                                        cve_vendor_name = vendor_detail_dict['vendor_name']
                                        for product_data_dict in vendor_detail_dict['product']['product_data']:
                                            cve_product_name = product_data_dict['product_name']

                                            all_cve_data_list.append( (cve_id, cve_assigner, cve_date, cve_desc_str, cve_cwe, cve_exp_score, cve_impact_score, cve_complex, cve_conf, cve_inte, cve_ava, cve_sco, cve_sev, cve_product_name, cve_vendor_name) )

            print '='*50
    full_csv_df = pd.DataFrame(all_cve_data_list)
    pickle.dump(full_csv_df, open( final_output_file +  '_DUMP.PKL', 'wb') )
    full_csv_df.to_csv(final_output_file, index = False, header=['ID', 'ASSIGNER', 'DATE', 'DESC', 'CWE', 'EXPLOIT_SCORE', 'IMPACT_SCORE', 'COMPLEXITY', 'CONFIDE', 'INTEG', 'AVAILAB', 'SCORE', 'SEVERITY', 'PRODUCT', 'VENDOR'],  encoding = 'utf-8')



if __name__=='__main__':
    cve_dir = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/nvd-cve-reports/'
    cve_out = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/nvd-cve-reports/FINAL_NVD_CVE_DATA_FULL.csv'
    all_cve_jsons = findAllZipFiles(cve_dir)
    # print all_cve_jsons
    mineCVEs(all_cve_jsons, cve_out)  