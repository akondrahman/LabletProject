'''
Akond Rahman 
July 04, 2019 
Mine chrome bugs 
'''
import os 
import numpy as np 
import pandas as pd 
import json
from ijson import items
import shutil

def findAllJSONFiles(dir_name):
    all_json_files = []
    for root_, dirs, files_ in os.walk(dir_name):
       for file_ in files_:
           if file_.endswith('.json')  :  # checkign extension requires dot 
              all_json_files.append(os.path.join(root_, file_)) 
    return all_json_files

def getJSONData(file_list):
    for file_ in file_list:
        if os.path.exists(file_):
            d_ = json.load(file_)
            print dir(d_) 
            print '*'*10            


if __name__=='__main__':
    bug_repor_dir  = '/Users/akond/Documents/AkondOneDrive/OneDrive/JobPrep-TNTU2019/research/chrome-bug-reports/bugs'
    all_json_files = findAllJSONFiles(bug_repor_dir)
    # print all_json_files
    getJSONData(all_json_files)