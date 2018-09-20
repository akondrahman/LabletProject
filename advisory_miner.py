'''
Akond Rahman 
Sep 20, 2018 
Mine security advisor reports 
'''
import pandas as pd 
import numpy as np 
from BeautifulSoup import BeautifulSoup
import urllib2
import json 
import os 
import cPickle as pickle


def getVulnName(parsed_html):
    vuln_names = []
    unparsed_dumps = parsed_html.body.findAll('h4')
    #print advi_link, unparsed_dump         
    for h4_content in unparsed_dumps:
        h4_content = str(h4_content)
        span_data = h4_content.split('#')[2]
        if (('>' in span_data) and ('<' in span_data)):
            vuln_data = span_data.split('>')[1].split('<')[0]
        else:
            vuln_data = 'Unnamed vulnerability'    
        vuln_names.append(vuln_data)
    return vuln_names

def getVulnImpact(parsed_html):
    vulns = []
    vuln_impact = 'NOT_REPORTED'
    unparsed_dumps = parsed_html.body.findAll('dd')
    for dd_content in unparsed_dumps:
       dd_content = str(dd_content)
       if ('class="level' in dd_content):      
            vuln_impact_data = dd_content.split('"')[1].split('"')[0] 
            vuln_impact = vuln_impact_data.split(' ')[1]
            vulns.append(vuln_impact)
    return vulns

def processAdvisory(link_ls, pkl_output):
    adv_dict = {} 
    for advi_link in link_ls:
          response_ = urllib2.urlopen(advi_link)
          html_dump = response_.read()
          parsed_html    = BeautifulSoup(html_dump)
          vuln_data_ls = getVulnName(parsed_html)
          vuln_impact_ls = getVulnImpact(parsed_html)
          name_and_impact = zip(vuln_data_ls, vuln_impact_ls) # list of tuples (description, severity)
          #print name_and_impact
          #print  advi_link, vuln_data, vuln_impact    
          if advi_link not in adv_dict:
             adv_dict[advi_link] = name_and_impact
    print adv_dict
    pickle.dump( adv_dict, open(pkl_output, 'wb'))          
    
if __name__=='__main__':
  secu_advi_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/2018.Advisory.Bug.Mapping.csv'
  advi_df = pd.read_csv(secu_advi_file)
  advi_ls = np.unique( advi_df['Advisory'].tolist() )
  output_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/2018.Advisory.Severity.PKL'
  processAdvisory(advi_ls, output_file)
