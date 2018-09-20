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
    unparsed_dumps = parsed_html.body.findAll('h4')
    #print advi_link, unparsed_dump         
    for h4_content in unparsed_dumps:
        h4_content = str(h4_content)
        span_data = h4_content.split('#')[2]
        if (('>' in span_data) and ('<' in span_data)):
            vuln_data = span_data.split('>')[1].split('<')[0]
        else:
            vuln_data = 'Unnamed vulnerability'    
    return vuln_data

def getVulnImpact(parsed_html):
    vuln_impact = ''
    unparsed_dumps = parsed_html.body.findAll('dl', attrs={'class':'summary'})
    for dl_content in unparsed_dumps:
       print dl_content            
    return vuln_impact 

def processAdvisory(link_ls):
    for advi_link in link_ls:
          response_ = urllib2.urlopen(advi_link)
          html_dump = response_.read()
          parsed_html    = BeautifulSoup(html_dump)
          vuln_data = getVulnName(parsed_html)
          vuln_impact = getVulnImpact(parsed_html)
          print  advi_link, vuln_data    

if __name__=='__main__':
  secu_advi_file = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/2018.Advisory.Bug.Mapping.csv'
  advi_df = pd.read_csv(secu_advi_file)
  advi_ls = np.unique( advi_df['Advisory'].tolist() )
  processAdvisory(advi_ls)
