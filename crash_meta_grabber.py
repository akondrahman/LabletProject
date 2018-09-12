'''
Akond Rahman 
Sep 12 2018 
Crash metadata grabber 
'''
from BeautifulSoup import BeautifulSoup
import urllib2
import json 
import ast 
import os 
import numpy as np 

def getOutputLines(inp_fil_):
    file_lines = []
    with open(inp_fil_, 'rU') as log_fil:
         file_str = log_fil.read()
         file_lines = file_str.split('\n')
    crashes = [x_.replace('"', '') for x_ in file_lines if len(x_) > 0]
    crashes = np.unique(crashes)
    return crashes

def dumpContentIntoFile(strP, fileP):
    fileToWrite = open( fileP, 'w')
    fileToWrite.write(strP)
    fileToWrite.close()
    return str(os.stat(fileP).st_size)


def getCrashMetaData(crash_id_list, out_dir_par):
    for crashID in crash_id_list:
          crash_dump_link = crashID + "#tab-details"
          crash_hash = crashID.split('/')[-1]
          print crash_dump_link 
          response_ = urllib2.urlopen(crash_dump_link)
          html_dump = response_.read()
          parsed_html   = BeautifulSoup(html_dump)
          unparsed_dump = parsed_html.body.find('table', attrs={'class':'record data-table vertical'})
          # print dir(unparsed_dump)
          tr_list = unparsed_dump.findAll('tr')
          # print tr_list
          for tr_elem in tr_list:
             key = tr_elem.find('th', attrs={'scope':'row'}).getString()
             # print key 
             if (('<' in key) and ('>' in key)):
                key = key.split('>')[1].split('<')[0]

             val = tr_elem.find('td').getString()
             # print val 
             val = val.split('>')[1].split('<')[0]
             val = val.replace('\n', '')

             print 'KEY:{},VAL:{}'.format(key, val)
             print '*'*25

          # parsed_dump   = unparsed_dump.replace('<div class="code">', '')
          # parsed_dump   = parsed_dump.replace('</div>', '')
          # dump_json_str = parsed_dump.replace('&#34;', '') 
          # dump_json_str = dump_json_str.replace('&amp;', '') 
          # dump_json_str = dump_json_str.replace('&gt;', '') 
          # dump_json_str = dump_json_str.replace('&lt;', '')
          # bytes = dumpContentIntoFile(dump_json_str, out_dir_par + crash_hash + '.json')
          # print 'Dumped a dump of {} bytes'.format(bytes)
          print '='*50

if __name__=='__main__':
   inp_fil_ = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/2018.crashID.txt'
   out_dir  = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/meta_crash_dump_out/'
   crashIDs = getOutputLines(inp_fil_)	
   # print crashIDs
   getCrashMetaData(crashIDs, out_dir)