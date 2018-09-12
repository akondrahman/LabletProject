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
    forbidden_key_list = ['EMCheckCompatibility', 'Processor Notes', 'App Notes', ':Build ID']
    dump_json_str = ''
    for crashID in crash_id_list:
          crash_dump_link = crashID + "#tab-details"
          crash_hash = crashID.split('/')[-1]
          response_ = urllib2.urlopen(crash_dump_link)
          html_dump = response_.read()
          parsed_html   = BeautifulSoup(html_dump)
          unparsed_dump = parsed_html.body.find('table', attrs={'class':'record data-table vertical'})
          # print dir(unparsed_dump)
          tr_list = unparsed_dump.findAll('tr')
          # print tr_list
          for tr_elem in tr_list:
             key = str(tr_elem.find('th', attrs={'scope':'row'}))
             kwy = key.strip()
             # print key 
             if (('<' in key) and ('>' in key)):
                key = key.split('>')[1].split('<')[0]

             val = str(tr_elem.find('td'))
             # print val 
             val = val.split('>')[1].split('<')[0]
             val = val.replace('\n', '')
             val = val.strip()
             
             if key not in forbidden_key_list:
                print 'CRASH:{},KEY:{},VAL:{}'.format(crash_dump_link, key, val)
                dump_json_str = dump_json_str + key + ',' + val + '\n'
                print '*'*10

          bytes = dumpContentIntoFile(dump_json_str, out_dir_par + crash_hash + '.csv')
          print 'Dumped a dump of {} bytes'.format(bytes)
          print '='*50

def getCrashThread(crash_id_list, out_dir_par):
    dump_str = ''
    for crashID in crash_id_list:
          crash_dump_link = crashID + "#tab-details"
          crash_hash = crashID.split('/')[-1] 
          response_ = urllib2.urlopen(crash_dump_link)
          html_dump = response_.read()
          parsed_html   = BeautifulSoup(html_dump)
          unparsed_dump = parsed_html.body.findAll('table', attrs={'class':'data-table'}, limit=1)[0]
          # print unparsed_dump

          tr_list = unparsed_dump.findAll('tr', attrs={'class':''})
          # print tr_list
          thread_cnt = 0 
          for tr_elem in tr_list:

             td_list = tr_elem.findAll('td')
             # print td_list
             for inner_td_index in xrange(len(td_list)):
                 if inner_td_index == 2:
                    sign = str(td_list[inner_td_index]).split('>')[1].split('<')[0] 
                    sign = sign.replace('&lt;', '')
                    sign = sign.replace('&gt;', '')

                 if inner_td_index == 3:                    
                    temp_src = str(td_list[inner_td_index])
                    temp_src = temp_src.replace('\n', '')

                    if 'href' in temp_src:
                        src_code_link = temp_src.split('"')[1].split('"')[0]
                    else:
                        src_code_link = 'NO_SOURCE_CODE'
             print crash_dump_link, thread_cnt, sign, src_code_link
             thread_cnt += 1 
             dump_str = dump_str  + str(thread_cnt) + ',' + sign + ',' + src_code_link + '\n'
             print '='*10


          bytes = dumpContentIntoFile(dump_str, out_dir_par + crash_hash + '_crashing_thread' + '.csv')
          print 'Dumped a dump of {} bytes'.format(bytes)
          print '-'*50

if __name__=='__main__':
   inp_fil_ = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/2018.crashID.txt'
   meta_out_dir  = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/meta_crash_dump_out/'
   thread_out_dir  = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/thread_crash_dump_out/'

   crashIDs = getOutputLines(inp_fil_)	
   # print crashIDs

   getCrashMetaData(crashIDs, meta_out_dir)
   # getCrashThread(crashIDs, thread_out_dir)