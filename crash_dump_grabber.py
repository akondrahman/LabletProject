'''
Akond Rahman 
Sep 11 2018 
Mine crash reports 
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

def processJSONString(str_par):
    out_str   = ''
    str_lines = str_par.split('\n')
    for str_ in str_lines:
       tmp_str = ''
       if ':' in str_:
          splitted_strs = str_.split(':')
          # print splitted_strs
          for index_ in xrange(len(splitted_strs)):
              if index_==0:
                 str_ =  ' '*25 +  '"' + splitted_strs[index_].replace(' ', '') + '"' + ':'
                 # str_ = '"' + splitted_strs[index_] + '"' + ':'                 
              else:
                 str_ = splitted_strs[index_]             	 
              tmp_str = tmp_str + str_ 
       else:
          tmp_str = str_        
       out_str = out_str + tmp_str + '\n'  
    return out_str   


def dumpContentIntoFile(strP, fileP):
    fileToWrite = open( fileP, 'w')
    fileToWrite.write(strP)
    fileToWrite.close()
    return str(os.stat(fileP).st_size)

def getExistingDumps(dir_par):
    exisitng_dump_files = []
    for root_, dirs, files_ in os.walk(dir_par):
       for file_ in files_:
          hash_ = file_.split('.')[0]
          exisitng_dump_files.append(hash_)
    return exisitng_dump_files


def getCrashDumps(crash_id_list, out_dir_par, exisitng_dump_files):
    for crashID in crash_id_list:
       if crashID not in exisitng_dump_files:    	
          crash_dump_link = crashID + "#tab-rawdump"
          crash_hash = crashID.split('/')[-1]
          print crash_dump_link 
          response_ = urllib2.urlopen(crash_dump_link)
          html_dump = response_.read()
          parsed_html   = BeautifulSoup(html_dump)
          unparsed_dump = parsed_html.body.find('div', attrs={'class':'code'}).text       

          parsed_dump   = unparsed_dump.replace('<div class="code">', '')
          parsed_dump   = parsed_dump.replace('</div>', '')
          dump_json_str = parsed_dump.replace('&#34;', '') 
          dump_json_str = dump_json_str.replace('&amp;', '') 
          dump_json_str = dump_json_str.replace('&gt;', '') 
          dump_json_str = dump_json_str.replace('&lt;', '')

          dump_json_str = processJSONString(dump_json_str)
          # print dump_json_str
          bytes = dumpContentIntoFile(dump_json_str, out_dir_par + crash_hash + '.json')

          # dump_dict = json.loads(dump_json_str)
          # dump_dict =  ast.literal_eval(dump_json_str)
          # print dump_dict
          print 'Dumped a dump of {} bytes'.format(bytes)
          print '*'*50

if __name__=='__main__':
   inp_fil_ = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/2018.crashID.txt'
   out_dir  = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/raw-moz-crash-reports/raw_crash_dump_out/'
   crashIDs = getOutputLines(inp_fil_)	
   exisitng_dumps = getExistingDumps(out_dir)
   # print crashIDs
   getCrashDumps(crashIDs, out_dir, exisitng_dumps)