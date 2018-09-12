import requests, json, os, time
import pprint 

start = 0
end = 1
tryAlt = 0 

token_header = {'Auth-Token': 'b9cab2524f324d50b4885ae51c37e6f0'}

crash_files = os.listdir('/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/crash-data/november/november_files_1/')

for file_ in crash_files:
    
    crash_uuid = file_.split('.')[0].split('_')[1]
    print file_, crash_uuid

    # url = 'https://crash-stats.mozilla.com/api/ProcessedCrash/?crash_id=' + crash_uuid  + '&datatype=processed'
    url = 'https://crash-stats.mozilla.com/api/RawCrash/?crash_id=' + crash_uuid  
    try:
      payload = requests.get(url, headers =  token_header ).json()
      print payload

    except:
      print 'Failed to get crash_id = ' + crash_id

    time.sleep(5)

    print '-'*50 