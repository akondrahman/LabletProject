#!/bin/bash
dir_name='2016'
output_file=$dir_name.'crashID.txt'

for html_file in $dir_name/*.html; do
  echo "=================================================="
  echo $html_file 
  cat $html_file | grep '<a href="https://crash-stats.mozilla.com/report/index/' | cut -d'=' -f2 | cut -d' ' -f1 >> $output_file
  echo "=================================================="
done

# {
#                     frame: 9,
#                     function: HALB_Guard::WaitFor(unsigned long long),
#                     function_offset: 0x24d,
#                     module: CoreAudio,
#                     module_offset: 0x39f57,
#                     offset: 0x7fffa74c7f57,
#                     trust: scan
#                 }
#             ]
#         }
#     ]
# }

# [u'                    frame', u' 9,']
# [u'                    function', u' HALB_Guard', u'', u'WaitFor(unsigned long long),']
# [u'                    function_offset', u' 0x24d,']
# [u'                    module', u' CoreAudio,']
# [u'                    module_offset', u' 0x39f57,']
# [u'                    offset', u' 0x7fffa74c7f57,']
# [u'                    trust', u' scan']