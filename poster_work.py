'''
Akond Rahman 
Feb 05, 2019 
HotSoS Poster Work 
'''
import pandas as pd 
import numpy as np 

def getAttackRQ2Answers(df_lis_p, orig_df):
    ID_List = []
    for df_ in df_lis_p:
        temp_list = df_['Id'].tolist()
        ID_List = ID_List + temp_list
    print 'Total questions for attacks:', len(np.unique(ID_List)) 
    unique_IDs = np.unique(ID_List) 
    unqiue_views, unique_ans = [], []
    for ID_ in unique_IDs: 
        temp_views = orig_df[orig_df['Id']==ID_]['ViewCount'].tolist() 
        unqiue_views = unqiue_views + temp_views

        temp_ans   = orig_df[orig_df['Id']==ID_]['AnswerCount'].tolist() 
        unique_ans = unique_ans + temp_ans 
    print 'Attacks: View per question:', float(sum(unqiue_views))/ float(len(unique_IDs))
    print 'Attacks: Answ per question:', float(sum(unique_ans))/ float(len(unique_IDs))
        	
def getRQ2Answer(selected_df, orig_df, categ):
    ID_List = selected_df['Id'].tolist() 
    print 'Total questions for {} are {}:'.format( categ , len(np.unique(ID_List))  )
    unique_IDs = np.unique(ID_List) 
    unqiue_views, unique_ans = [], []
    for ID_ in unique_IDs: 
        temp_views = orig_df[orig_df['Id']==ID_]['ViewCount'].tolist() 
        unqiue_views = unqiue_views + temp_views

        temp_ans   = orig_df[orig_df['Id']==ID_]['AnswerCount'].tolist() 
        unique_ans = unique_ans + temp_ans 
    print '{}: View per question: {}'.format(  categ , float(sum(unqiue_views))/ float(len(unique_IDs)) )
    print '{}: Answ per question: {}'.format( categ , float(sum(unique_ans))/ float(len(unique_IDs)) )

def getAttackRQ1Answers(df_lis_p, categ_):
    ID_List = []
    for df_ in df_lis_p:
        temp_list = df_['Id'].tolist()
        ID_List = ID_List + temp_list
    print 'Total questions for {} is : {}'.format( categ_ ,  len(np.unique(ID_List))  )

if __name__=='__main__':
   the_file='/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/HotSoS2019/ForPaper.csv'
   the_df_ = pd.read_csv(the_file)
   # print the_ds_.head()
   the_df_['ModifiedCategory'] = the_df_['Category'].str.lower()

   attack_df = the_df_[the_df_['ModifiedCategory'].str.contains('attack')]
   simul_df  = the_df_[the_df_['ModifiedCategory'].str.contains('simulation')]
   bypass_df = the_df_[the_df_['ModifiedCategory'].str.contains('bypass')]
   metas_df  = the_df_[the_df_['ModifiedCategory'].str.contains('metasploit')]
   meter_df  = the_df_[the_df_['ModifiedCategory'].str.contains('meterpreter')]
   netw_df   = the_df_[the_df_['ModifiedCategory'].str.contains('network')]
   nmap_df   = the_df_[the_df_['ModifiedCategory'].str.contains('nmap')]
   scan_df   = the_df_[the_df_['ModifiedCategory'].str.contains('scanning')]
   reve_df   = the_df_[the_df_['ModifiedCategory'].str.contains('reverse')]

#    getAttackRQ1Answers( [scan_df, nmap_df, netw_df] , 'NETWORK_ATTACK' )
#    print '='*100

#    getAttackRQ1Answers( [meter_df] , 'DLL_INJECTION' )
#    print '='*100

#    auth_df   = the_df_[the_df_['ModifiedCategory'].str.contains('authentication')]
#    getAttackRQ1Answers( [auth_df] ,  'AUTHENTICATION_ATTACK' )
#    print '='*100

#    sql_df   = the_df_[the_df_['ModifiedCategory'].str.contains('sql')]
#    getAttackRQ1Answers( [sql_df] , 'SQL_INJECTION' )
#    print '='*100

#    xss_df   = the_df_[the_df_['ModifiedCategory'].str.contains('xss')]
#    getAttackRQ1Answers( [xss_df] , 'XSS' )
#    print '='*100

#    rev_df   = the_df_[the_df_['ModifiedCategory'].str.contains('reverse')]
#    getAttackRQ1Answers( [rev_df] , 'REVERSE_SHELL' )
#    print '='*100

   attack_df_list = [attack_df, simul_df, bypass_df, metas_df, meter_df, netw_df, nmap_df, scan_df, reve_df] 
   getAttackRQ2Answers(attack_df_list, the_df_ )
   print '='*100

   legal_df  = the_df_[the_df_['ModifiedCategory'].str.contains('legal')]
   getRQ2Answer(legal_df, the_df_, 'LEGAL' )
   print '='*100   
   ethics_df = the_df_[the_df_['ModifiedCategory'].str.contains('ethic')]
   getRQ2Answer(ethics_df, the_df_, 'ETHICS' )
   print '='*100   
   testing_df= the_df_[the_df_['ModifiedCategory'].str.contains('testing')]
   getRQ2Answer(testing_df, the_df_, 'General Testing' )
   print '='*100   
   best_df   = the_df_[the_df_['ModifiedCategory'].str.contains('best')]
   getRQ2Answer(best_df, the_df_, 'BEST PRACTICES' )
   print '='*100   


#    print ethics_df.head()


