'''
Akond Rahman 
Oct 05, 2018 
Vulnerability Exploration 
'''
import cPickle as pickle 
def getAdvData(file_):
    adv_dic = pickle.load(open(file_, 'rb'))
    return adv_dic 

if __name__=='__main__':
   adv_vul_dat = '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/2017/2017.Advisory.Severity.PKL'
   adv_cve_dic = getAdvData(adv_vul_dat)
   print adv_cve_dic
