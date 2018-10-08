'''
Akond Rahman 
Oct 08, 2018 
Crash Graph Miner 
'''
import cPickle as pickle 
import numpy as np 

def createFrameDict(ls_):
    dict_ = {}
    cnt_  = 0
    for elem in ls_:
        dict_[elem] = cnt_ 
        cnt_ += 1 
    return dict_

def makeGraphForCVEs(df_p):
    cve_lis = np.unique(df_p['CVE_NAME'].tolist())
    for cve_ in cve_lis:
        frame_signs = []
        cve_df = df_p[df_p['CVE_NAME']==cve_]
        #print cve_df.head()
        frame_list = cve_df['FRAMES'].tolist() 
        for frame_ in frame_list:
            frame_sign = frame_[1] 
            frame_signs.append(frame_sign)
        uni_frame_signs = np.unique(frame_signs)
        frame_dict = createFrameDict(uni_frame_signs)
        print frame_dict

if __name__ == '__main__':
   full_df = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/FULL_DATSET.PKL', 'rb'))
   makeGraphForCVEs(full_df)