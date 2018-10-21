'''
Akond Rahman 
Oct 08, 2018 
Crash Graph Miner 
'''
import cPickle as pickle 
import numpy as np 
import os 

def createFrameDict(ls_):
    dict_ = {}
    cnt_  = 0
    for elem in ls_:
        dict_[elem] = cnt_ 
        cnt_ += 1 
    return dict_

def dumpContentIntoFile(strP, fileP):
  fileToWrite = open( fileP, 'w')
  fileToWrite.write(strP )
  fileToWrite.close()
  return str(os.stat(fileP).st_size)

def dumpCVEGraphs(cve_name, node_list, edge_list):
    node_str, edge_str = '', ''
    for node in node_list:
        node_str = node_str + str(node) + ',' + '\n'
    node_byte = dumpContentIntoFile(node_str, cve_name + '_NODES.csv')
    for edge in edge_list:
        edge_str = edge_str + str(edge[0]) + ',' + str(edge[1]) + ',' + '\n'
    edge_byte = dumpContentIntoFile(edge_str, cve_name + '_EDGES.csv')        
    print 'DUMPED A NODE AND EDGE FILE OF {} AND {} BYTES'.format(node_byte, edge_byte)

def getSignDict(df_p):
    out_dic = {}
    cve_lis = np.unique(df_p[df_p['CVE_NAME'] != 'NOT_FOUND']['CVE_NAME'].tolist())
    for cve_ in cve_lis:
        final_graph_lis = []
        frame_signs = []
        cve_df = df_p[df_p['CVE_NAME']==cve_]
        frame_list = cve_df['FRAMES'].tolist() 
        for frames_ in frame_list:
            for frame_ in frames_:
                frame_sign = frame_[1] 
                frame_signs.append(frame_sign)
        uni_frame_signs = list(np.unique(frame_signs))

        frame_dict = createFrameDict(uni_frame_signs)
        uni_fra_sig_keys= [frame_dict[x_] for x_ in uni_frame_signs]

        the_sign = frame_signs.pop()
        the_sign_key = frame_dict[the_sign] ## instead of storing the signature, store the ID 
        for frame_sign in frame_signs: 
            frame_key = frame_dict[frame_sign] ## instead of storing the signature, store the ID 
            tup_ = (the_sign_key, frame_key)
            final_graph_lis.append(tup_)
        out_dic[cve_] = (frame_dict, uni_fra_sig_keys, final_graph_lis)  ## mapper, list of nodes , list of edges as a list of tuples 
        dumpCVEGraphs(cve_, uni_fra_sig_keys , final_graph_lis)
    return out_dic
            


if __name__ == '__main__':
   full_df   = pickle.load(open('/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/FULL_DATSET.PKL', 'rb'))
   graph_dic = getSignDict(full_df)
   #print full_df.head()
   pickle.dump( graph_dic, open( '/Users/akond/Documents/AkondOneDrive/OneDrive/SoSLablet/Fall-2018/datasets/FULL_CRASH_GRAPH_DATASET.PKL', 'wb')) 
   for cve_, cve_details in graph_dic.iteritems():
       print 'CVE:{}, details:{}'.format(cve_, cve_details)
   