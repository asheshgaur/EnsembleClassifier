#include <iostream>
#include <stdlib.h>
#include <cmath>
#include "TabTree.h"
using namespace std;

TabTree::TabTree(int k1, int threshold1, std::vector<Rule> &classifier){

    k = k1;      //0:SA, 1:DA
    threshold = threshold1;  
    this->rules = classifier;
    numrules = classifier.size();
    nodeSet = new TabTreeNode[MAXNODES+1];
    root = 1;

    pass=1;
	Total_Rule_Size=0;
    Total_Array_Size=0;
    Leaf_Node_Count=0;
    NonLeaf_Node_Count=0;
    total_bit_memory_in_KB=0;
    total_tss_memory_in_KB=0;

    nodeSet[root].depth = 1; 
    nodeSet[root].isleaf = 0;
    nodeSet[root].nrules = numrules;
    nodeSet[root].classifier = classifier;
    nodeSet[root].flag = 1; //bit selecting 
    nodeSet[root].ntuples = 0;

    freelist = 2;
    
}
  

TabTree::~TabTree(){
    delete [] nodeSet; 
}


//strategy2: select top b optimal bits
int BitSelect2(TabTreeNode* node, int k, int threshold){

    int minDiff = node->nrules;
    int count_left_child = 0,count_right_child = 0;
    int bitSelect = -1;
    int flag = -1;

    for(int t=0;t<maxBits;t++){
        bitSelect = -1;
        minDiff = node->nrules;
        for(int i=0;i<32-threshold;i++){
            if(node->bitFlag[i] == 0){
                count_left_child = 0;
                count_right_child = 0;
                for(int j=0;j<node->nrules;j++){
                    if(((node->classifier[j].range[k][0] >> (31-i)) & 1) == 0) count_left_child++;
                    else count_right_child++;
                }
                int absDiff = abs(count_right_child - count_left_child);
                if(minDiff >= absDiff){
                    minDiff = absDiff;
                    bitSelect = i;
                    flag = 1;
                }
            }
        }
        if(bitSelect != -1){
            node->sbits[t] = bitSelect;
            node->bitFlag[bitSelect] = 1;
            node->ncuts = node->ncuts * 2;
        }
    }

    return flag;
}

/*
//Compute Standard Deviation
double costFunc(TabTreeNode* node, int *cur_sbits, int k){
    double variance = 0, stdDev = 0;
    int maxchilds = (int)pow(2,maxBits);
    int numRules[maxchilds] = {0};
    double meanValue = node->nrules/(double)maxchilds;
    //printf("nrules = %d  meanValue = %f\n",node->nrules,meanValue);
    for(const Rule& r : node->classifier){
        int index = 0;
        int cnode = 0;
        for(int j = 0;j < maxBits;j++){
            cnode += ((r.range[k][0] >> (31-cur_sbits[j])) & 1) * ((int)pow(2,index));
            index++;
        }
        numRules[cnode]++;
    }

    for(int i = 0;i < maxchilds; i++){
        //if(numRules[i] > 0)
        variance += (numRules[i]-meanValue)*(numRules[i]-meanValue);
    }
    variance = variance/maxchilds;
    stdDev = sqrt(variance);
    //printf("variance = %f stdDev = %f \n",variance,stdDev);

    return stdDev;
}

//strategy3: violence algorithm to find the best b bits
int BitSelect3(TabTreeNode* node, int k, int threshold){

    double minStdDev = MAXNODES; //TODO
    double curCost = 0;
    int flag = -1;
    for(int i=0;i<32-threshold-3;i++){
        if(node->bitFlag[i]==0){
            for(int j=i+1;j<32-threshold-2;j++){
                if(node->bitFlag[j]==0){
                    for(int h=j+1;h<32-threshold-1;h++){
                        if(node->bitFlag[h]==0){
                            for(int t=h+1;t<32-threshold;t++){
                                if(node->bitFlag[t]==0){
                                    int cur_sbits[maxBits] = {i,j,h,t};
                                    curCost = costFunc(node,cur_sbits,k);
                                    if(curCost < minStdDev){
                                        flag = 1;
                                        minStdDev = curCost;
                                        memcpy(node->sbits,cur_sbits, sizeof(node->sbits));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

    }
    for(int h=0;h<maxBits;h++){
        node->bitFlag[node->sbits[h]] = 1;
        node->ncuts = node->ncuts * 2;
    }

    return flag;
}
*/

void TabTree::ConstructClassifier(const vector<Rule>& rules)
{
    int u,v;
    int flag;

    qNode.push(root);

    while(!qNode.empty()){
        v=qNode.front();
        qNode.pop();

        if(nodeSet[v].flag==1){  
            if(nodeSet[v].depth > ((32-threshold)/4)) nodeSet[v].flag = 2; //PSTSS node            
            else{
                flag = BitSelect2(&nodeSet[v],k,threshold); //bit
                if(flag == -1) { //tss
                    nodeSet[v].flag = 2;
                }
            }
        }

        if(nodeSet[v].flag==1) //bit stage
        {
            if(nodeSet[v].nrules <= binth){ //leaf node (linear node)
                nodeSet[v].isleaf = 1;
				Total_Rule_Size+= nodeSet[v].nrules;
                Leaf_Node_Count++;
            }
            else{ 
                NonLeaf_Node_Count++;
                Total_Array_Size += nodeSet[v].ncuts;
                nodeSet[v].child = (int *)malloc(sizeof(int)*nodeSet[v].ncuts);

                for(int i = 0;i < nodeSet[v].ncuts; i++){
                    nodeSet[v].child[i] = freelist;
                    u = freelist;
                    freelist++;

                    for(const Rule& r : nodeSet[v].classifier){
                        int index = 0;
                        int cnode = 0;
                        for(int j = 0;j < maxBits;j++){
                            if(nodeSet[v].sbits[j] != -1){
                                cnode += ((r.range[k][0] >> (31-nodeSet[v].sbits[j])) & 1) * ((int)pow(2,index));
                                index++;
                            }
                        }
                        if(cnode == i){
                            nodeSet[u].classifier.push_back(r);
                        }
                    }
					
                    nodeSet[u].nrules = nodeSet[u].classifier.size();					
                    if(nodeSet[u].nrules > 0){
                        nodeSet[u].depth = nodeSet[v].depth+1;

                        if(nodeSet[u].nrules <= binth) { //leaf node (linear node)
                            nodeSet[u].isleaf = 1;
							Total_Rule_Size+= nodeSet[u].nrules;
                            Leaf_Node_Count++;
                        }
                        else{
                            nodeSet[u].isleaf = 0;
                            nodeSet[u].flag=1;  //bit

                            if(pass<nodeSet[u].depth){
                                pass=nodeSet[u].depth;
                            }

                            qNode.push(u); 
                        }

                        memcpy(nodeSet[u].bitFlag, nodeSet[v].bitFlag, sizeof(nodeSet[u].bitFlag));

                    }else //empty
                        nodeSet[v].child[i] = Null;
                }
            } 
        } else{ //TSS assisted stage
            if(nodeSet[v].nrules <= binth){  //leaf node (linear node)
                nodeSet[v].isleaf = 1;
				Total_Rule_Size+= nodeSet[v].nrules;
                Leaf_Node_Count++;
            }
            else{   //leaf node (PSTSS node)
                NonLeaf_Node_Count++;
                nodeSet[v].ptss.ConstructClassifier(nodeSet[v].classifier);
                nodeSet[v].ntuples = nodeSet[v].ptss.NumTables();
                total_tss_memory_in_KB += nodeSet[v].ptss.MemSizeBytes();
			}

        }

    }

}

//strategy2: select top k best bits
//strategy3: violence search to find the best k bits
int TabTree::ClassifyAPacket(const Packet &packet){
    int cnode = 1;
    int flag_tss = 0;
    int match_id = -1;

    while(nodeSet[cnode].isleaf != 1){ 

        int index = 0;
        int cchild = 0;

        cchild = ((packet[k] >> (31-nodeSet[cnode].sbits[0])) & 1) + ((packet[k] >> (31-nodeSet[cnode].sbits[1])) & 1) * 2
                + ((packet[k] >> (31-nodeSet[cnode].sbits[2])) & 1) * 4 + ((packet[k] >> (31-nodeSet[cnode].sbits[3])) & 1) * 8;

        cnode = nodeSet[cnode].child[cchild];
        queryCount[0]++;

        if(cnode == Null) break;
        if(nodeSet[cnode].flag == 2) {
            flag_tss = 1;
            break;
        }
    }

    if(cnode != Null && flag_tss == 1){ //tss stage
        match_id = nodeSet[cnode].ptss.ClassifyAPacket(packet); //priority
    }
    else if(cnode != Null && flag_tss == 0 && nodeSet[cnode].isleaf == 1){ //bitSelect stage
		int n = nodeSet[cnode].classifier.size();
        for(int i = 0; i < n; i++){
            queryCount[0]++;
            if(packet[0] >= nodeSet[cnode].classifier[i].range[0][LowDim] && packet[0] <= nodeSet[cnode].classifier[i].range[0][HighDim] &&
               packet[1] >= nodeSet[cnode].classifier[i].range[1][LowDim] && packet[1] <= nodeSet[cnode].classifier[i].range[1][HighDim] &&
               packet[2] >= nodeSet[cnode].classifier[i].range[2][LowDim] && packet[2] <= nodeSet[cnode].classifier[i].range[2][HighDim] &&
               packet[3] >= nodeSet[cnode].classifier[i].range[3][LowDim] && packet[3] <= nodeSet[cnode].classifier[i].range[3][HighDim] &&
               packet[4] >= nodeSet[cnode].classifier[i].range[4][LowDim] && packet[4] <= nodeSet[cnode].classifier[i].range[4][HighDim]){
                match_id = nodeSet[cnode].classifier[i].priority;
                break;
            }
        }

    }

    return  match_id;
}
 

//strategy2/3
void TabTree::DeleteRule(const Rule& delete_rule) {
    int cnode = 1;
    int flag_tss = 0;
    int i,j;

    while(nodeSet[cnode].isleaf != 1){  

        int index = 0;
        int cchild = 0;

        cchild = ((delete_rule.range[k][0] >> (31-nodeSet[cnode].sbits[0])) & 1) + ((delete_rule.range[k][0] >> (31-nodeSet[cnode].sbits[1])) & 1) * 2
                 + ((delete_rule.range[k][0] >> (31-nodeSet[cnode].sbits[2])) & 1) * 4 + ((delete_rule.range[k][0] >> (31-nodeSet[cnode].sbits[3])) & 1) * 8;

        cnode = nodeSet[cnode].child[cchild];

        if(nodeSet[cnode].flag == 2) {
            flag_tss = 1;
            break;
        }
    }
    //cnode != Null && flag_tss == 1
    if(flag_tss){
        nodeSet[cnode].ptss.DeleteRule(delete_rule);
    }
    //cnode != Null && flag_tss == 0 && nodeSet[cnode].isleaf == 1
    else {
        if(nodeSet[cnode].nrules > 0){
            int size = nodeSet[cnode].classifier.size();
            for(i=0;i<size;i++){
                if(nodeSet[cnode].classifier[i].id == delete_rule.id) break;
            }
            nodeSet[cnode].classifier.erase(nodeSet[cnode].classifier.begin()+i);
            nodeSet[cnode].nrules--;
        }
    }
}
//strategy2/3
void TabTree::InsertRule(const Rule& insert_rule) {

    int cnode = 1;
    int flag_tss = 0;
    int cchild = 0;
    int u;

    while(nodeSet[cnode].isleaf != 1){  

        int index = 0;
        cchild = 0;

        cchild = ((insert_rule.range[k][0] >> (31-nodeSet[cnode].sbits[0])) & 1) + ((insert_rule.range[k][0] >> (31-nodeSet[cnode].sbits[1])) & 1) * 2
                 + ((insert_rule.range[k][0] >> (31-nodeSet[cnode].sbits[2])) & 1) * 4 + ((insert_rule.range[k][0] >> (31-nodeSet[cnode].sbits[3])) & 1) * 8;

        u = nodeSet[cnode].child[cchild];

        if(u == Null) break;
        if(nodeSet[u].flag == 2) {
            flag_tss = 1;
            break;
        }

        cnode = u;
    }
    if(u == Null){
        nodeSet[cnode].child[cchild] = freelist;
        u = freelist;
        freelist++;
        nodeSet[u].classifier.push_back(insert_rule);
        nodeSet[u].nrules++;
    }
    //u != Null && flag_tss == 1
    else if(flag_tss){ //tss stage
        nodeSet[u].ptss.InsertRule(insert_rule);
    }
    //u != Null && flag_tss == 0 && nodeSet[cnode].isleaf == 1
    else { //bitSelect stage

        nodeSet[cnode].nrules++;
        nodeSet[cnode].classifier.push_back(insert_rule);

        if(nodeSet[cnode].nrules > binth){  
            //printf("new tss node!\n");
            nodeSet[cnode].isleaf = 0;
            nodeSet[cnode].flag = 2;
            nodeSet[cnode].ptss.ConstructClassifier(nodeSet[cnode].classifier);
        }

    }

}