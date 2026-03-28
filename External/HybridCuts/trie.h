#include<stdio.h>
#include<stdlib.h>
#include<queue>
using namespace std;

class trie {
	struct nodeItem {
                bool isleaf;   
		int *rulelist;
                int nrules; 
                range field[MAXDIMENSIONS];  
                int *ruleid;    
  	        unsigned int ncuts; 
                int* child; 
                int  layNo; 
                int flag; 

  		int select_dim[MAXDIMENSIONS];   //dimensions to cut in HyperCuts stage
  		int ncuts2[MAXDIMENSIONS]; //number of cuts in HyperCuts stage
                };
public:

  	int   binth;                 
	float spfac;
	int   redun;
	int   pass;              // max trie level
	int   n2;               // removed rules during preprocessing
        int   k;               
        int   freelist;		// first nodeItem on free list

       int Total_Rule_Size;    // number of rules stored
       int Total_Array_Size;
       int Leaf_Node_Count;
       int NonLeaf_Node_Count;
       int total_memory;
       int total_memory_in_KB;       

       int max_depth;
       int   spfacFiCuts;
       int   numrules;
       pc_rule *rule;
       int 	root;			// root of trie
       nodeItem *nodeSet;	// base of array of NodeItems

public:
       queue<int> qNode;  //queue for node
       trie(int, int, float, pc_rule*,int);
       int  count_np(nodeItem*);
       void choose_np_dim(nodeItem *v);
       void remove_redundancy(nodeItem *v); 
       void move_up(nodeItem *v);
       void regionCompaction(nodeItem *curr_node);
       void createtrie();		
};



