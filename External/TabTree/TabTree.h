#pragma once

#include "./OVS/TupleSpaceSearch.h"

#define maxBits 4  

class range
{
public:
	unsigned low;
	unsigned high;
};

class field_length
{
public:
	unsigned length[5];
	int size[5];
 };

struct TabTreeNode{
	int	depth;
	bool isleaf;

	std::vector<Rule> classifier;
	int nrules = 0;

	int bitFlag[32] = {0}; //has been selected bits

    //for strategy2&3
	int sbits[maxBits] = {-1}; //selected bits
	int ncuts = 1;
    int *child;

	int flag = 1; //bit 1 or tss 2
	PriorityTupleSpaceSearch ptss;
	int ntuples = 0;
};

class TabTree : public PacketClassifier {
public:
	TabTree(int k1,int threshold1, std::vector<Rule>& classifier);
	~TabTree();
	virtual void ConstructClassifier(const std::vector<Rule>& rules);
	virtual int ClassifyAPacket(const Packet& packet);
	virtual void DeleteRule(const Rule& delete_rule);
	virtual void InsertRule(const Rule& insert_rule);
	virtual Memory MemSizeBytes() const {
		size_t bitBytes = static_cast<size_t>(Total_Rule_Size) * PTR_SIZE
			+ static_cast<size_t>(Total_Array_Size) * PTR_SIZE
			+ static_cast<size_t>(LEAF_NODE_SIZE) * Leaf_Node_Count
			+ static_cast<size_t>(TREE_NODE_SIZE) * NonLeaf_Node_Count;
		return static_cast<Memory>(bitBytes + static_cast<size_t>(total_tss_memory_in_KB));
	}
	virtual int MemoryAccess() const { return 0; } // TODO
	virtual size_t NumTables() const { return 1; }
	virtual size_t RulesInTable(size_t tableIndex) const { return rules.size(); }

	void prints(){
		double total_bit_memory_kb = double(Total_Rule_Size*PTR_SIZE+Total_Array_Size*PTR_SIZE+LEAF_NODE_SIZE*Leaf_Node_Count+TREE_NODE_SIZE*NonLeaf_Node_Count)/1024;
		double total_tss_memory_kb = double(total_tss_memory_in_KB)/1024;
 
		if(numrules>binth){
			if(k==0)
				printf("\t***SA Subset Tree(BitSelect + PSTSS):***\n");
			if(k==1)
				printf("\t***DA Subset Tree(BitSelect + PSTSS):***\n");
			printf("\tnumber of rules:%d",numrules);
			printf("\n\tworst case tree level: %d",pass);
			printf("\n\ttotal memory(Pre Bit-selecting): %f(KB)",total_bit_memory_kb);
			printf("\n\ttotal memory(Post PSTSS): %f(KB)\n",total_tss_memory_kb);		
		}
	}

    int TablesQueried()
    {
		for(int i=1; i<=MAXNODES; i++) {
			if(nodeSet[i].flag == 2){
				queryCount[0] += nodeSet[i].ptss.TablesQueried();
			}
		}
	    return queryCount[0];
    }

//    int cutPktCount() const { return queryCount[1]; }
//    int tssPktCount() const { return queryCount[2]; }
//    int noMatchCount() const { return queryCount[3]; }
//    int totalPktsCount() const { return queryCount[4]; }

private:
	std::vector<Rule> rules;
	TabTreeNode *nodeSet;	// base of array of NodeItems
	int k; //sa:0 da:1
	unsigned int threshold;


    std::queue<int> qNode;	//queue for node
    int numrules = 0;
    int root = 1;
    int	binth = 4;
    int	pass;			// max trie level
    int	freelist;		// first nodeItem on free list

    int queryCount[5] = {0,0,0,0,0}; //0:query count  1:match packet at cut stage count  2:match packet at tss stage count 3:no match packets count 4:total packets processed

	int	Total_Rule_Size;  // number of rules stored in leaf
	int	Total_Array_Size;   // number of tree nodes
	int	Leaf_Node_Count;
	int	NonLeaf_Node_Count;
	double	total_bit_memory_in_KB;
	double	total_tss_memory_in_KB;
};
