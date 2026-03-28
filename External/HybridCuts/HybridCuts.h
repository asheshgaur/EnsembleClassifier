#define MAXDIMENSIONS 5
#define MAXBUCKETS 40
#define MAXNODES 5000000
#define MAXRULES 100000
#define MAXCUTS  64
#define MAXCUTS1 64
#define RULESIZE 13//sa=4,da=4,sp=2,dp=2,protocol=1
#define HEADER_SIZE 4
#define PTR_SIZE 4
#define LEAF_NODE_SIZE HEADER_SIZE
#define NODESIZE 26 //EffiCuts paper show details 


class range  
{
public:
   unsigned low;
   unsigned high;
};

class pc_rule
{
public:
range field[MAXDIMENSIONS];
};

class field_length
{
public:
unsigned length[5];
int size[5];
int flag_smallest[4]; 
};



