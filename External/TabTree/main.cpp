/*-----------------------------------------------------------------------------
 *  
 *  Name:		    main function for construction and simulation
 *  Description:	TabTree Packet classification algorithm  
 *  Paper:			“TabTree: A TSS-assisted Bit-selecting Tree Scheme for Packet Classification with Balanced Rule Mapping” 
 *  Conference:		ACM/IEEE Symposium on Architectures for Networking and Communications Systems (ANCS), 2019
 *  Version:		1.0 (release)
 *  Author:		    Wenjun Li (Designer) and Ting Huang (Coder, Under the guidance of Wenjun Li)
 *  Date:		    11/11/2019
 *   
 *-----------------------------------------------------------------------------*/

#include <iostream>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<math.h>
#include<list>
#include <sys/time.h>
#include <string.h>

#include "./TabTree.h"

using namespace std; 

FILE *fpr = fopen("./fw_1k", "r");           // ruleset file
FILE *fpt = fopen("./fw_1k_trace", "r");           // test trace file for cuttss

int bucketSize = 4;   // leaf threashold
int threshold = 16;   // Assume T_SA=T_DA=threshold
int prefixLength = 32-threshold;
int updateFlag = 0;

map<int,int> pri_id;
int rand_update[MAXRULES]; //random generate rule id
int max_pri[4] = {-1,-1,-1,-1};

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  loadrule
 *  Description:  load rules from file
 * =====================================================================================
 */
vector<Rule> loadrule(FILE *fp)
{
    unsigned int tmp;
    unsigned sip1,sip2,sip3,sip4,smask;
    unsigned dip1,dip2,dip3,dip4,dmask;
    unsigned sport1,sport2;
    unsigned dport1,dport2;
    unsigned protocal,protocol_mask;
    unsigned ht, htmask;
    int number_rule=0; //number of rules

    vector<Rule> rule;

    while(1){

        Rule r;
        std::array<Point,2> points;

        if(fscanf(fp,"@%d.%d.%d.%d/%d\t%d.%d.%d.%d/%d\t%d : %d\t%d : %d\t%x/%x\t%x/%x\n",
                  &sip1, &sip2, &sip3, &sip4, &smask, &dip1, &dip2, &dip3, &dip4, &dmask, &sport1, &sport2,
                  &dport1, &dport2,&protocal, &protocol_mask, &ht, &htmask)!= 18) break;


        if(smask == 0){
            points[0] = 0;
            points[1] = 0xFFFFFFFF;
        }else if(smask > 0 && smask <= 8){
            tmp = sip1<<24;
            points[0] = tmp;
            points[1] = points[0] + (1<<(32-smask)) - 1;
        }else if(smask > 8 && smask <= 16){
            tmp = sip1<<24; tmp += sip2<<16;
            points[0] = tmp;
            points[1] = points[0] + (1<<(32-smask)) - 1;
        }else if(smask > 16 && smask <= 24){
            tmp = sip1<<24; tmp += sip2<<16; tmp +=sip3<<8;
            points[0] = tmp;
            points[1] = points[0] + (1<<(32-smask)) - 1;
        }else if(smask > 24 && smask <= 32){
            tmp = sip1<<24; tmp += sip2<<16; tmp += sip3<<8; tmp += sip4;
            points[0] = tmp;
            points[1] = points[0] + (1<<(32-smask)) - 1;
        }else{
            printf("Src IP length exceeds 32\n");
            exit(-1);
        }
        r.range[0] = points;

        if(dmask == 0){
            points[0] = 0;
            points[1] = 0xFFFFFFFF;
        }else if(dmask > 0 && dmask <= 8){
            tmp = dip1<<24;
            points[0] = tmp;
            points[1] = points[0] + (1<<(32-dmask)) - 1;
        }else if(dmask > 8 && dmask <= 16){
            tmp = dip1<<24; tmp +=dip2<<16;
            points[0] = tmp;
            points[1] = points[0] + (1<<(32-dmask)) - 1;
        }else if(dmask > 16 && dmask <= 24){
            tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8;
            points[0] = tmp;
            points[1] = points[0] + (1<<(32-dmask)) - 1;
        }else if(dmask > 24 && dmask <= 32){
            tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8; tmp +=dip4;
            points[0] = tmp;
            points[1] = points[0] + (1<<(32-dmask)) - 1;
        }else{
            printf("Dest IP length exceeds 32\n");
            exit(-1);
        }
        r.range[1] = points;

        points[0] = sport1;
        points[1] = sport2;
        r.range[2] = points;

        points[0] = dport1;
        points[1] = dport2;
        r.range[3] = points;

        if(protocol_mask == 0xFF){
            points[0] = protocal;
            points[1] = protocal;
        }else if(protocol_mask== 0){
            points[0] = 0;
            points[1] = 0xFF;
        }else{
            printf("Protocol mask error\n");
            exit(-1);
        }
        r.range[4] = points;

        r.prefix_length[0] = smask;
        r.prefix_length[1] = dmask;
        r.id = number_rule;
        //r.priority = number_rule;

        rule.push_back(r);

        number_rule++;
    }

    //printf("the number of rules = %d\n", number_rule);
    int max_pri = number_rule-1;
    for(int i=0;i<number_rule;i++){
        rule[i].priority = max_pri - i;
        pri_id.insert(pair<int,int>(rule[i].priority,rule[i].id));
        /*printf("%u: %u:%u %u:%u %u:%u %u:%u %u:%u %d\n", i,
          rule[i].range[0][0], rule[i].range[0][1],
          rule[i].range[1][0], rule[i].range[1][1],
          rule[i].range[2][0], rule[i].range[2][1],
          rule[i].range[3][0], rule[i].range[3][1],
          rule[i].range[4][0], rule[i].range[4][1],
          rule[i].priority);*/
    }
    pri_id.insert(pair<int,int>(-1,-1));

    return rule;
}

std::vector<Packet> loadpacket(FILE *fp)
{
    unsigned int header[MAXDIMENSIONS];
    unsigned int proto_mask, fid;
    int number_pkt=0; //number of packets
    std::vector<Packet> packets;

    while(1){
        if(fscanf(fp,"%u %u %d %d %d %u %d\n",
                     &header[0], &header[1], &header[2], &header[3], &header[4], &proto_mask, &fid) == Null) break;
        Packet p;
        p.push_back(header[0]);
        p.push_back(header[1]);
        p.push_back(header[2]);
        p.push_back(header[3]);
        p.push_back(header[4]);
        p.push_back(fid);

        packets.push_back(p);
        number_pkt++;
    }

    /*printf("the number of packets = %d\n", number_pkt);
    for(int i=0;i<number_pkt;i++){
        printf("%u: %u %u %u %u %u %u\n", i,
               packets[i][0],
               packets[i][1],
               packets[i][2],
               packets[i][3],
               packets[i][4],
               packets[i][5]);}*/

    return packets;
}

void parseargs(int argc, char *argv[])
{
    int	c;
    bool	ok = 1;
    while ((c = getopt(argc, argv, "b:t:r:e:s:u:p:h")) != -1){
        switch (c) {
            case 'b':
                bucketSize = atoi(optarg);
                break;
            case 't':
                threshold = atoi(optarg);
                break;
            case 'r':
                fpr = fopen(optarg, "r");
                break;
            case 'e':
                fpt = fopen(optarg, "r");
                break;
            case 'u':
                updateFlag = atoi(optarg);
                break;
            case 'h':
                printf("TabTree [-b bucketSize][-t threshold(assume T_SA=T_DA)][-r ruleset][-e trace]\n");
                printf("mail me: wenjunli@pku.edu.cn\n");
                exit(1);
                break;
            default:
                ok = 0;
        }
    }

    if(bucketSize <= 0 || bucketSize > MAXBUCKETS){
        printf("bucketSize should be greater than 0 and less than %d\n", MAXBUCKETS);
        ok = 0;
    }
    if(threshold < 0 || threshold > 32){
        printf("threshold should be greater than 0 and less than 32\n");
        ok = 0;
    }
    if(fpr == NULL){
        printf("can't open ruleset file\n");
        ok = 0;
    }
    if (!ok || optind < argc){
        fprintf (stderr, "TabTree [-b bucketSize][-t threshold(assume T_SA=T_DA)][-r ruleset][-e trace][-u update]\n");
        fprintf (stderr, "Type \"TabTree -h\" for help\n");
        exit(1);
    }

    printf("************TabTree: version 1.0******************\n");
    printf("Bucket Size =  %d\n", bucketSize);
    printf("Threshold = %d,%d\n", threshold,threshold);
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  count_length
 *  Description:  record length of field and corresponding size
 * =====================================================================================
 */
void count_length(int number_rule,vector<Rule> rule,field_length *field_length_ruleset)
{
    unsigned temp_size=0;
    unsigned temp_value=0;
    //unsigned temp0=0;

    for(int i=0;i<number_rule;i++) //length&size（log2(length+1)）
    {
        for(int j=0;j<5;j++)  //record field length in field_length_ruleset[i]
        {
            field_length_ruleset[i].length[j]=rule[i].range[j][1]-rule[i].range[j][0];
            if(field_length_ruleset[i].length[j]==0xffffffff)
                field_length_ruleset[i].size[j]=32; //for address *
            else
            {
                temp_size=0;
                temp_value=field_length_ruleset[i].length[j]+1;   //0xf +1 4
                while((temp_value=temp_value/2)!=0)
                    temp_size++;
                //for port number
                if((field_length_ruleset[i].length[j]+1 - pow(2,temp_size))!=0) //10 3 11-8=3 4
                    temp_size++;

                field_length_ruleset[i].size[j]=temp_size;
            }
        }
    }
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  partition_v1 (version2)
 *  Description:  partition ruleset into 3 subsets(sa da big) based on address field(2 dim.)
 * =====================================================================================
 */
void partition_v1(vector<Rule> rule,vector<Rule> subset[3],int num_subset[3],int number_rule,field_length *field_length_ruleset,int threshold_value[2])
{  //Subset 0:sa; 1:da; 2:big
    int num_small_tmp[number_rule];
    for(int i=0;i<number_rule;i++){ //number of small field in sip dip
        num_small_tmp[i]=0;
        for(int k=0;k<2;k++)
            if(field_length_ruleset[i].size[k] <= threshold_value[k])
                num_small_tmp[i]++;
    }

    int count_sa=0;
    int count_da=0;
    int count_big=0;  //big rule set
    for(int i=0;i<number_rule;i++){
        if(num_small_tmp[i]==0){
            subset[2].push_back(rule[i]);
            count_big++;
            if(rule[i].priority>max_pri[2]) max_pri[2]=rule[i].priority;
        }
        else if(num_small_tmp[i]==2){
            subset[0].push_back(rule[i]);
            count_sa++;
            if(rule[i].priority>max_pri[0]) max_pri[0]=rule[i].priority;
        }
        else if(num_small_tmp[i]==1){
            if(field_length_ruleset[i].size[0]<=threshold_value[0]) {
                subset[0].push_back(rule[i]);
                count_sa++;
                if(rule[i].priority>max_pri[0]) max_pri[0]=rule[i].priority;
            }//sip is small
            else if(field_length_ruleset[i].size[1]<=threshold_value[1]){
                subset[1].push_back(rule[i]);
                count_da++;
                if(rule[i].priority>max_pri[1]) max_pri[1]=rule[i].priority;
            } //dip is small

        }
    }

    num_subset[0]=count_sa;
    num_subset[1]=count_da;
    num_subset[2]=count_big;

    printf("Sa_subset:%d\tDa_subset:%d\tBig_subset:%d\n",count_sa,count_da,count_big);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  partition_v2 (version2)
 *  Description:  partition ruleset into 4 subsets(sa_da sa da big) based on address field(2 dim.)
 * =====================================================================================
 */
/*
void partition_v2(vector<Rule> rule,vector<Rule> subset[4],int num_subset[4],int number_rule,field_length *field_length_ruleset,int threshold_value[2])
{  //0:sa,da; 1:sa; 2:da; 3:big
    int num_small_tmp[number_rule];
    for(int i=0;i<number_rule;i++){ 
        num_small_tmp[i]=0;
        for(int k=0;k<2;k++)
            if(field_length_ruleset[i].size[k] <= threshold_value[k])
                num_small_tmp[i]++;
    }

    int count_sa_da=0;
    int count_sa=0;
    int count_da=0;
    int count_big=0;  
    for(int i=0;i<number_rule;i++){
        if(num_small_tmp[i]==0){
            subset[3].push_back(rule[i]);
            count_big++;
            if(rule[i].priority>max_pri[3]) max_pri[3]=rule[i].priority;
        }
        else if(num_small_tmp[i]==2){
            subset[0].push_back(rule[i]);
            count_sa_da++;
            if(rule[i].priority>max_pri[0]) max_pri[0]=rule[i].priority;
        }
        else if(num_small_tmp[i]==1){
            if(field_length_ruleset[i].size[0]<=threshold_value[0]) {
                subset[1].push_back(rule[i]);
                count_sa++;
                if(rule[i].priority>max_pri[1]) max_pri[1]=rule[i].priority;
            }
            else if(field_length_ruleset[i].size[1]<=threshold_value[1]){
                subset[2].push_back(rule[i]);
                count_da++;
                if(rule[i].priority>max_pri[2]) max_pri[2]=rule[i].priority;
            } 

        }
    }

    num_subset[0]=count_sa_da;
    num_subset[1]=count_sa;
    num_subset[2]=count_da;
    num_subset[3]=count_big;

    printf("Sa_Da_subset:%d\tSa_subset:%d\tDa_subset:%d\tBig_subset:%d\n\n",count_sa_da,count_sa,count_da,count_big);
}
*/

int main(int argc, char* argv[])
{

    parseargs(argc, argv);

    vector<Rule> rule;
    vector<Packet> packets;

    std::chrono::time_point<std::chrono::steady_clock> start, end;
    std::chrono::duration<double> elapsed_seconds;


    if(fpr != NULL){
        rule = loadrule(fpr);
        int number_rule = rule.size();
        printf("the number of rules = %d\n", number_rule);

        field_length *field_length_ruleset = (field_length*)malloc(sizeof(field_length)*number_rule);
        count_length(number_rule,rule,field_length_ruleset); 
        int threshold_value[2]={threshold,threshold};   //T_SA=T_DA=threshold 

        vector<Rule> subset_3[3];  //subset 0:sa; 1:da; 2:big
        int num_subset_3[3]={0,0,0};  //#subset
        partition_v1(rule,subset_3,num_subset_3,number_rule,field_length_ruleset,threshold_value); //3 subset: sa_small, da_small, big

			
        printf("**************** Construction ****************\n");
        TabTree bt_sa(0,threshold,subset_3[0]);
        TabTree bt_da(1,threshold,subset_3[1]);
        PriorityTupleSpaceSearch ptss;

        //construct classifier
        start = std::chrono::steady_clock::now();
        if(num_subset_3[0] > 0) bt_sa.ConstructClassifier(subset_3[0]);
        if(num_subset_3[1] > 0) bt_da.ConstructClassifier(subset_3[1]);
        if(num_subset_3[2] > 0) ptss.ConstructClassifier(subset_3[2]);
        end = std::chrono::steady_clock::now();
        elapsed_seconds = end - start;
        Memory total_memory_bytes = bt_sa.MemSizeBytes() + bt_da.MemSizeBytes() + ptss.MemSizeBytes();
        printf("\tConstruction time: %f ms\n", elapsed_seconds.count() * 1000.0);
        printf("\tTotal memory consumption: %u bytes\n", total_memory_bytes);
        printf("BENCHMARK.TabTree.CONSTRUCTION_MS=%.6f\n", elapsed_seconds.count() * 1000.0);
        printf("BENCHMARK.TabTree.MEMORY_BYTES=%u\n", total_memory_bytes);

        bt_sa.prints();
        bt_da.prints();
        printf("\t***PSTSS for big rules:***\n");
        ptss.prints();


        if(fpt != NULL){
            printf("**************** Classification ****************\n");
            packets = loadpacket(fpt);
            int number_pkt = packets.size();
            printf("\tnumber of packets = %d\n", number_pkt);

            int match_miss = 0;
            int match_pri = -1;
            vector<int> results;

            match_pri = -1;
            results.clear();
            start = std::chrono::steady_clock::now();
            for (auto const &p : packets) {
                match_pri = -1;
                if(num_subset_3[0] > 0) match_pri = max(match_pri, bt_sa.ClassifyAPacket(p));
                if(num_subset_3[1] > 0 && match_pri < max_pri[1]) match_pri = max(match_pri, bt_da.ClassifyAPacket(p));
                if(num_subset_3[2] > 0 && match_pri < max_pri[2]) match_pri = max(match_pri, ptss.ClassifyAPacket(p));
                results.push_back(pri_id[match_pri]);
            }
            end = std::chrono::steady_clock::now();
            elapsed_seconds = end - start;
            
            match_miss = 0;
            for(int i = 0;i < number_pkt;i++){
                if(results[i] == -1) match_miss++;
                else if(packets[i][5] < results[i]) match_miss++;
            }
            printf("\t%d packets are classified, %d of them are misclassified\n", number_pkt, match_miss);
            printf("\tTotal classification time: %f s\n", elapsed_seconds.count());

            int total_query = bt_sa.TablesQueried()+bt_da.TablesQueried()+ptss.TablesQueried();
            printf("\tTotal memory access: %d\n", total_query);
            printf("\tAverage memory access: %f\n", 1.0 * total_query /  packets.size());
            printf("BENCHMARK.TabTree.TIME_NS_TOTAL=%.0f\n", elapsed_seconds.count() * 1e9);
            printf("BENCHMARK.TabTree.ACCURACY_PERCENT=%f\n", 100.0 * (number_pkt - match_miss) / double(number_pkt));
            printf("BENCHMARK.TabTree.CORRECT=%d\n", number_pkt - match_miss);
            printf("BENCHMARK.TabTree.INCORRECT=%d\n", match_miss);
            printf("BENCHMARK.TabTree.PACKETS=%d\n", number_pkt);

        }



        if(fpr != NULL && updateFlag != 0){
            printf("**************** Update ****************\n");
            srand((unsigned)time(NULL));
            for(int ra=0;ra<MAXRULES;ra++){ //1000000
                rand_update[ra] = rand()%2; //0:insert 1:delete
            }
            int insert_num = 0, delete_num = 0;
            int number_update = min(number_rule,MAXRULES);

            start = std::chrono::steady_clock::now();
            for(int ra=0;ra<number_update;ra++){
                int smask = rule[ra].prefix_length[0];
                int dmask = rule[ra].prefix_length[1];
                if(rand_update[ra] == 0)//0:insert
                {
                    if(smask>=prefixLength) bt_sa.InsertRule(rule[ra]);
                    else if(dmask>=prefixLength) bt_da.InsertRule(rule[ra]);
                    else ptss.InsertRule(rule[ra]);
                    insert_num++;
                } else{//1:delete
                    if(smask>=prefixLength) bt_sa.DeleteRule(rule[ra]);
                    else if(dmask>=prefixLength) bt_da.DeleteRule(rule[ra]);
                    else ptss.DeleteRule(rule[ra]);
                    delete_num++;
                }
            }
            end = std::chrono::steady_clock::now();
            elapsed_seconds = end - start;
            printf("\t%d rules update: insert_num = %d delete_num = %d\n", number_update,insert_num,delete_num);
            printf("\tTotal update time: %f s\n", elapsed_seconds.count());
            printf("\tAverage update time: %f us\n", elapsed_seconds.count()*1000000/number_update);

        }

    }

    //fclose(fpr);fclose(fpt);

    return 0;

}


