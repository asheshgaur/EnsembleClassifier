#include<stdio.h>
#include<stdlib.h> 
#include<unistd.h>
#include<math.h>
#include<list>
#include"HybridCuts.h"  
#include"trie.h"  
#include "common.h"
  
using namespace std; 

int bucketSize = 8;   // leaf threashold
float spfac = 4;     // space explosion factor
FILE *fpr;           // ruleset file
int threshold=16;   // for simple implement, we assume T_SA=T_DA=threshold


//**********Function: load rules from file*************************************
int loadrule(FILE *fp,pc_rule *rule)
{
   int tmp;
   unsigned sip1,sip2,sip3,sip4,smask;
   unsigned dip1,dip2,dip3,dip4,dmask;
   unsigned sport1,sport2;
   unsigned dport1,dport2;
   unsigned protocal,protocol_mask;
   int number_rule=0; //number of rules

   while(1){
      if(fscanf(fp,"@%d.%d.%d.%d/%d\t%d.%d.%d.%d/%d\t%d : %d\t%d : %d\t%x/%x\n", &sip1, &sip2, &sip3, &sip4, &smask, &dip1, &dip2, &dip3, &dip4, &dmask, &rule[number_rule].field[2].low, &rule[number_rule].field[2].high, &rule          [number_rule].field[3].low, &rule[number_rule].field[3].high,&protocal, &protocol_mask)!= 16) break;


   if(smask == 0){
      rule[number_rule].field[0].low = 0;
      rule[number_rule].field[0].high = 0xFFFFFFFF;
    }else if(smask > 0 && smask <= 8){
      tmp = sip1<<24;
      rule[number_rule].field[0].low = tmp;
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1<<(32-smask)) - 1;
    }else if(smask > 8 && smask <= 16){
      tmp = sip1<<24; tmp += sip2<<16;
      rule[number_rule].field[0].low = tmp; 	
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1<<(32-smask)) - 1;	
    }else if(smask > 16 && smask <= 24){
      tmp = sip1<<24; tmp += sip2<<16; tmp +=sip3<<8; 
      rule[number_rule].field[0].low = tmp; 	
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1<<(32-smask)) - 1;			
    }else if(smask > 24 && smask <= 32){
      tmp = sip1<<24; tmp += sip2<<16; tmp += sip3<<8; tmp += sip4;
      rule[number_rule].field[0].low = tmp; 
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1<<(32-smask)) - 1;	
    }else{
      printf("Src IP length exceeds 32\n");
      return 0;
    }
    if(dmask == 0){
      rule[number_rule].field[1].low = 0;
      rule[number_rule].field[1].high = 0xFFFFFFFF;
    }else if(dmask > 0 && dmask <= 8){
      tmp = dip1<<24;
      rule[number_rule].field[1].low = tmp;
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1<<(32-dmask)) - 1;
    }else if(dmask > 8 && dmask <= 16){
      tmp = dip1<<24; tmp +=dip2<<16;
      rule[number_rule].field[1].low = tmp; 	
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1<<(32-dmask)) - 1;	
    }else if(dmask > 16 && dmask <= 24){
      tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8;
      rule[number_rule].field[1].low = tmp; 	
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1<<(32-dmask)) - 1;			
    }else if(dmask > 24 && dmask <= 32){
      tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8; tmp +=dip4;
      rule[number_rule].field[1].low = tmp; 	
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1<<(32-dmask)) - 1;	
    }else{
      printf("Dest IP length exceeds 32\n");
      return 0;
    }
    if(protocol_mask == 0xFF){
      rule[number_rule].field[4].low = protocal;
      rule[number_rule].field[4].high = protocal;
    }else if(protocol_mask== 0){
      rule[number_rule].field[4].low = 0;
      rule[number_rule].field[4].high = 0xFF;
    }else{
      printf("Protocol mask error\n");
      return 0;
    }

   number_rule++;
   }
  
   //-------------flag1: used for test--------------------
   /* 
   printf("the number of rules = %d\n", number_rule);
     for(int i=0;i<number_rule;i++){
      printf("%u: %u:%u %u:%u %u:%u %u:%u %u:%u\n", i,
        rule[i].field[0].low, rule[i].field[0].high, 
        rule[i].field[1].low, rule[i].field[1].high,
        rule[i].field[2].low, rule[i].field[2].high,
        rule[i].field[3].low, rule[i].field[3].high, 
        rule[i].field[4].low, rule[i].field[4].high);}
   */
   //--------------used for test:flag1---------------------

  return number_rule;  
}

void parseargs(int argc, char *argv[])  
{
  int	c;
  bool	ok = 1;
  while ((c = getopt(argc, argv, "b:s:r:t:h")) != -1){
    switch (c) {
	case 'b':
	  bucketSize = atoi(optarg);
	  break;
	case 's':
	  spfac = atof(optarg);
	  break;
	case 't':
	  threshold = atoi(optarg);
          break;
	case 'r':
	  fpr = fopen(optarg, "r");
          break;
	case 'h':
	  printf("HybridCuts [-b bucketSize][-s spfac][-t threshold(assume T_SA=T_DA)][-r ruleset]\n");
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
  if(spfac < 1.0){
    printf("space factor should be >= 1\n");
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
    fprintf (stderr, "HybridCuts [-b bucketSize][-s spfac][-t threshold(assume T_SA=T_DA)][-r ruleset]\n");
    fprintf (stderr, "Type \"HybridCuts -h\" for help\n");
    exit(1);
     }

   printf("****************HybridCuts: version 2.0, 2013-12-25***********************\n");
   printf("Bucket Size =  %d\n", bucketSize);
   printf("Space Factor = %.2f\n", spfac);  
   printf("Threshold = %d,%d\n", threshold,threshold);  
}

//**********Function: dump rules or rule set*************************************
void dump_rule(pc_rule *rule, int rule_id)
{
	int	 i;
	pc_rule	 *p = &rule[rule_id];
	range    r;

	printf("rule[%d]:\t", rule_id);

	// dump SIP & DIP
	for (i = 0; i < 2; i++) {
		r = p->field[i];
		if (r.low == r.high) 
			dump_ip(r.low);
		else if (r.low == 0 && r.high == 0xffffffff)
			printf("*");
		else {
			dump_ip(r.low);
			printf("/%d", log2(r.high-r.low+1));
		}
		printf(",\t");
	}

	// dump SP & DP
	for (i = 2; i < 4; i++) {
		r = p->field[i];
		if (r.low == r.high) 
			printf("%x", r.low);
		else if (r.low == 0 && r.high == 0xffff)
			printf("*");
		else {
			printf("[%x-%x]", r.low, r.high);
		}
		printf(",  ");
	}

	// dump proto
	r = p->field[4];
	if (r.low == r.high)
		printf("%d", r.low);
	else if (r.low == 0 && r.high == 0xff)
		printf("*");
	else
		printf("[%d-%d]", r.low, r.high);

	printf("\n");
}

void dump_ruleset(pc_rule *rule, int num)
{
  for (int i = 0; i < num; i++)
      dump_rule(rule,i);
  printf("\n");
}


//***********Function: record length of field and correponding size**************
void count_length(int number_rule,pc_rule *rule,field_length *field_length_ruleset)
{
   unsigned temp_size=0;
   unsigned temp_value=0;
   unsigned temp0=0;

   for(int i=0;i<number_rule;i++)
       {
       for(int j=0;j<5;j++)  //record field length in field_length_ruleset[i]
           {
          field_length_ruleset[i].length[j]=rule[i].field[j].high-rule[i].field[j].low;    
          if(field_length_ruleset[i].length[j]==0xffffffff)
             field_length_ruleset[i].size[j]=32; //for address*, since length int is also 32
          else 
             {
             temp_size=0;
             temp_value=field_length_ruleset[i].length[j]+1;
             while((temp_value=temp_value/2)!=0)
                temp_size++;  

              //the following code is used for port number 
             temp0=pow(2,temp_size);
             temp0=field_length_ruleset[i].length[j]+1-temp0;
             if(temp0!=0)
               temp_size++; 

             field_length_ruleset[i].size[j]=temp_size;
               }
            }

       double temp_value[4]={
                            (double)field_length_ruleset[i].size[0]/32,
                            (double)field_length_ruleset[i].size[1]/32,
                            (double)field_length_ruleset[i].size[2]/16,
                            (double)field_length_ruleset[i].size[3]/16
                            }; //for fair comparasion 

      int index_max=3;
      int index_min=0;
      for(int t=0;t<4;t++){ //find the biggest and smallest filed   
         if(temp_value[index_min]>temp_value[t])
            index_min=t;
         if(temp_value[index_max]<temp_value[t])
            index_max=t;}

        int index_min_second=0;
        if(index_min_second==index_min)
           index_min_second++;
        if(index_min_second==index_max)
           index_min_second++;
        if(index_min_second==index_min)
           index_min_second++;//can not be ingore

      for(int t=0;t<4;t++){ //find the second small fiels
         if((temp_value[index_min_second]>temp_value[t])&&(t!=index_min)&&(t!=index_max))
            index_min_second=t;}

      int index_min_third=6-index_min-index_min_second-index_max;

      field_length_ruleset[i].flag_smallest[0]=index_min;
      field_length_ruleset[i].flag_smallest[1]=index_min_second;
      field_length_ruleset[i].flag_smallest[2]=index_min_third;
      field_length_ruleset[i].flag_smallest[3]=index_max; 
      }

     //-------------flag2: used for test--------------------
     /*   
      printf("field length of each rule:\n");
      for(int i=0;i<number_rule;i++){
         printf("No%d--",i);
         for(int j=0;j<5;j++)
            printf("%u\t",field_length_ruleset[i].length[j]);
         printf("\n");
          }
     */
     /*
      printf("field length size of each rule:\n");
      for(int i=0;i<number_rule;i++){
         printf("No%d--",i);
         for(int j=0;j<5;j++)
            printf("%d\t",field_length_ruleset[i].size[j]);
         printf("\n");
          }
      */
     /*
      printf("field length rank:\n");
      for(int i=0;i<number_rule;i++){
         printf("No%d--",i);
         for(int j=0;j<4;j++)
            printf("%d\t",field_length_ruleset[i].flag_smallest[j]);
         printf("\n");
          }
     */
   //--------------used for test:flag2---------------------
}


//*************Function: print percentage value change with T(t1,t2,t3,t4)***************
void percentage_5(field_length *field_length_ruleset,int number_rule,int* num_small[33],int* num_small_counter[33])
{
    int ip=32;
    int port=16;
    int threshold[33][4];
    for(int i=0;i<33;i++,ip--)
        {
        threshold[i][0]=ip;
        threshold[i][1]=ip;
        if((ip%2)==0) 
            {
           threshold[i][2]=ip/2;
           threshold[i][3]=ip/2;  
            }
        else
            {
           threshold[i][2]=ip/2+1;
           threshold[i][3]=ip/2+1; 
            }
         }  //T from（32，32，16，16）to（0，0，0，0）     
  
    //-------------flag3: used for test--------------------
    /*
    printf("threshold from（32，32，16，16）to（0，0，0，0）:\n");
    for(int i=0;i<33;i++)
         {
        for(int j=0;j<4;j++)
           printf("%d\t",threshold[i][j]);
        printf("\n");
         }
    */ 
   //--------------used for test:flag3---------------------

  //record number of each subset and number of small fields in each rule
   for(int i=0;i<33;i++)
       {   
      for(int j=0;j<5;j++)
         num_small_counter[i][j]=0; 
        
      for(int j=0;j<number_rule;j++)
          {
         num_small[i][j]=0; 
         for(int k=0;k<4;k++)
           if(field_length_ruleset[j].size[k]<=threshold[i][k]) 
              num_small[i][j]++;                 
         for(int r=0;r<5;r++)
            if(num_small[i][j]==r)
               num_small_counter[i][r]++;
          }      
       }

    //-------------flag4: used for test and print the result--------------------
    /* 
     for(int i=0;i<33;i++)
        {
        printf("No %d\n",i);
        printf("Total number of rules:%d\n",number_rule);
        printf("threshold value:");  
        for(int k=0;k<4;k++)
           printf("%d\t",threshold[i][k]);  
        printf("\n"); 
        printf("None small field(BIG RULE):%d,      \t about %f%%\n",num_small_counter[i][0],(double)num_small_counter[i][0]*100/number_rule);
        printf("At least one small field(SMALL RULE):%d, \t about %f%%\n",number_rule-num_small_counter[i][0],100-(double)num_small_counter[i][0]*100/number_rule);
   //   printf("Only one small field:%d,\t about %f%%\n",num_small_counter[i][1],(double)num_small_counter[i][1]*100/number_rule);
   //   printf("Two small fields:%d,    \t about %f%%\n",num_small_counter[i][2],(double)num_small_counter[i][2]*100/number_rule);
   //   printf("Three small fields:%d,  \t about %f%%\n",num_small_counter[i][3],(double)num_small_counter[i][3]*100/number_rule);
   //   printf("Four small fields:%d,   \t about %f%%\n",num_small_counter[i][4],(double)num_small_counter[i][4]*100/number_rule);
        }
    */   
    //-------------used for test and print the result:flag4--------------------

}


//*************Function: print percentage value change with T(t1,t2)***************
void percentage_3(field_length *field_length_ruleset,int number_rule,int* num_small[33],int* num_small_counter[33])
{
    int ip=32;
    int threshold[33][2];
    for(int i=0;i<33;i++,ip--)
        {
        threshold[i][0]=ip;
        threshold[i][1]=ip;
        }   
  
    //-------------flag5: used for test--------------------
    /*
    printf("threshold from（32，32）to（0，0）:\n");
    for(int i=0;i<33;i++)
         {
        for(int j=0;j<2;j++)
           printf("%d\t",threshold[i][j]);
        printf("\n");
         } 
    */ 
   //--------------used for test:flag5---------------------
   

   for(int i=0;i<33;i++)
       {   
      for(int j=0;j<3;j++)
         num_small_counter[i][j]=0; 
        
      for(int j=0;j<number_rule;j++)
          {
         num_small[i][j]=0;  
         for(int k=0;k<2;k++)
            if(field_length_ruleset[j].size[k]<=threshold[i][k]) 
               num_small[i][j]++;                 
         for(int r=0;r<3;r++)
            if(num_small[i][j]==r)
               num_small_counter[i][r]++;
          }      
       }

    //-------------flag6: used for test and print the result--------------------
    /*          
     for(int i=0;i<33;i++)
         {
        printf("No %d\n",i);
        printf("Total number of rules:%d\n",number_rule);
        printf("threshold value:");  
        for(int k=0;k<2;k++)
           printf("%d\t",threshold[i][k]);  
        printf("\n"); 
        printf("None small field(BIG RULE):%d,      \t about %f%%\n",num_small_counter[i][0],(double)num_small_counter[i][0]*100/number_rule);
        printf("At least one small field(SMALL RULE):%d, \t about %f%%\n",number_rule-num_small_counter[i][0],100-(double)num_small_counter[i][0]*100/number_rule);
     // printf("Only one small field:%d,\t about %f%%\n",num_small_counter[i][1],(double)num_small_counter[i][1]*100/number_rule);
     // printf("Two small fields:%d,    \t about %f%%\n",num_small_counter[i][2],(double)num_small_counter[i][2]*100/number_rule);
         }
    */
    //-------------used for test and print the result:flag6--------------------
}


//****Function:*******partition ruleset into each field subset*********2 dim****
void partition_3(pc_rule *rule,pc_rule* subset[3],int num_subset[3],int number_rule,field_length *field_length_ruleset,int *num_small_tmp,int threshold_value[2])
{
  int count0=0; 
  for(int i=0;i<number_rule;i++)
     if(num_small_tmp[i]==0)
        subset[0][count0++]=rule[i];
  num_subset[0]=count0;

  int count1=0;
  int count2=0;
  for(int i=0;i<number_rule;i++){

      if((count0<=bucketSize)&&(num_small_tmp[i]==0)){
         if((rule[i].field[0].high-rule[i].field[0].low)<(rule[i].field[1].high-rule[i].field[1].low))
            subset[1][count1++]=rule[i];
         else
            subset[2][count2++]=rule[i];
        }
      if((num_small_tmp[i]==1)&&(field_length_ruleset[i].size[0]<=threshold_value[0]))
         subset[1][count1++]=rule[i];      
      if((num_small_tmp[i]==1)&&(field_length_ruleset[i].size[1]<=threshold_value[1]))
         subset[2][count2++]=rule[i];

/////////////////////////////////
/*

      if(num_small_tmp[i]==2)
          {
         if(count1<=count2)
            subset[1][count1++]=rule[i];
         else
            subset[2][count2++]=rule[i];
          }
       }
*/
///////////////////////////////////

      if(num_small_tmp[i]==2)
        {
         if(field_length_ruleset[i].size[0]<field_length_ruleset[i].size[1])
            subset[1][count1++]=rule[i];
         else if(field_length_ruleset[i].size[0]>field_length_ruleset[i].size[1])
            subset[2][count2++]=rule[i];     
         else if(count1<=count2)  
            subset[1][count1++]=rule[i];
         else
            subset[2][count2++]=rule[i];
         }
      } 

////////////////////////////////////

   num_subset[1]=count1; 
   num_subset[2]=count2;
   if(count0>bucketSize)
     printf("Big_subset:%d\tSa_subset:%d\tDa_subset:%d\n",count0,count1,count2);
   if(count0<=bucketSize){
     printf("Big tree is merged!\n");
     printf("Sa_subset:%d\tDa_subset:%d\n",count1,count2);
     }
}


//****Function:*******partition ruleset into each field subset*********2 dim****
void partition_2(pc_rule *rule,pc_rule* subset[3],int num_subset[3],int number_rule,field_length *field_length_ruleset,int *num_small_tmp,int threshold_value[2])
{
  int count0=0;  
  for(int i=0;i<number_rule;i++)
     if(num_small_tmp[i]==0)
        subset[0][count0++]=rule[i];
  num_subset[0]=count0;

  int count1=0;
  int count2=0;
  int count1_tmp=0; 
  int count2_tmp=0; 



  int index[number_rule];
  int index_con=0;
  list<range> element_SA; 
  element_SA.clear();     
  list<range> element_DA;    
  element_SA.clear(); 
  range check;
  int same1=0;
  int same2=0;
  int n1=pow(2,20);
  int n2=pow(2,12);
  int* sa;
  sa=(int*)calloc(n1,sizeof(int)); 
  int* da;
  da=(int*)calloc(n1,sizeof(int)); 

  for(int i=0;i<n1;i++)
     {
     sa[i]=0;da[i]=0;}
     int index_sa=0;
     int index_da=0;
     int index_low=0;
     int index_high=0;
     int cnum=0;
     int flag=0;
     int sum1=0;
     int sum2=0;
  
  //a new partition method
  for(int i=0;i<number_rule;i++)
      {
      if((count0<=8)&&num_small_tmp[i]==0)
        {
        if((rule[i].field[0].high-rule[i].field[0].low)<(rule[i].field[1].high-rule[i].field[1].low))
          {
           index_low=rule[i].field[0].low/n2;
           index_high=rule[i].field[0].high/n2;
           cnum=index_high-index_low;

           if(cnum>1)
             {
              for(int y=0;y<cnum+1;y++)
                 sa[index_low+y]++;
             }
           else{
                index_sa=rule[i].field[0].low/n2;
                sa[index_sa]++;
               }
           subset[1][count1_tmp++]=rule[i];
           }
     else{
          index_low=rule[i].field[1].low/n2;
          index_high=rule[i].field[1].high/n2;
          cnum=index_high-index_low;

          if(cnum>1)
            {
             for(int y=0;y<cnum+1;y++)
                da[index_low+y]++;
            }
          else{
               index_da=rule[i].field[1].low/n2;
               da[index_da]++;
               }

         subset[2][count2_tmp++]=rule[i];
         }
     }

      index_sa=0;
      index_da=0;
      sum1=0;
      sum2=0;
      flag=0;
      cnum=0;
      index_high=0;
      index_low=0;

      if((num_small_tmp[i]==1)&&(field_length_ruleset[i].size[0]<=threshold_value[0]))
        {
        index_low=rule[i].field[0].low/n2;
        index_high=rule[i].field[0].high/n2;
        cnum=index_high-index_low;

        if(cnum>1)
           {
            for(int y=0;y<cnum+1;y++)
               sa[index_low+y]++;
           }
        else{
            index_sa=rule[i].field[0].low/n2;
            sa[index_sa]++;
            }
    
          subset[1][count1_tmp++]=rule[i];   
         }

      if((num_small_tmp[i]==1)&&(field_length_ruleset[i].size[1]<=threshold_value[1])) 
         {
         index_low=rule[i].field[1].low/n2;
         index_high=rule[i].field[1].high/n2;
         cnum=index_high-index_low;

         if(cnum>1)
            {
             for(int y=0;y<cnum+1;y++)
               da[index_low+y]++;
            }
         else{
             index_da=rule[i].field[1].low/n2;
             da[index_da]++;
             }

          subset[2][count2_tmp++]=rule[i];
         }
      }

   for(int i=0;i<number_rule;i++)
      {
      index_sa=0;
      index_da=0;
      sum1=0;
      sum2=0;
      flag=0;
      cnum=0;
      index_high=0;
      index_low=0;

      if(num_small_tmp[i]==2)
        {
        index_low=rule[i].field[0].low/n2;
        index_high=rule[i].field[0].high/n2;
        cnum=index_high-index_low;
        
        for(int e=0;e<=cnum;e++)
            {
             if(sa[index_low+e]>bucketSize)
             sum1++;
            }

        index_low=rule[i].field[1].low/n2;
        index_high=rule[i].field[1].high/n2;
        cnum=index_high-index_low;
        for(int e=0;e<=cnum;e++)
            {
             if(da[index_low+e]>bucketSize)
             sum2++;
            }
 
        if(sum1<sum2)
          { 
          index_low=rule[i].field[0].low/n2;
          index_high=rule[i].field[0].high/n2;
          cnum=index_high-index_low;

          if(cnum>1)
             {
             for(int y=0;y<cnum+1;y++)
                sa[index_low+y]++;
             }
           else{
               index_sa=rule[i].field[0].low/n2;
               sa[index_sa]++;
               }
    
           subset[1][count1_tmp++]=rule[i];  
           }
        else if(sum1>sum2)
            {
            index_low=rule[i].field[1].low/n2;
            index_high=rule[i].field[1].high/n2;
            cnum=index_high-index_low;

            if(cnum>1)
              {
               for(int y=0;y<cnum+1;y++)
                 da[index_low+y]++;
              }
            else{
                 index_da=rule[i].field[1].low/n2;
                 da[index_da]++;
                 }

            subset[2][count2_tmp++]=rule[i];
            } 
        else 
            {
             if(count1_tmp<=count2_tmp)
               {
               index_low=rule[i].field[0].low/n2;
               index_high=rule[i].field[0].high/n2;
               cnum=index_high-index_low;

               if(cnum>1)
                 {
                 for(int y=0;y<cnum+1;y++)
                    sa[index_low+y]++;
                 }
                else{
                    index_sa=rule[i].field[0].low/n2;
                    sa[index_sa]++;
                    }
    
                subset[1][count1_tmp++]=rule[i];  
                }
              else
                 {
                 index_low=rule[i].field[1].low/n2;
                 index_high=rule[i].field[1].high/n2;
                 cnum=index_high-index_low;

                 if(cnum>1)
                    {
                     for(int y=0;y<cnum+1;y++)
                        da[index_low+y]++;
                     }
                 else{
                     index_da=rule[i].field[1].low/n2;
                     da[index_da]++;
                     }

                 subset[2][count2_tmp++]=rule[i];
                 }
              }
        }
     }

   count1=count1_tmp;
   count2=count2_tmp; 
   num_subset[1]=count1; 
   num_subset[2]=count2;
   if(count0>bucketSize)
     printf("Big_subset:%d\tSa_subset:%d\tDa_subset:%d\n",count0,count1,count2);
   if(count0<=bucketSize){
     printf("Big tree is merged!\n");
     printf("Sa_subset:%d\tDa_subset:%d\n",count1,count2);
     }

}


int main(int argc, char* argv[])
{
  pc_rule *rule;  
  int number_rule=0;
  parseargs(argc, argv); 
  char test1;
  while((test1=fgetc(fpr))!=EOF)
    if(test1=='@')
       number_rule++;   
  rewind(fpr); 
  rule = (pc_rule *)calloc(number_rule, sizeof(pc_rule)); 
  number_rule=loadrule(fpr,rule);
  printf("the number of rules = %d\n", number_rule);
  fclose(fpr);
  //dump_ruleset(rule,number_rule);


  field_length field_length_ruleset[number_rule]; 
  count_length(number_rule,rule,field_length_ruleset);
  
  int* num_small_5[33]; 
  int* num_small_3[33];
  int* num_small_counter_5[33]; 
  int* num_small_counter_3[33];
  for(int i=0;i<33;i++) 
      {
      num_small_5[i]=(int *)calloc(number_rule, sizeof(int)); 
      num_small_3[i]=(int *)calloc(number_rule, sizeof(int)); 
      num_small_counter_5[i]=(int *)calloc(5,sizeof(int));  
      num_small_counter_3[i]=(int *)calloc(3,sizeof(int));  
      }

    percentage_5(field_length_ruleset,number_rule,num_small_5,num_small_counter_5);
    percentage_3(field_length_ruleset,number_rule,num_small_3,num_small_counter_3);



  pc_rule* subset_3[3];  
  for(int n=0;n<3;n++)
      subset_3[n]=(pc_rule *)malloc(number_rule*sizeof(pc_rule)); 
  int num_subset_3[3]={0,0,0};  
  int num_small_tmp_3[number_rule];
  for(int i=0;i<number_rule;i++)   
     num_small_tmp_3[i]=num_small_3[32-threshold][i];
  int threshold_value_3[2]={threshold,threshold};
  
  // partition_3(rule,subset_3,num_subset_3,number_rule,field_length_ruleset,num_small_tmp_3,threshold_value_3);
  

   partition_2(rule,subset_3,num_subset_3,number_rule,field_length_ruleset,num_small_tmp_3,threshold_value_3);
   //-------------used for test and print the result:flag7--------------------
   /*
   printf("***********************big_ruleset*******************************************\n");
        if(num_subset_3[0]!=0)
           dump_ruleset(subset_3[0],num_subset_3[0]);
        else
           printf("empty!\n");
        if(num_subset_3[0]>0&&num_subset_3[0]<=bucketSize)
           printf("Big tree will be merged!\n");
   printf("***********************SA_ruleset**********************************************\n");
        dump_ruleset(subset_3[1],num_subset_3[1]);
   printf("***********************DA_ruleset***********************************************\n");
        dump_ruleset(subset_3[2],num_subset_3[2]);
   */
   //-------------used for test and print the result:flag7--------------------

   trie T(num_subset_3[1],bucketSize,spfac,subset_3[1],0);
   trie T1(num_subset_3[2],bucketSize,spfac,subset_3[2],1);
   trie T2(num_subset_3[0],bucketSize,spfac,subset_3[0],5);

   int OVERALL_DEPTH=0;
   if(T.max_depth>OVERALL_DEPTH)
     OVERALL_DEPTH=T.max_depth;
   if(T1.max_depth>OVERALL_DEPTH)
     OVERALL_DEPTH=T1.max_depth;
   if(num_subset_3[0]>bucketSize && T2.max_depth>OVERALL_DEPTH)
     OVERALL_DEPTH=T2.max_depth;

   int OVERALL_LEVELS=0;
   if(T.pass>OVERALL_LEVELS)
     OVERALL_LEVELS=T.pass;
   if(T1.pass>OVERALL_LEVELS)
     OVERALL_LEVELS=T1.pass;
   if(num_subset_3[0]>bucketSize && T2.pass>OVERALL_LEVELS)
     OVERALL_LEVELS=T2.pass;

   printf("****************************************************************************\n");
   if(num_subset_3[0]>bucketSize){
     printf("OVERALL_MEMORY(KB)=%d\n",T.total_memory_in_KB+T1.total_memory_in_KB+T2.total_memory_in_KB);
     printf("OVERALL_DEPTH:%d\n",OVERALL_DEPTH);
     printf("OVERALL_LEVELS:%d\n",OVERALL_LEVELS);
     }
   else{
      printf("OVERALL_MEMORY(KB)=%d\n",T.total_memory_in_KB+T1.total_memory_in_KB);
      printf("OVERALL_DEPTH:%d\n",OVERALL_DEPTH);
      printf("OVERALL_LEVELS:%d\n",OVERALL_LEVELS);
      }
   printf("****************************************************************************\n");
}
