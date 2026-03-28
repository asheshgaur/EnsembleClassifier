#include "stdinc.h"
#include <stdio.h>
#include <stdlib.h>
#include<queue>
#include<list>
#include<math.h>
#include"HybridCuts.h"
#include "trie.h"

using namespace std;

trie::trie(int numrules1, int binth1, float spfac1, pc_rule* rule1,int k1) 
{
   numrules = numrules1;  
   binth = binth1;
   spfac = spfac1;
   rule = rule1;
   k=k1;
   nodeSet = new nodeItem[MAXNODES+1]; 
   root = 1;  
   freelist = 2;	
   n2=0; 
   pass=0;
   spfacFiCuts=spfac1;//spfacFiCuts just used for FiCuts  
   max_depth=0;

   Total_Rule_Size=0;
   Total_Array_Size=0;
   Leaf_Node_Count=0;
   NonLeaf_Node_Count=0;

   for(int i=1; i<=MAXNODES; i++) 
      nodeSet[i].child = (int*)malloc(sizeof(int)); 

   nodeSet[root].isleaf = 0;
   nodeSet[root].nrules = numrules;

   for (int i=0; i<MAXDIMENSIONS; i++) 
        {
        nodeSet[root].field[i].low = 0;
        if(i<2)
           nodeSet[root].field[i].high = 0xffffffff;
        else if(i==4) 
           nodeSet[root].field[i].high = 255;
        else 
           nodeSet[root].field[i].high = 65535; 
        }
  nodeSet[root].ruleid = (int*)calloc(numrules, sizeof(int));
  for(int i=0; i< numrules; i++) 
      nodeSet[root].ruleid[i] = i;

  nodeSet[root].ncuts = 0;
  nodeSet[root].layNo = 0;
  nodeSet[root].flag = 1;
  if(k==5) nodeSet[root].flag==2;
	

  for (int i = 2; i < MAXNODES; i++) 
     nodeSet[i].child[0] = i+1;
  nodeSet[MAXNODES].child[0] = Null;
 
  createtrie();


  for(int i=1; i<=MAXNODES; i++) 
     free(nodeSet[i].child);
  delete [] nodeSet;
}

//count np in FiCuts stage
int trie::count_np(nodeItem *v)
{
   int np=0;  
   int done=0;
   int sm=0;
   int nump=0; 
   int *nr;   
   nr=(int *)malloc(sizeof(int));
   int lo,hi,r; 

   if(v->field[k].high == v->field[k].low)
      nump=1;
   else
      nump=2;
     
   while(!done)
         {
        sm=0;
        nr = (int*)realloc(nr, nump*sizeof(int));
        for(int i=0; i<nump; i++) 
            nr[i]=0;  
        for(int j=0; j<v->nrules; j++)
             {
            r = (v->field[k].high - v->field[k].low)/nump;
            lo = v->field[k].low;
            hi = lo + r;

            for(int i=0; i<nump; i++){ 
                if(rule[v->ruleid[j]].field[k].low >=lo && rule[v->ruleid[j]].field[k].low <=hi ||
                   rule[v->ruleid[j]].field[k].high>=lo && rule[v->ruleid[j]].field[k].high<=hi ||
                   rule[v->ruleid[j]].field[k].low <=lo && rule[v->ruleid[j]].field[k].high>=hi){
                   sm++;
                   nr[i]++;
                     }	 
                lo = hi + 1;
                hi = lo + r;
                  }
              }
  
        sm+=nump;
        if(sm < (int)(spfacFiCuts*v->nrules) && nump<= MAXCUTS/2 && nump < (v->field[k].high - v->field[k].low))
           nump=nump*2;
        else
           done=1; 
         }
    np=nump;
    return np; 
}

//choose dim and count cuts in hypercut stage
void trie::choose_np_dim(nodeItem *v){
   int nc[MAXDIMENSIONS];  //number of cuts in each field
   int done;
   int *nr[MAXDIMENSIONS];      //number of rules in each child
   int unique_elements[MAXDIMENSIONS];
   double average = 0;
   range check;
   int lo,hi,r;
   int Nr=0;
   int NC=0;
   int maxnc, minnc;
   int flag=1; 

   //v->child=(int *)malloc(sizeof(int));

   for(int k=0; k<MAXDIMENSIONS; k++)
       nr[k]=(int *)malloc(sizeof(int));

  //count the unique components on each dimension
   for(int k=0; k<MAXDIMENSIONS; k++){ //the start of first for() 
      list<range> element_list;    //unique element list 
      element_list.clear();
      unique_elements[k]=0;  
      for(int i = 0; i<v->nrules; i++){//the start of second for() 
          int found=0;
          if(rule[v->ruleid[i]].field[k].low > v->field[k].low) 
             check.low = rule[v->ruleid[i]].field[k].low;
          else
             check.low = v->field[k].low;

          if(rule[v->ruleid[i]].field[k].high < v->field[k].high) 
             check.low = rule[v->ruleid[i]].field[k].high;
          else
             check.low = v->field[k].high;

          for (list <range>::iterator range=element_list.begin();range != element_list.end();++range)
               if(check.low == (*range).low && check.high == (*range).high){
                 found=1;
                 break;
                   }

          if(!found){
             element_list.push_back(check);
             unique_elements[k]++;
               }
        
           } //the end of second for()  

      unique_elements[k] = element_list.size();   

       //printf("%d\t",unique_elements[k]);  //for test
     }//the end of first for()  

  //choose the set of dimensions to cut
   int dims_cnt = 0;
   for(int k = 0;k < MAXDIMENSIONS;k++)
       {
       if(v->field[k].high > v->field[k].low)
          {
         average += unique_elements[k];
         dims_cnt++;
          }
       }
   average = average / dims_cnt;

   for (int k = 0;k < MAXDIMENSIONS;++k){
       v->select_dim[k] = 0;
       if (v->field[k].high > v->field[k].low && unique_elements[k] >= average){
           v->select_dim[k] = 1;
           nc[k] = 2;
            }
       else{
           v->select_dim[k] = 0;
           nc[k] = 1;
             }
        }

  
  //choose the number of cuts
   for(int k=0; k<MAXDIMENSIONS; k++){
      if(v->select_dim[k] == 1){
         done = 0; 
         while(!done){
               nr[k] = (int *)realloc(nr[k], nc[k]*sizeof(int));
               for(int i=0; i<nc[k]; i++) 
                   nr[k][i]=0;

               for(int j=0; j<v->nrules; j++){
                   r = (v->field[k].high - v->field[k].low)/nc[k];
                   lo = v->field[k].low;
                   hi = lo + r;

                   for(int i=0; i<nc[k]; i++){
                      if(rule[v->ruleid[j]].field[k].low <=hi && rule[v->ruleid[j]].field[k].high >=lo)
                         nr[k][i]++; 	
 
                      lo = hi + 1;
                      hi = lo + r;
                         }
                      }

               Nr = nc[k];
               for(int i=0; i<nc[k]; i++) 
                   Nr += nr[k][i]; 

               if(Nr < spfac * v->nrules && v->field[k].high - v->field[k].low > nc[k] && nc[k] <= MAXCUTS1/2) 
	           nc[k] = nc[k]*2;
	        else 
	           done = 1;

               } //the end of while(!done)
          }//the end of if(v->dim[k] == 1)
      }//the end of for()
 
   NC = 1;	
   for(int k=0; k<MAXDIMENSIONS; k++) 
      if(v->select_dim[k] == 1) 
         NC = NC * nc[k];

   while(NC > 2*spfac * sqrt(v->nrules) || NC > MAXCUTS1 ){ 
        maxnc = 0;
        minnc = MAXCUTS1+1;

        for(int k=0; k<MAXDIMENSIONS; k++){
           if(v->select_dim[k] == 1){ 
              if(maxnc < nc[k]) maxnc = nc[k];
              if(minnc > nc[k]) minnc = nc[k];
                }
             }  

        for(int k=MAXDIMENSIONS-1; k>=0; k--){
           if(v->select_dim[k] == 1){
               if(flag == 1 && minnc == nc[k]){
                  nc[k] = nc[k]/2;
                  if(nc[k] == 1) v->select_dim[k] = 0;
                  break;
                    }
               else if(flag == 0 && maxnc == nc[k]){
                      nc[k] = nc[k]/2;
                      if(nc[k] == 1) 
                      v->select_dim[k] = 0;
                      break;
                         }
                 } 
             }

       NC = 1;	
       for(int k=0; k<MAXDIMENSIONS; k++) 
           if(v->select_dim[k] == 1) 
             NC = NC * nc[k];

       if(flag == 1) 
          flag = 0;
       else 
          flag = 1;

       }//the end of while()


   for(int k=0; k<MAXDIMENSIONS; k++){
       if(v->select_dim[k] == 1)
          v->ncuts2[k] = nc[k];
       else 
          v->ncuts2[k] = 1;
        }

   v->child = (int *)realloc(v->child, NC*sizeof(int));

} 


//remove redundancy by covering
void trie::remove_redundancy(nodeItem *v)
{	
   int cover;
   int tmp, tmp2;
  
   if(v->nrules == 1) return;
  
   tmp = v->nrules -1;
   tmp2 = v->nrules -2;
   while(tmp >= 1){
     for(int i = tmp2; i >= 0; i--)
         {
        for(int k= 0; k < MAXDIMENSIONS; k++){
            cover = 1;
            if(max(rule[v->ruleid[i]].field[k].low, v->field[k].low) > max(rule[v->ruleid[tmp]].field[k].low, v->field[k].low) ||
               min(rule[v->ruleid[i]].field[k].high,v->field[k].high)< min(rule[v->ruleid[tmp]].field[k].high,v->field[k].high)){
               cover = 0;
               break;
                 }
             }//the end of the second for();	
         if(cover == 1){     	
             for(int j = tmp; j < v->nrules-1; j++)
      	          v->ruleid[j] = v->ruleid[j+1]; 	
             v->nrules --;
            // Total_Rule_Size++;//wo jia jin qu de 
      	      n2++;
             break;
               }
         } //the end of the first for();	
     tmp --;
     tmp2 --;
     } //the end of while();	                         		
}


void trie::move_up(nodeItem *v){
  int i, j;
  int index = 0;
  int cover = 0;
  
  for(int i = 0; i < v->nrules; i++){
     if(cover == 1) i--;
     cover = 1;

     for(int k=0; k < MAXDIMENSIONS; k++){
        if(v->select_dim[k] == 1){
           if(rule[v->ruleid[i]].field[k].low > v->field[k].low ||
      	      rule[v->ruleid[i]].field[k].high < v->field[k].high){
      	      cover = 0;
      	      break;
      	      }
           }
      }
      if(cover == 1){
         v->rulelist = (int *)realloc(v->rulelist, (index+1)*sizeof(int));
         v->rulelist[index] = v->ruleid[i];
      
         for(int j = i+1; j < v->nrules; j++) 
              v->ruleid[j-1] = v->ruleid[j];
            
         v->nrules --;
         index ++;
        }
  }
}


void trie::regionCompaction(nodeItem *v) { 
   list<unsigned int> f0, f1, f2, f3, f4; 

 
   for (int i=0;i<v->nrules;i++){

       if(rule[v->ruleid[i]].field[0].low < v->field[0].low) 
          f0.push_back(v->field[0].low);
       else  
          f0.push_back(rule[v->ruleid[i]].field[0].low);
       if(rule[v->ruleid[i]].field[0].high > v->field[0].high)
          f0.push_back(v->field[0].high);
       else
          f0.push_back(rule[v->ruleid[i]].field[0].high);


       if(rule[v->ruleid[i]].field[1].low < v->field[1].low) 
          f1.push_back(v->field[1].low);
       else  
          f1.push_back(rule[v->ruleid[i]].field[1].low);
       if(rule[v->ruleid[i]].field[1].high > v->field[1].high)
          f1.push_back(v->field[1].high);
       else
          f1.push_back(rule[v->ruleid[i]].field[1].high);


       if(rule[v->ruleid[i]].field[2].low < v->field[2].low) 
          f2.push_back(v->field[2].low);
       else  
          f2.push_back(rule[v->ruleid[i]].field[2].low);
       if(rule[v->ruleid[i]].field[2].high > v->field[2].high)
          f2.push_back(v->field[2].high);
       else
          f2.push_back(rule[v->ruleid[i]].field[2].high);


       if(rule[v->ruleid[i]].field[3].low < v->field[3].low) 
          f3.push_back(v->field[3].low);
       else  
          f3.push_back(rule[v->ruleid[i]].field[3].low);
       if(rule[v->ruleid[i]].field[3].high > v->field[3].high)
          f3.push_back(v->field[3].high);
       else
          f3.push_back(rule[v->ruleid[i]].field[3].high);


       if(rule[v->ruleid[i]].field[4].low < v->field[4].low) 
          f4.push_back(v->field[4].low);
       else  
          f4.push_back(rule[v->ruleid[i]].field[4].low);
       if(rule[v->ruleid[i]].field[4].high > v->field[4].high)
          f4.push_back(v->field[4].high);
       else
          f4.push_back(rule[v->ruleid[i]].field[4].high);

       }

   f0.sort();
   f1.sort();
   f2.sort();
   f3.sort();
   f4.sort();
   v->field[0].low = f0.front();
   v->field[0].high = f0.back();
   v->field[1].low = f1.front();
   v->field[1].high = f1.back();
   v->field[2].low = f2.front();
   v->field[2].high = f2.back();
   v->field[3].low = f3.front();
   v->field[3].high = f3.back();
   v->field[4].low = f4.front();
   v->field[4].high = f4.back();
//printf("v->field[0].low=%u\tv->field[0].high=%u\n",v->field[0].low,v->field[0].high );
}




void trie::createtrie()
{ 
   int v=0;
   int np=0; 
   int nr;
   int empty;
   int flag1;
   int r1, lo1, hi1;
   int r[MAXDIMENSIONS], lo[MAXDIMENSIONS], hi[MAXDIMENSIONS];
   int i[MAXDIMENSIONS];
   int u; 
   int index;
 
   qNode.push(root);

   while(!qNode.empty()) 
   {
   v=qNode.front();  
   regionCompaction(&nodeSet[v]);
   qNode.pop();    
    remove_redundancy(&nodeSet[v]);


   if(nodeSet[v].flag==1){      
     np=count_np(&nodeSet[v]);
     if(np<MAXCUTS) 
        nodeSet[v].flag=2;   
      }



   if(nodeSet[v].flag==1) //FiCuts stage
      {    
      if(nodeSet[v].nrules <= binth){
        nodeSet[v].isleaf = 1;
        Total_Rule_Size+= nodeSet[v].nrules;
        Leaf_Node_Count++;

        if(max_depth<(nodeSet[v].layNo+nodeSet[v].nrules))
           max_depth=nodeSet[v].layNo+nodeSet[v].nrules;

        }
      else if(np==1)
          {
           nodeSet[v].isleaf = 1;
           Total_Rule_Size+= nodeSet[v].nrules;
           Leaf_Node_Count++;


           if(max_depth<(nodeSet[v].layNo+nodeSet[v].nrules))       
              max_depth=nodeSet[v].layNo+nodeSet[v].nrules;

           } 
      else{  //the start of the big else()
          NonLeaf_Node_Count++;
          nodeSet[v].ncuts = np;
          nodeSet[v].child = (int *)realloc(nodeSet[v].child, nodeSet[v].ncuts * sizeof(int));

          r1 = (nodeSet[v].field[k].high - nodeSet[v].field[k].low)/nodeSet[v].ncuts;
          lo1 = nodeSet[v].field[k].low;
          hi1 = lo1 + r1;

          for(int i = 0; i < nodeSet[v].ncuts; i++){ //the start of the first for()
	       empty = 1;
	       nr = 0;
              for(int j=0; j<nodeSet[v].nrules; j++){
                 if(rule[nodeSet[v].ruleid[j]].field[k].low >=lo1 && rule[nodeSet[v].ruleid[j]].field[k].low <=hi1 ||
                    rule[nodeSet[v].ruleid[j]].field[k].high>=lo1 && rule[nodeSet[v].ruleid[j]].field[k].high<=hi1 ||
                    rule[nodeSet[v].ruleid[j]].field[k].low <=lo1 && rule[nodeSet[v].ruleid[j]].field[k].high>=hi1){
                    empty = 0;
                    nr++;  
                       }
                    }

              if(!empty){
                 Total_Array_Size++;
                 nodeSet[v].child[i] = freelist; 
                 u=freelist;
                 freelist++;
                 nodeSet[u].nrules = nr;
                 if(nr <= binth){
                    nodeSet[u].isleaf = 1;
                    Total_Rule_Size+= nr;
                    Leaf_Node_Count++;
                    nodeSet[u].layNo=nodeSet[v].layNo+1;

                    if(max_depth<(nodeSet[u].layNo+nr))
                       max_depth=nodeSet[v].layNo+nr;

                    }
                 else{
                      nodeSet[u].isleaf = 0;
                      nodeSet[u].layNo=nodeSet[v].layNo+1;

                      if(np<MAXCUTS) 
                         nodeSet[u].flag=2;
                      else
                         nodeSet[u].flag=1;

                      if(pass<nodeSet[u].layNo) 
                         pass=nodeSet[u].layNo;
                      qNode.push(u);
                        }

                 for (int t=0; t<MAXDIMENSIONS; t++){   
                     if(t != k){ 
	                nodeSet[u].field[t].low = nodeSet[v].field[t].low;
	                nodeSet[u].field[t].high= nodeSet[v].field[t].high;
	                  } 
                     else{
	                  nodeSet[u].field[t].low = lo1;
	                  nodeSet[u].field[t].high= hi1;
	                     }
                        }

                 int s = 0;
                 nodeSet[u].ruleid = (int *)calloc(nodeSet[v].nrules, sizeof(int));        
                 for(int j=0; j<nodeSet[v].nrules; j++){
                    if(rule[nodeSet[v].ruleid[j]].field[k].low >=lo1 && rule[nodeSet[v].ruleid[j]].field[k].low <=hi1 ||
                       rule[nodeSet[v].ruleid[j]].field[k].high>=lo1 && rule[nodeSet[v].ruleid[j]].field[k].high<=hi1 ||
                       rule[nodeSet[v].ruleid[j]].field[k].low <=lo1 && rule[nodeSet[v].ruleid[j]].field[k].high>=hi1){
                       nodeSet[u].ruleid[s] = nodeSet[v].ruleid[j];
                       s++;
                          }
                       }

                } //the end of if(!empty)
             else
                 nodeSet[v].child[i] = Null;
        
             lo1 = hi1 + 1;
             hi1 = lo1 + r1;
            }  //the end of the first for()
         }//the end of the big else()
      }//the end of if(nodeSet[v].flag==1)

   else{  //HybridCuts stage
       if(nodeSet[v].nrules <= binth){
          nodeSet[v].isleaf = 1;
          Total_Rule_Size+= nodeSet[v].nrules;
          Leaf_Node_Count++;

        if(max_depth<(nodeSet[v].layNo+nodeSet[v].nrules))
           max_depth=nodeSet[v].layNo+nodeSet[v].nrules;

           }
        else{  //else2
           NonLeaf_Node_Count++;
           choose_np_dim(&nodeSet[v]);
           move_up(&nodeSet[v]);
           index = 0;
           r[0] = (nodeSet[v].field[0].high - nodeSet[v].field[0].low)/nodeSet[v].ncuts2[0];
           lo[0] = nodeSet[v].field[0].low;
           hi[0] = lo[0] + r[0];	
           for(i[0] = 0; i[0] < nodeSet[v].ncuts2[0]; i[0]++){     //------start:3

              r[1] = (nodeSet[v].field[1].high - nodeSet[v].field[1].low)/nodeSet[v].ncuts2[1];
              lo[1] = nodeSet[v].field[1].low;
              hi[1] = lo[1] + r[1];
              for(i[1] = 0; i[1] < nodeSet[v].ncuts2[1]; i[1]++){
      
                 r[2] = (nodeSet[v].field[2].high - nodeSet[v].field[2].low)/nodeSet[v].ncuts2[2];
                 lo[2] = nodeSet[v].field[2].low;
                 hi[2] = lo[2] + r[2];
                 for(i[2] = 0; i[2] < nodeSet[v].ncuts2[2]; i[2]++){
      
                    r[3] = (nodeSet[v].field[3].high - nodeSet[v].field[3].low)/nodeSet[v].ncuts2[3];
                    lo[3] = nodeSet[v].field[3].low;
                    hi[3] = lo[3] + r[3];
                    for(i[3] = 0; i[3] < nodeSet[v].ncuts2[3]; i[3]++){
      
                       r[4] = (nodeSet[v].field[4].high - nodeSet[v].field[4].low)/nodeSet[v].ncuts2[4];
                       lo[4] = nodeSet[v].field[4].low;
                       hi[4] = lo[4] + r[4];
                       for(i[4] = 0; i[4] < nodeSet[v].ncuts2[4]; i[4]++){
          
                           empty = 1;
	                    nr = 0;
                           for(int j=0; j<nodeSet[v].nrules; j++){//for 1------start:2
                              flag1 = 1;
                              for(int k = 0; k < MAXDIMENSIONS; k++){
                                 if(rule[nodeSet[v].ruleid[j]].field[k].low > hi[k] || rule[nodeSet[v].ruleid[j]].field[k].high < lo[k]){
                                    flag1 = 0;
                                    break;
                                         }
                                      }

                              if(flag1 == 1){
                                empty = 0;
                                nr++;
                                    }
                           }//1 for ------end:2

                           if(!empty){//if 1------start:1
                              Total_Array_Size++;           
                              nodeSet[v].child[index] = freelist; 
                              u = freelist;
                              freelist++;
                              nodeSet[u].nrules = nr;
                              if(nr <= binth){
                                 nodeSet[u].isleaf = 1;
                                 Total_Rule_Size+=nr;
                                 Leaf_Node_Count++;


                                 nodeSet[u].layNo=nodeSet[v].layNo+1;
                                 if(max_depth<(nodeSet[u].layNo+nr))
                                    max_depth=nodeSet[v].layNo+nr;

                                  }
                              else{
                                   nodeSet[u].isleaf = 0;
                                   nodeSet[u].layNo=nodeSet[v].layNo+1;
                                   nodeSet[u].flag=2;
                                   if(pass<nodeSet[u].layNo) 
                                      pass=nodeSet[u].layNo;
                                   qNode.push(u); 
                                   }

                             for (int t=0; t<MAXDIMENSIONS; t++){ 
                                 if(nodeSet[v].select_dim[t] == 1){
        	                     nodeSet[u].field[t].low = lo[t];
	                            nodeSet[u].field[t].high= hi[t];
                                        }
                                 else{
                                     nodeSet[u].field[t].low = nodeSet[v].field[t].low;
	                              nodeSet[u].field[t].high= nodeSet[v].field[t].high;
                                          }
                                      }

                              int s = 0;
                              nodeSet[u].ruleid = (int *)calloc(nodeSet[v].nrules, sizeof(int));      
                              for(int j=0; j<nodeSet[v].nrules; j++){
                                 flag1 = 1;

                                 for(int k = 0; k < MAXDIMENSIONS; k++){
                                     if(nodeSet[v].select_dim[k] == 1)
                                        if(rule[nodeSet[v].ruleid[j]].field[k].low > hi[k] || rule[nodeSet[v].ruleid[j]].field[k].high < lo[k]){
                                           flag1 = 0;
                                           break;
                                                 }                                        
                                          }

                                 if(flag1 == 1){
                                    nodeSet[u].ruleid[s] = nodeSet[v].ruleid[j];
                                    s++;
                                         }
                                      }

                               }//1 if(!empty)
                            else
                               nodeSet[v].child[index] = Null;  //------end:1

                            index ++;
                            lo[4] = hi[4] + 1;
                            hi[4] = lo[4] + r[4];
                                }
                          lo[3] = hi[3] + 1;
                          hi[3] = lo[3] + r[3];
                             }
                       lo[2] = hi[2] + 1;
                       hi[2] = lo[2] + r[2];
                          }
                     lo[1] = hi[1] + 1;
                     hi[1] = lo[1] + r[1];
                        }
                  lo[0] = hi[0] + 1;
                  hi[0] = lo[0] + r[0];
                 }//------end:3

          }//the end of else2{}
       }//the end of else{}

   }//the end of while() loop

  total_memory=Total_Rule_Size*PTR_SIZE+Total_Array_Size*PTR_SIZE+LEAF_NODE_SIZE*Leaf_Node_Count+NODESIZE*NonLeaf_Node_Count;
  total_memory_in_KB=total_memory/1024;

if(numrules>binth){

   if(k==5)
      printf("**************************Big Subset Tree:****************************\n");
   if(k==0)
      printf("**************************SA Subset Tree:****************************\n");
   if(k==1)
      printf("**************************DA Subset Tree:****************************\n");

   printf("Rules:%d\n",numrules);
   printf("Level=%d\n",pass); //for test
   printf("Depth=%d\n",max_depth);
   printf("Total_Rule_Size=%d\n",Total_Rule_Size);
   printf("Leaf_Node num:%d\n",Leaf_Node_Count);
   printf("NonLeaf_Node num:%d\n",NonLeaf_Node_Count);
   printf("Node_Count=%d\n",freelist-1); //for test
   printf("Total_Array_Size=%d\n",Total_Array_Size);
   printf("-------------------\n");
   printf("ruleptr_memory: %d\n",Total_Rule_Size*PTR_SIZE);
   printf("array_memory: %d\n",Total_Array_Size*PTR_SIZE);
   printf("leaf_node_memory: %d\n",LEAF_NODE_SIZE*Leaf_Node_Count);
   printf("NonLeaf_int_node_memory: %d\n",NODESIZE*NonLeaf_Node_Count);
   printf("total_memory: %d\n",total_memory);
   printf("total_memory_in_KB: %d\n",total_memory_in_KB);
  }

}



