#ifndef __CONFIG_H__
#define __CONFIG_H__

#define DEFINE_ROOT1 struct node *root1
#define LOAD_TREE1 root1 = load_tree(ifp1, &info)
#define SEARCH_TREE1 (uint32_t)search_rules(root1, ft+i*MAXDIMENSIONS)
#define DEFINE_ROOT2 int root2_disabled_unused = 0
#define LOAD_TREE2 ((void)0)
#define SEARCH_TREE2 UINT32_MAX
#define DEFINE_ROOT3 int root3_disabled_unused = 0
#define LOAD_TREE3 ((void)0)
#define SEARCH_TREE3 UINT32_MAX

#endif

