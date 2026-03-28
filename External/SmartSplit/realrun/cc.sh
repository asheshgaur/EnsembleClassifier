#!/bin/bash
set -e

cat << EOF > config.h
#ifndef __CONFIG_H__
#define __CONFIG_H__

EOF

emit_disabled_tree() {
    local idx="$1"
    echo "#define DEFINE_ROOT${idx} int root${idx}_disabled_unused = 0" >> config.h
    echo "#define LOAD_TREE${idx} ((void)0)" >> config.h
    echo "#define SEARCH_TREE${idx} UINT32_MAX" >> config.h
}

if [[ "$1" == "1" ]]
then
    echo "#define DEFINE_ROOT1 struct node *root1" >> config.h 
    echo "#define LOAD_TREE1 root1 = load_tree(ifp1, &info)" >> config.h
    echo "#define SEARCH_TREE1 (uint32_t)search_rules(root1, ft+i*MAXDIMENSIONS)" >> config.h
elif [[ -z "$1" ]]
then
    emit_disabled_tree 1
else
    echo "#define DEFINE_ROOT1 struct table_entry *root1" >> config.h 
    echo "#define LOAD_TREE1 root1 = load_hs(ifp1)" >> config.h
    echo "#define SEARCH_TREE1 (uint32_t)lookup_table(root1, ft+i*MAXDIMENSIONS)" >> config.h
fi

if [[ "$2" == "1" ]] 
then
    echo "#define DEFINE_ROOT2 struct node *root2" >> config.h 
    echo "#define LOAD_TREE2 root2 = load_tree(ifp2, &info)" >> config.h
    echo "#define SEARCH_TREE2 (uint32_t)search_rules(root2, ft+i*MAXDIMENSIONS)" >> config.h
elif [[ -z "$2" ]]
then
    emit_disabled_tree 2
else
    echo "#define DEFINE_ROOT2 struct table_entry *root2" >> config.h 
    echo "#define LOAD_TREE2 root2 = load_hs(ifp2)" >> config.h
    echo "#define SEARCH_TREE2 (uint32_t)lookup_table(root2, ft+i*MAXDIMENSIONS)" >> config.h
fi

if [[ "$3" == "1" ]]
then
    echo "#define DEFINE_ROOT3 struct node *root3" >> config.h 
    echo "#define LOAD_TREE3 root3 = load_tree(ifp3, &info)" >> config.h
    echo "#define SEARCH_TREE3 (uint32_t)search_rules(root3, ft+i*MAXDIMENSIONS)" >> config.h
elif [[ -z "$3" ]]
then
    emit_disabled_tree 3
else
    echo "#define DEFINE_ROOT3 struct table_entry *root3" >> config.h 
    echo "#define LOAD_TREE3 root3 = load_hs(ifp3)" >> config.h
    echo "#define SEARCH_TREE3 (uint32_t)lookup_table(root3, ft+i*MAXDIMENSIONS)" >> config.h
fi


cat << EOF >> config.h

#endif

EOF

make clean;make
