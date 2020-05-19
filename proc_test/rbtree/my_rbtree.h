#include <linux/rbtree.h>

/*
 * root
 */
struct rb_tree
{
    struct rb_node *root; // указатель на корневой узел
    int count; // количество узлов в дереве
};

int my_insert(struct rb_root *root, struct mytype *data);
struct mytype *my_search(struct rb_root *root, char *string);
