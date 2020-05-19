#include <linux/rbtree.h>
#include <linux/kernel.h>
#include "my_rbtree"
#define TRUE    1
#define FALSE   0



/*
 * function for searching
 */
struct mytype *my_search(struct rb_root *root, char *string)
  {
  	struct rb_node *node = root->rb_node;

  	while (node)
    {
  		struct mytype *data = container_of(node, struct mytype, node);
		int result;

		result = strcmp(string, data->keystring);

		if (result < 0)
  			node = node->rb_left;
		else if (result > 0)
  			node = node->rb_right;
		else
  			return data;
	  }
	return NULL;
  }

/*
 * function for insert
 */
int my_insert(struct rb_root *root, struct mytype *data)
 {
   struct rb_node **new = &(root->rb_node), *parent = NULL;

   /* Figure out where to put new node */
   while (*new) {
       struct mytype *this = container_of(*new, struct mytype, node);
       int result = strcmp(data->keystring, this->keystring);

       parent = *new;
       if (result < 0)
           new = &((*new)->rb_left);
       else if (result > 0)
           new = &((*new)->rb_right);
       else
           return FALSE;
   }

   /* Add new node and rebalance tree. */
   rb_link_node(&data->node, parent, new);
   rb_insert_color(&data->node, root);

   return TRUE;
 }

 /*
  * function for remove tree node
  */
 void rb_erase(struct rb_node *victim, struct rb_root *tree);
 /*
  * an example of using rb_erase
  *
  *struct mytype *data = mysearch(&mytree, "walrus");
  *
  * if (data) {
  *	rb_erase(&data->node, &mytree);
  *	myfree(data);
  *}
  */

 /*
  * function for replase node
  * WARNING
  * old->key == new->key
  */
  void rb_replace_node(struct rb_node *old, struct rb_node *new,
           struct rb_root *tree);

 /*
  * function to traverse a tree
  *
  * struct rb_node *rb_first(struct rb_root *tree);
  * struct rb_node *rb_last(struct rb_root *tree);
  * struct rb_node *rb_next(struct rb_node *node);
  * struct rb_node *rb_prev(struct rb_node *node);
  */
