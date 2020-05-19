
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/uaccess.h>
#include <linux/rbtree.h>
#include "rbtree/my_rbtree.h"

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define BASE_DIR	"base_dir"
#define EOF         "\0"
#define HELLO_MSG   "Hello user_space\n"
#define LEN_MSG 160

struct rb_tree * input;
struct rb_tree * output;
struct rb_tree * forward;
struct rb_tree * pre;
struct rb_tree * post;

static char *buff_glob = HELLO_MSG;

/*
 * Файл открыт -- пока нам нет нужды беспокоиться о чем-то
 * единственное, что нужно сделать -- это нарастить
 * счетчик обращений к модулю.
 */
int file_open(struct inode *inode, struct file *file)
{
  try_module_get(THIS_MODULE);
  return 0;
}

/*
 * Файл закрыт -- уменьшить счетчик обращений.
 */
int file_close(struct inode *inode, struct file *file)
{
  module_put(THIS_MODULE);
  return 0;             /* все нормально! */
}

static ssize_t file_read(struct file *f, /* см. include/linux/fs.h   */
             char __user *buf_user,      /* буфер с данными */
             size_t len,     /* размер буфера   */
             loff_t * offset)
{
    static int finished = 0;
  /*
   * Для индикации признака конца файла возвращается 0.
   */
    if (finished)
    {
        finished = 0;
        return 0;
    }

    //sprintf(message, "Last input:%s\n", Message);
    int size = strlen(buff_glob);
//копирует буффер в пространство полльзователя
    if (copy_to_user(buf_user, buff_glob, size))
    {
        	return -EFAULT;
    }
    finished = 1;
    return size;

}

static ssize_t file_write(struct file *file, const char __user *buf_user,
				  size_t count, loff_t *pos)
{
  //struct mytype *test;
  //struct rb_tree * my_tree;
	if (count > PAGE_SIZE)
		count = PAGE_SIZE;
    char buf_help[PAGE_SIZE];
//копирует буффер из пространства пользователя в ядро
	if (copy_from_user(buf_help, buf_user, count))
	{
        return -EFAULT;
  }
  // my_insert(my_tree ,test);
    buff_glob = buf_help;
	return count;
}

static unsigned int func_filter(void *priv, struct sk_buff *skb,
						  const struct nf_hook_state *state)
{
  long port_dest = 0;
  struct machdr *mach;
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;

  int result = 0;
  char * pre = NULL;
  char * rc  = NULL;

	if (!skb)
		return NF_ACCEPT;

  while ((pre = my_search(pre)) != NULL)
  {
    if (strstr(pre,"mac"))
    {
      if(strstr(pre,"dst"))
      {
        while( rc != NULL)
        {
          rc = strtok(pre, " ")
        }
        mach = mac_hdr(skb);
        if (kstrtol(rc, 10, &result) < 0){
      		return -EINVAL;
      	}
        if (htohs(mach->dest) == result )
        {
          return NF_DROP;
        }
      }
      if(strstr(pre,"src"))
      {
        while( rc != NULL)
        {
          rc = strtok(pre, " ")
        }
        mach = mac_hdr(skb);
        if (kstrtol(rc, 10, &result) < 0){
      		return -EINVAL;
      	}
        if (htohs(mach->src) == result )
        {
          return NF_DROP;
        }
      }

    }
    if (strstr(pre,"ip"))
    {
      if(strstr(pre,"dst"))
      {
        while( rc != NULL)
        {
          rc = strtok(pre, " ")
        }
        iph = ip_hdr(skb);
        if (kstrtol(rc, 10, &result) < 0){
      		return -EINVAL;
      	}
        if (htohs(iph->dest) == result )
        {
          return NF_DROP;
        }
      }
      if(strstr(pre,"src"))
      {
        while( rc != NULL)
        {
          rc = strtok(pre, " ")
        }
        iph = ip_hdr(skb);
        if (kstrtol(rc, 10, &result) < 0){
      		return -EINVAL;
      	}
        if (htohs(iph->src) == result )
        {
          return NF_DROP;
        }
      }
    }
    if (strstr(pre,"tcp"))
    {
      if (strstr(pre,"port_dst"))
      {
        while( rc != NULL)
        {
          rc = strtok(pre, " ")
        }
        tcph = tcp_hdr(skb);
        if (kstrtol(rc, 10, &result) < 0){
          return -EINVAL;
        }
        if (htohs(tcph->port_dst) == result )
        {
          return NF_DROP;
        }
      }
      if (strstr(pre,"port_src"))
      {
        while( rc != NULL)
        {
          rc = strtok(pre, " ")
        }
        tcph = tcp_hdr(skb);
        if (kstrtol(rc, 10, &result) < 0){
          return -EINVAL;
        }
        if (htohs(tcph->port_src) == result )
        {
          return NF_DROP;
        }
      }

    }
    if (strstr(pre,"udp"))
    {
      if (strstr(pre,"port_dst"))
      {
        while( rc != NULL)
        {
          rc = strtok(pre, " ")
        }
        udph = udp_hdr(skb);
        if (kstrtol(rc, 10, &result) < 0){
          return -EINVAL;
        }
        if (htohs(tcph->port_dst) == result )
        {
          return NF_DROP;
        }
      }
      if (strstr(pre,"port_src"))
      {
        while( rc != NULL)
        {
          rc = strtok(pre, " ")
        }
        udph = udp_hdr(skb);
        if (kstrtol(rc, 10, &result) < 0){
          return -EINVAL;
        }
        if (htohs(udph->port_src) == result )
        {
          return NF_DROP;
        }
      }
    }

  }
	return NF_ACCEPT;
}

static const struct nf_hook_ops prerouting = {
	.hook		= func_filter,
	.pf		    = PF_INET,
	.hooknum	= NF_INET_PRE_ROUTING,
	.priority	= NF_IP_PRI_FIRST,
};

static const struct nf_hook_ops forward = {
	.hook		= func_filter,
	.pf		    = PF_INET,
	.hooknum	= NF_INET_FORWARD,
	.priority	= NF_IP_PRI_FIRST,
};

static const struct nf_hook_ops input = {
	.hook		= func_filter,
	.pf		    = PF_INET,
	.hooknum	= NF_INET_LOCAL_IN  ,
	.priority	= NF_IP_PRI_FIRST,
};

static const struct nf_hook_ops output = {
	.hook		= func_filter,
	.pf		    = PF_INET,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= NF_IP_PRI_FIRST,
};

static const struct nf_hook_ops postrouting = {
	.hook		= func_filter,
	.pf		    = PF_INET,
	.hooknum	= NF_INET_POST_ROUTING,
	.priority	= NF_IP_PRI_FIRST,
};


static const struct file_operations f_ops = {
	.owner		= THIS_MODULE,
	.open		= file_open,
	.read		= file_read,
	.llseek		= seq_lseek,
	.release	= file_close,
	.write		= file_write,
};

int init_module()
{
  int rv = 0;
  struct proc_dir_entry *base_dir, *output, *input, *pre, *post, *entry;

  printk(KERN_INFO "Trying to create /proc/base_dir:\n");
  //create dir in /proc
  base_dir = proc_mkdir(BASE_DIR, NULL);
	if (!base_dir) {
		printk(KERN_ERR "Couldn't create base dir /proc/%s\n",
				BASE_DIR);
		return -ENOMEM;
	}

  output = proc_mkdir("output", base_dir);
	if (!output) {
		printk(KERN_ERR "Couldn't create base dir /proc/%s\n",
				BASE_DIR);
		return -ENOMEM;
	}

  input = proc_mkdir("output", base_dir);
	if (!input) {
		printk(KERN_ERR "Couldn't create base dir /proc/%s\n",
				BASE_DIR);
		return -ENOMEM;
	}

  forward = proc_mkdir("output", base_dir);
	if (!forward) {
		printk(KERN_ERR "Couldn't create base dir /proc/%s\n",
				BASE_DIR);
		return -ENOMEM;
	}

  pre = proc_mkdir("output", base_dir);
	if (!pre) {
		printk(KERN_ERR "Couldn't create base dir /proc/%s\n",
				BASE_DIR);
		return -ENOMEM;
	}

  post = proc_mkdir("output", base_dir);
	if (!post) {
		printk(KERN_ERR "Couldn't create base dir /proc/%s\n",
				BASE_DIR);
		return -ENOMEM;
	}

    //функции для создания файла в родительской директории
    entry = proc_create_data("rules", S_IRUGO | S_IWUSR, output, &f_ops, 0);
    entry = proc_create_data("rules", S_IRUGO | S_IWUSR, input, &f_ops, 0);
    entry = proc_create_data("rules", S_IRUGO | S_IWUSR, forward, &f_ops, 0);
    entry = proc_create_data("rules", S_IRUGO | S_IWUSR, pre, &f_ops, 0);
    entry = proc_create_data("rules", S_IRUGO | S_IWUSR, post, &f_ops, 0);

    entry = proc_create_data("remove_rules", S_IRUGO | S_IWUSR, output, &f_ops, 0);
    entry = proc_create_data("remove_rules", S_IRUGO | S_IWUSR, input, &f_ops, 0);
    entry = proc_create_data("remove_rules", S_IRUGO | S_IWUSR, forward, &f_ops, 0);
    entry = proc_create_data("remove_rules", S_IRUGO | S_IWUSR, pre, &f_ops, 0);
    entry = proc_create_data("remove_rules", S_IRUGO | S_IWUSR, post, &f_ops, 0);

    entry = proc_create_data("show", S_IRUGO | S_IWUSR, base_dir, &f_ops, 0);

/* регистрация крючков для перехвата пакетов на каждом узле*/
    nf_register_net_hook(&init_net, &prerouting);
    nf_register_net_hook(&init_net, &forward);
    nf_register_net_hook(&init_net, &input);
    nf_register_net_hook(&init_net, &output);
    nf_register_net_hook(&init_net, &postrouting);

  return rv;
}

void cleanup_module()
{
  /*перд тем как удалить модуль нужно удалить псевдофайлы и директорию*/
  remove_proc_entry("rules",NULL);
  remove_proc_entry("remove_rules",NULL);
  remove_proc_entry("show",NULL);
  remove_proc_entry("output",NULL);
  remove_proc_entry(BASE_DIR, NULL);
  printk(KERN_INFO "/proc/BASE_DIR removed\n");
}
MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "Dondok Baldanov <dondok.baldanov95@gmail.com>" );
