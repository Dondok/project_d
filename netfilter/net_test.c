#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define LEN_MSG 160
static struct kobject *nf_kobj;
static char buf_msg[LEN_MSG] = "53\n";

/*
 * Метод show() вызывается при чтении файла файловой системы sysfs из простран-
 *	ства пользователя.
 */
static ssize_t net_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	int i = 0;
	int buff[1000];
	for(i = 0; i < 1000; i ++)
	{
		buff[i] = i;
		strcpy( buf, buff[i] );
	}

	//printk( "read %ld byte\n", strlen( buf ) );
	//buf_msg[ strlen(buf) ] = '\0';
//	return strlen(buf);
}

/*
 * Метод store() вызывается при записи. Он должен скопировать size байт данных
 * из буфера buffer в переменную, представляемую атрибутом attr.
 */
static ssize_t net_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t size)
{
	printk( "write %ld byte\n" , size );
	strncpy( buf_msg, buf, size );
	buf_msg[ size ] = '\0';
	return size;
}

/*
struct nf_hook_state {
	unsigned int hook;
	u_int8_t pf;
	struct net_device *in;
	struct net_device *out;
	struct sock *sk;
	struct net *net;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};
*
* для чего нужна функция okfn???
* int (*okfn)(struct sk_buff *) — callback функция, которая вызывается
* 	 с пакетом, когда все итерации вернут положительный ответ.
*
struct nf_hook_ops {
	//User fills in from here down.
	nf_hookfn		*hook;
	struct net_device	*dev;
	void			*priv;
	u_int8_t		pf;
	unsigned int		hooknum;
	// Hooks are ordered in ascending priority.
	int			priority;
};
*/

static unsigned int hfunc(void *priv, struct sk_buff *skb,
						  const struct nf_hook_state *state)
{
	long port_dest = 0;
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;

	if (kstrtol(buf_msg, 10, &port_dest) < 0){
		return -EINVAL;
	}

	if (!skb) //как заполняется буффер skb???
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (ntohs(udph->dest) == port_dest)	{
			return NF_DROP;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (ntohs(tcph->dest) == port_dest)	{
			return NF_DROP;
		}
	}


	return NF_ACCEPT;
	/*	в зависимости, что возвращается эта функция, регистратор крючка
	 * решает что с пакетом делать дальше.
	 *	NF_DROP -отбросить пакет
	 *	NF_ACCEPT - отправить пакет дальше
	 *  NF_QUEUE - поставить в очерель для пространства пользователя
	 */
}

static const struct nf_hook_ops nfho = {
	.hook		= hfunc,			/* hook function */
	.pf		    = PF_INET,			/* IPv4 */
	/* hooknum - идентификатор крючка. */
	.hooknum	= NF_INET_PRE_ROUTING,	/* received packets */
	.priority	= NF_IP_PRI_FIRST,		/* max hook priority */
};

//#define __ATTR_RW(name_file) __ATTR(name, 0644, show, store)
//static struct kobj_attribute net_attr = __ATTR_RW(net);
/*
 *создание в родительском("netfilter_test") каталоге файла "net"
 *с правами на чтение и запись
 */
static struct kobj_attribute net = __ATTR(net, S_IRUGO | S_IWUSR,
									          net_show, net_store);
static int __init LKM_init(void)
{
	int result = 0;
	/*
	 *создание папки с именем "netfilter_test" в директории /sys
	 */
	nf_kobj = kobject_create_and_add("netfilter_test", nf_kobj);
	if (!nf_kobj){
		return -ENOMEM;
	}

	result = sysfs_create_file(nf_kobj, &net.attr);
	if (result < 0){
		printk("create file: FAIL\n");
	} else {
		printk("create file: SUCCES\n");
	}

	nf_register_net_hook(&init_net, &nfho);
						//откуда берется init_net??
}

static void __exit LKM_exit(void)
{
	sysfs_remove_file(nf_kobj, &net.attr);
	kobject_del(nf_kobj);

	nf_unregister_net_hook(&init_net, &nfho);
}

module_init(LKM_init);
module_exit(LKM_exit);
MODULE_LICENSE("GPL");
