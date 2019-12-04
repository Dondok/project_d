
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
//	#include <asm/sal.h>
#include <linux/uaccess.h>
#include <linux/rbtree.h>

#define BASE_DIR	"base_dir"
#define EOF         "\0"
#define HELLO_MSG   "Hello user_space\n"

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

    if (copy_to_user(buf_user, buff_glob, size))
    {
        	return -EFAULT;
    }
    finished = 1;
    return size;

}
/*
ssize_t probchar_write(struct file *filp,
    const char __user *data, size_t s, loff_t *off) {

    printk("Data> |%s|\n", buf_user); // only for debug
    char chars[MAX_LENGHT];
    if(size > MAX_LENGHT)
        size = MAX_LENGHT;
    if (copy_from_user(chars, buf_user, size)) {
        return -EFAULT;
    }
    printk(KERN_DEBUG "Chars> |%s|\n", chars);
    buff_glob = chars;
    return size;
*/
static ssize_t file_write(struct file *file, const char __user *buf_user,
				  size_t count, loff_t *pos)
{

	if (count > PAGE_SIZE)
		count = PAGE_SIZE;
    char buf_help[PAGE_SIZE];
	if (copy_from_user(buf_help, buf_user, count))
	{
        return -EFAULT;
    }
    buff_glob = buf_help;
	return count;
}

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
  struct proc_dir_entry *base_dir, *entry;

  printk(KERN_INFO "Trying to create /proc/base_dir:\n");
  //create dir in /proc
  base_dir = proc_mkdir(BASE_DIR, NULL);
	if (!base_dir) {
		printk(KERN_ERR "Couldn't create base dir /proc/%s\n",
				BASE_DIR);
		return -ENOMEM;
	}
    //функции для создания файла в родительской директории
    entry = proc_create_data("file_base_dir", S_IRUGO | S_IWUSR, base_dir, &f_ops, 0);
    //proc_create_data(entry->name, 0644, named_dir,&srm_env_proc_fops, (void *)entry->id))
    //entry = proc_create_single("test_file", S_IRUGO, base_dir, fake_ide_media_proc_show);
  return rv;
}

void cleanup_module()
{
  remove_proc_entry(BASE_DIR, NULL);
  printk(KERN_INFO "/proc/BASE_DIR removed\n");
}
MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "Dondok Baldanov <dondok.baldanov95@gmail.com>" );
