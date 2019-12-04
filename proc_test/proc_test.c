#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>

#define NAME_DIR  "mod_dir"
#define NAME_NODE "mod_node"
#define LEN_MSG 160

static char *get_rw_buf( void ) {
   static char buf_msg[ LEN_MSG + 1 ] =
          ".........1.........2.........3.........4.........5\n";
   return buf_msg;
}

// чтение из /proc/mod_proc :
static ssize_t node_read( struct file *file, char *buf,
                          size_t count, loff_t *ppos ) {
   char *buf_msg = get_rw_buf();
   int res;
   printk( "read: %lu bytes (ppos=%lld)", count, *ppos );
   if( *ppos >= strlen( buf_msg ) ) {     // EOF
      *ppos = 0;
      printk( "EOF" );
      return 0;
   }
   if( count > strlen( buf_msg ) - *ppos )
      count = strlen( buf_msg ) - *ppos;  // это копия
   res = raw_copy_from_user( (void*)buf, buf_msg + *ppos, count );
   *ppos += count;
   printk( "return %lu bytes", count );
   return count;
}


// запись в /proc/mod_proc :
static ssize_t node_write( struct file *file, const char *buf,
                           size_t count, loff_t *ppos ) {
   char *buf_msg = get_rw_buf();
   int res, len = count < LEN_MSG ? count : LEN_MSG;
   printk( "write: %lu bytes", count );
   res = raw_copy_from_user( buf_msg, (void*)buf, len );
   buf_msg[ len ] = '\0';
   printk( "put %i bytes", len );
   return len;
}


static int __init proc_init( void ) {
   int ret;
   struct proc_dir_entry *dir, *file;
   if ((dir = proc_mkdir( NULL)) == NULL) {
        return -1;
    }
   file =   proc_mkdir_mode( NAME_NODE, S_IFREG | S_IRUGO | S_IWUGO, dir );


   if( NULL == file ) {
      ret = -ENOENT;
      printk( "can't create /proc/%s", NAME_NODE );
      goto err_node;
   }

   //file->uid = file->gid = 0;
   //file.read_proc = node_read;
   printk( "/proc/%s installed", NAME_NODE );
   return 0;
err_node:
   return ret;
}

static void __exit proc_exit( void ) {
   remove_proc_entry( NAME_NODE, NULL );
   printk( "/proc/%s removed", NAME_NODE );
}



MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "Dondok Baldanov <dondok.baldanov95@gmail.com>" );

static int  __init proc_init( void );
static void __exit proc_exit( void );

module_init( proc_init );
module_exit( proc_exit );
