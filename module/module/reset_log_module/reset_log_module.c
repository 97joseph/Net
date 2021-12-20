#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/skbuff.h>          
#include <linux/init.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <linux/ip.h>              
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 
#include <uapi/linux/netfilter_ipv4.h> 

#include "../hook_module/log.h"
#include"../hw4secws.h"
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roee Ashkenazi");



static int major_number;
static struct device* sysfs_device = NULL;
extern struct class* sysfs_class;
int reset_k;

static unsigned int input_int = -1;

extern struct klist_packet_list mylist;

struct klist_packet_list  *reset_log_first;
struct list_head *reset_log_pos, *reset_log_q;
struct packet_info *reset_log_info;


void reset_log(void){

if(mylist.size!=0){
printk("deleting the list using list_for_each_safe()\n");
	list_for_each_safe(reset_log_pos, reset_log_q, &mylist.list){
		 reset_log_first= list_entry(reset_log_pos, struct klist_packet_list, list);
                 reset_log_info = &reset_log_first->info;

		 printk("info details: time = %lu,protocol = %u , src_ip =   %u, dst_ip =%u, src_port =   %u, dst_port =%u, count =%u, reason=%u ,action = %u\n\n",  reset_log_info->time,reset_log_info->protocol, reset_log_info->src_ip, reset_log_info->dst_ip,
reset_log_info->src_port,reset_log_info->dst_port, reset_log_info->count ,reset_log_info->reason,
reset_log_info->action);


		 list_del(reset_log_pos);
		 kfree( reset_log_first);
	}

for(reset_k=0;reset_k<BUFFER_SIZE;reset_k++){
log_array[reset_k]->timestamp = 0;
log_array[reset_k]->protocol = 0;
log_array[reset_k]->action = 0;
log_array[reset_k]->src_ip = 0;
log_array[reset_k]->dst_ip = 0;
log_array[reset_k]->src_port = 0;
log_array[reset_k]->dst_port = 0;

log_array[reset_k]->reason = 0;
log_array[reset_k]->count = 0;
}

}

}

//empty fops simply to deliver to module init

static struct file_operations fops = {
	.owner = THIS_MODULE,
        
};


// load function for chardev

ssize_t reset_log_display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
        
       
	return scnprintf(buf, PAGE_SIZE, "Logs have been reset");
}


//store function for chardev

ssize_t reset_log_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{

  int temp;
	if (sscanf(buf, "%u", &temp) == 1)
		input_int = temp;
        if (input_int ==0){
        reset_log();
}
		
	return count;	
}

static DEVICE_ATTR(reset, S_IWUSR | S_IRUGO , reset_log_display, reset_log_modify);

int simple_reset_log_init(void)
{
	
	//create char device
	major_number = register_chrdev(0, "reset", &fops);\
	if (major_number < 0)
		return -1;
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "log");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "reset");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "reset");
		return -1;
	}


	




	return 0;
}

void simple_reset_log_cleanup(void)
{
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "reset");


}

//module_init(simple_init);
//module_exit(simple_exit);
