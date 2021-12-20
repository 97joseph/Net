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

int input_int;
//int j;

struct klist_conns_list connslist;

//void insert_to_conns_list(int j);

//insert a connection into the list


int if_connection_in_connections_list(connection_info * connection){

struct list_head *pos, *q;
struct klist_conns_list  *first = NULL;
struct connection_info *conns_info;




//loop over list
//printk("checking if a connection already exists in the connections list using list_for_each_safe()\n");
	list_for_each_safe(pos, q, &connslist.list){
		 first= list_entry(pos, struct klist_conns_list, list);
                 conns_info = &(first->info);


//printk("connection data = \n");
//printk("connection->src_ip = %u\n",connection->src_ip);
//printk("connection->dst_ip = %u\n",connection->dst_ip);
//printk("protocol = %u\n",packet->protocol);
//printk("connection->src_port = %u\n",connection->src_port);
//printk("connection->dst_port = %u\n",connection->dst_port);





//printk("conns_info data = \n");
//printk("conns_info->src_ip = %u\n",conns_info->src_ip);
//printk("conns_info->dst_ip = %u\n",conns_info->dst_ip);
//printk("protocol = %u\n",packet->protocol);
//printk("conns_info->src_port = %u\n",conns_info->src_port);
//printk("conns_info->dst_port = %u\n",conns_info->dst_port);



		 if ((connection->src_ip == conns_info->dst_ip

&&
connection->dst_ip == conns_info->src_ip

&&
connection->src_port == conns_info->src_port

&&
connection->dst_port == conns_info->dst_port)

|| 


(connection->src_ip == conns_info->src_ip

&&
connection->dst_ip == conns_info->dst_ip

&&
connection->src_port == conns_info->src_port

&&
connection->dst_port == conns_info->dst_port))

{

//printk("connection alerady in table");


return 1;

}//close-if			 


}//close-loop



return 0;

}





void insert_to_conns_list(log_row_t * log_row){
struct klist_conns_list  *first_conns = NULL;
struct connection_info *conns_info;


first_conns = (struct klist_conns_list *)kmalloc(sizeof(struct klist_conns_list),GFP_KERNEL);
conns_info = &first_conns->info;

conns_info->src_ip = log_row->src_ip;
conns_info->dst_ip = log_row->dst_ip;
conns_info->src_port = log_row->src_port;
conns_info->dst_port = log_row->dst_port;
conns_info->state = 0;

list_add(&(first_conns->list), &(connslist.list));
}




void change_state(log_row_t * log_row, int ack){


struct list_head *pos, *q;
struct klist_conns_list  *first = NULL;
struct connection_info *conns_info;




//loop over list
printk("checking if a connection already exists in the connections list using list_for_each_safe()\n");
	list_for_each_safe(pos, q, &connslist.list){
		 first= list_entry(pos, struct klist_conns_list, list);
                 conns_info = &(first->info);


//printk("log_row data = \n");
//printk("log_row->src_ip = %u\n",log_row->src_ip);
//printk("log_row->dst_ip = %u\n",log_row->dst_ip);
//printk("protocol = %u\n",packet->protocol);
//printk("log_row->src_port = %u\n",log_row->src_port);
//printk("log_row->dst_port = %u\n",log_row->dst_port);



/**

printk("conns_info data = \n");
printk("conns_info->src_ip = %u\n",conns_info->src_ip);
printk("conns_info->dst_ip = %u\n",conns_info->dst_ip);
printk("conns_info->src_port = %u\n",conns_info->src_port);
printk("conns_info->dst_port = %u\n",conns_info->dst_port);


**/
		 if ((log_row->src_ip == conns_info->dst_ip

&&
log_row->dst_ip == conns_info->src_ip

&&
log_row->src_port == conns_info->src_port

&&
log_row->dst_port == conns_info->dst_port)

|| 


(log_row->src_ip == conns_info->src_ip

&&
log_row->dst_ip == conns_info->dst_ip

&&
log_row->src_port == conns_info->src_port

&&
log_row->dst_port == conns_info->dst_port))

{

//printk("changing state");

conns_info->state = ack;




}//close-if			 


}//close-loop





}












//empty fops simply to deliver to module init

static struct file_operations fops = {
	.owner = THIS_MODULE,
        
};


// load function for chardev

ssize_t conns_log_display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
        
       
	return scnprintf(buf, PAGE_SIZE, "conns");
}


//store function for chardev

ssize_t conns_log_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{

  int temp;
	if (sscanf(buf, "%u", &temp) == 1)
		input_int = temp;
		
	return count;	
}

static DEVICE_ATTR(conns, S_IWUSR | S_IRUGO , conns_log_display, conns_log_modify);

int simple_conns_init(void)
{
	
	//create char device
	major_number = register_chrdev(0, "conns", &fops);\
	if (major_number < 0)
		return -1;
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "conns");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "conns");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_conns.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "conns");
		return -1;
	}


	  //init packet list
	INIT_LIST_HEAD(&connslist.list);




	return 0;
}

void simple_conns_cleanup(void)
{

struct list_head *pos, *q;
struct klist_conns_list  *first = NULL;
struct connection_info conns_info;
char state_string [32];
int state;


//delete list
printk("deleting the connections list using list_for_each_safe()\n");
	list_for_each_safe(pos, q, &connslist.list){
		 first= list_entry(pos, struct klist_conns_list, list);
                 conns_info = first->info;

//classify by state

state =  conns_info.state;

if(state == 0){
scnprintf(state_string,32,"%s","ACK_PERFORMED");
}
if(state == 1){
scnprintf(state_string,32,"%s","SYN_ACK_PERFORMED");
}

if(state == 2){
scnprintf(state_string,32,"%s","CONNECTION_ESTABLISHED");
}

		 printk("info details:  src_ip =   %u, dst_ip =%u,src_port =   %u, dst_port =%u, state = %s\n", conns_info.src_ip, conns_info.dst_ip,conns_info.src_port, conns_info.dst_port,state_string);
		 list_del(pos);
		 kfree( first);
	}


	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_conns.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	//class_destroy(sysfs_class);
	unregister_chrdev(major_number, "conns");


}

