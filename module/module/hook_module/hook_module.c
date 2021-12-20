#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/module.h> 
#include <linux/skbuff.h>          
#include <linux/init.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <linux/ip.h>              
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 
#include <uapi/linux/netfilter_ipv4.h> 
#include<linux/slab.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/time.h>


#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include<linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/string.h>

#include "log.h"
#include"../rule_table_module/fw.h"
#include"../hw4secws.h"


#define NAME "fw_log" 


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roee Ashkenazi");

/**hook**/

//nf_hook_ops struct for netfilter implementation
//static struct nf_hook_ops pre_routing_hook;
static struct nf_hook_ops pre_routing_hook;
//static struct nf_hook_ops local_out_hook;

static int major_number= -1;
static struct cdev mycdev;
static struct class *myclass = NULL;

struct klist_packet_list mylist;
//struct klist_conns_list conns_list;


struct list_head *pos, *q;

struct timeval time;
unsigned long local_time;




int packets_accepted=0;
int packets_dropped=0;
int matches=0;



/**show_log**/


//static char device_buffer[BUFFER_SIZE];


extern struct klist_packet_list mylist;



struct klist_packet_list  *first;



unsigned int j=0;
unsigned int k=0;
int message_length=0;
int num=0;
int matches_prev_connection=0;

static int str_len;	
char * buffer_index;
char messages[BUFFER_SIZE+1][BUFFER_SIZE+1];




int matches_previous_packet(struct packet_info *packet){

int location = 0 ;
 struct klist_packet_list  *first = NULL;
 struct packet_info *info;
struct connection_info * connection;




//assign connection data

if(packet->protocol == 6){

connection = (struct connection_info *)kmalloc(sizeof(struct connection_info),GFP_KERNEL);


connection->src_ip = packet->src_ip;
connection->dst_ip = packet->dst_ip;
connection->src_port = packet->src_port;
connection->dst_port = packet->dst_port;





if (if_connection_in_connections_list(connection) == 0)
{
//printk("connection not in table");


matches_prev_connection =0;

}

else{
//printk("connection in table");

matches_prev_connection =1;


}

}


if(mylist.size!=0){

list_for_each_safe(pos, q, &mylist.list){


first= list_entry(pos, struct klist_packet_list, list);
                 info = &first->info;





if(info->src_ip == packet->src_ip

&&

info->dst_ip == packet->dst_ip

&&

info->protocol== packet->protocol

&&
info->src_port == packet->src_port

&&

info->dst_port == packet->dst_port){
//printk("found match!\n");
info->count++;


return location;

}//close-if equals

location++;

}//close-loop

}//close- if size not 0 

//printk("end of comparison data\n");



return -1; 
}




void update_count_for_log_entry(int location,int ack){


char reason_string[32];
int reason;
long time;

//matches_prev_connection =0;


log_array[location]->reason = -2;
reason = log_array[location]->reason;


time = log_array[location]->timestamp;


log_array[location]->count++;


if(reason == -2){
scnprintf(reason_string,32,"%s","NO_MATCHING_RULE");
}

if(reason == -6){
scnprintf(reason_string,32,"%s","ILLEGAL_VALUE");
}

if(matches_prev_connection){
log_array[location]->action = 1;

scnprintf(reason_string,32,"%s","CONNECTION_IN_TABLE");

change_state(log_array[location],ack);
}

if(log_array[location]->action!=0){
scnprintf(messages[location], PAGE_SIZE,"info details: time = %lu,protocol = %u , src_ip =   %u, dst_ip =%u, src_port =   %u, dst_port =%u, count =%u, action = accept\n\n",  log_array[location]->timestamp,log_array[location]->protocol, log_array[location]->src_ip, log_array[location]->dst_ip,
 log_array[location]->src_port, log_array[location]->dst_port, log_array[location]->count);
//packets_accepted++;



}


else{
scnprintf(messages[location], PAGE_SIZE,"info details: time = %lu,protocol = %u , src_ip =   %u, dst_ip =%u, src_port =   %u, dst_port =%u, count =%u, reason=%s ,action = drop\n\n",  log_array[location]->timestamp,log_array[location]->protocol, log_array[location]->src_ip, log_array[location]->dst_ip,
 log_array[location]->src_port, log_array[j]->dst_port, log_array[location]->count,reason_string);
}


message_length = strlen(messages[location]);
messages[location][message_length]='\0';
//printk("messages[location] = %s",messages[location]);




}


void insert_into_log(packet_info * info){

char reason_string[32];
int reason;
long time;

matches_prev_connection =0;


reason = info->reason;
//printk("info.reason = %d",info->reason);

time = info->time;
//printk("info.time = %lu",info->time);

if(reason == -2){
scnprintf(reason_string,32,"%s","NO_MATCHING_RULE");
}
if(reason == -4){
scnprintf(reason_string,32,"%s","REASON_XMAS_PACKET");
}

if(reason == -6){
scnprintf(reason_string,32,"%s","ILLEGAL_VALUE");
}



log_array[j]->timestamp = time;
log_array[j]->protocol = info->protocol;
log_array[j]->action = info->action;
log_array[j]->src_ip = info->src_ip;
log_array[j]->dst_ip = info->dst_ip;
log_array[j]->src_port = info->src_port;
log_array[j]->dst_port = info->dst_port;

log_array[j]->reason = info->reason;
log_array[j]->count = info->count;





//insert into connections table

//update conns info and insert into connection table


insert_to_conns_list(log_array[j]);








if(info->action!=0){
scnprintf(messages[j], PAGE_SIZE,"info details: time = %lu,protocol = %u , src_ip =   %u, dst_ip =%u, src_port =   %u, dst_port =%u, count =%u, action = accept\n\n",  log_array[j]->timestamp,log_array[j]->protocol, log_array[j]->src_ip, log_array[j]->dst_ip,
 log_array[j]->src_port, log_array[j]->dst_port, log_array[j]->count);
packets_accepted++;
}


else{
scnprintf(messages[j], PAGE_SIZE,"info details: time = %lu,protocol = %u , src_ip =   %u, dst_ip =%u, src_port =   %u, dst_port =%u, count =%u, reason=%s ,action = drop\n\n",  log_array[j]->timestamp,log_array[j]->protocol, log_array[j]->src_ip, log_array[j]->dst_ip,
 log_array[j]->src_port, log_array[j]->dst_port, log_array[j]->count,reason_string);
packets_dropped++;
}

message_length = strlen(messages[j]);
messages[j][message_length]='\0';
//printk("messages[j] = %s",messages[j]);
j++;


  //cyclic buffer implemented
 if(j==BUFFER_SIZE){
          j=0;
         }




}


void print_status(void){
printk("number of packets so far = %d",packets_accepted+packets_dropped+matches);
printk("number of accepted packets so far = %d",packets_accepted);
printk("number of dropped packets so far = %d",packets_dropped);
printk("number of matches so far = %d",matches);
}


//if a packet is in our connections list, we don't need to log it, and we just accept it







/**
source info : this code combines hw1secws.c (previous homework) 
and the sysfs example given in class
**/

// hook function that also counts the amount of dropped/accepted packets


unsigned int pre_routing_hook_func(void *priv,
                   struct sk_buff *skb,
                   const struct nf_hook_state *state)
{
struct tcphdr *tcp_header;
 struct udphdr *udp_header;
 struct icmphdr *icmp_header;
 struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
 struct klist_packet_list  *first = NULL;

 struct packet_info *info;
 
 int match_index;
 
char source[16];
char dest[16];
int ack=0;
 
//matches_prev_connection = 0 ; 

first = (struct klist_packet_list *)kmalloc(sizeof(struct klist_packet_list),GFP_KERNEL);
info = &first->info;


info->src_ip = ntohl(ip_header->saddr);
info->dst_ip = ntohl(ip_header->daddr);


snprintf(source, 16, "%pI4", &ip_header->saddr);
snprintf(dest, 16, "%pI4", &ip_header->daddr);


/**get timestamp**/
do_gettimeofday(&time);
local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));



info->time = local_time;

printk("local time = %lu",info->time);

//loopback packet

if (info->src_ip == info->dst_ip){
printk("***Packet Accepted***");
//packets_accepted++;
info->action = 1;
//print_status();
return NF_ACCEPT;
}


info->protocol =  ip_header->protocol;

//tcp packet
if (ip_header->protocol ==6){
  tcp_header  = (struct tcphdr *)skb_network_header(skb);
  info->src_port = ntohs(tcp_header->source);
info->dst_port = ntohs(tcp_header->dest);


if(info->src_port>1023){
info->src_port=1023;
}
if(info->dst_port>1023){
info->dst_port=1023;
}

//for MITM
if(info->dst_port == 80){
printk("dst port is 80");
info->dst_port=800;
}

//for MITM
if(info->dst_port == 21){
printk("dst port is 21");
info->dst_port=210;
}


ack = tcp_header->ack;




//christamx packet
if(tcp_header->psh ==1 &&
tcp_header ->urg == 1&&
tcp_header-> ack ==1){
printk("***Packet Dropped***");
printk("***Merry Christams***");
packets_dropped++;
info->action = 0;
info->reason = -4;
printk("dropped with reason: %d",info->reason);
print_status();
return NF_DROP;

}



}

//udp packet
else if (ip_header->protocol ==17){
  udp_header  = (struct udphdr *)skb_network_header(skb);



if(info->src_port>1023){
info->src_port=1023;
}
if(info->dst_port>1023){
info->dst_port=1023;
}
}
//icmp packet
else if (ip_header->protocol ==1){
  icmp_header  = (struct icmphdr *)skb_network_header(skb);




if(info->src_port>1023){
info->src_port=1023;
}
if(info->dst_port>1023){
info->dst_port=1023;
}
 
}

//accept any non-tcp,udp,icmp packet
else{
printk("***Packet Accepted***");
//packets_accepted++;
info->action = 1;
info->reason = 1;
insert_into_log(info);
print_status();
return NF_ACCEPT;
}


//printk("****Comparing packet to all rules****");


if(decide_on_packet(info)!=1){
printk("decide_on_packet(info) = %d",decide_on_packet(info));
}



//check if matches previous packet

match_index=matches_previous_packet(info);


//if ack ==0 - check against static rule table 

if (ack == 0){

// check if matches previous packet, if so, update counter

if(match_index !=-1){
matches++;

update_count_for_log_entry(match_index,ack);

printk("packet matches previous one");

//if there is a rule for the packet

if(decide_on_packet(info)==1){
 //matches_prev_connection=0;
printk("***Packet Accepted***");
printk("found matching rule");
//packets_accepted++;
info->action = 1;
print_status();
return NF_ACCEPT;
}

else if(decide_on_packet(info)!=1){
 //matches_prev_connection=0;
printk("***Packet Dropped***");
printk("no matching rule");
info->reason = -2;
   print_status();
   printk("dropped with reason: %d",info->reason);
   return NF_DROP;
}


   

}


//doesn't match previous packet - must be inserted

else{
list_add(&(first->list), &(mylist.list));
info->count=1;
mylist.size++;

//if there isn't a rule for the packet or connection not in table



if(decide_on_packet(info)!=1){

info->reason = -2;
info->action = 0;
insert_into_log(info);
printk("no rule for packet");
printk("***Packet Dropped***");
//print_status();
return NF_DROP;
}

//if there is


 else if(decide_on_packet(info)==1){
printk("***Packet Accepted***");
//packets_accepted++;
info->action = 1;
printk("found matching rule for new packet");
print_status();
return NF_ACCEPT;
}


}

}

else if (ack == 1){
//check against connection table

// found matching connection

if (matches_prev_connection){
printk("***Packet Accepted***");
packets_accepted++;
info->action = 1;
printk("found matching connection");
print_status();
return NF_ACCEPT;
}

// didn't find matching connection
else {
printk("***Packet Dropped***");
packets_dropped++;
info->action = 0;
printk("matching connection not found");
print_status();
return NF_DROP;

}

}




return 0;

 
}



//open

/* Our custom open function  for file_operations --------------------- */
int hook_module_open(struct inode *_inode, struct file *_file) { // Each time we open the device we initilize the changing variables ( so we will be able to read it again and again


	str_len = strlen(messages[k]);
	buffer_index = messages[k];
        k++;
        
        //cyclic buffer implemented
        if(k==BUFFER_SIZE){
          k=0;
         }
      
	return 0;
}

static int hook_module_close(struct inode *i, struct file *f)
{
    printk(KERN_INFO "hook_module: close()\n");
    return 0;
}

//read

static ssize_t hook_module_read(struct file *fp, char *buff, size_t length, loff_t *ppos)
{
 ssize_t num_of_bytes;

	num_of_bytes = (str_len < length) ? str_len : length;
    
    if (num_of_bytes == 0) { 
    	return 0;
	}
    
    if (copy_to_user(buff, buffer_index, num_of_bytes)) { 
        return -EFAULT;
    } else { 
        str_len -= num_of_bytes;
        buffer_index += num_of_bytes;
        return num_of_bytes;
    }
	return -EFAULT;
}

static struct file_operations fops = 
{
    .owner   = THIS_MODULE,
    .open = hook_module_open,
     .release= hook_module_close,
    .read    = hook_module_read,
};

                    



void cleanup(int device_created)
{
    if (device_created) {
        device_destroy(myclass, major_number);
        cdev_del(&mycdev);
    }
    if (myclass)
        class_destroy(myclass);
    if (major_number != -1)
        unregister_chrdev_region(major_number, 1);
}




int __init simple_hook_init(void)
{

int device_created = 0;

/**hook**/
simple_rule_table_init();
simple_conns_init();
simple_reset_log_init();

        //init packet list
	INIT_LIST_HEAD(&mylist.list);





	//init pre_routing hook privates,namely hooknum(0)
	pre_routing_hook.hook=pre_routing_hook_func;
   pre_routing_hook.pf=PF_INET;        
    pre_routing_hook.hooknum=0;
    pre_routing_hook.priority= NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net,&pre_routing_hook);



/**


//init local_out hook privates,namely hooknum(4)
	local_out_hook.hook=forward_hook_func;
   local_out_hook.pf=PF_INET;        
    local_out_hook.hooknum=4;
    local_out_hook.priority= NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net,&local_out_hook);




**/


/**show_log**/

 if (alloc_chrdev_region(&major_number, 0, 1, NAME "_proc") < 0)
        goto error;
      if ((myclass = class_create(THIS_MODULE, NAME "_sys")) == NULL)
        goto error;
      if (device_create(myclass, NULL, major_number, NULL, NAME "") == NULL)
        goto error;

       

       device_created = 1;
    cdev_init(&mycdev, &fops);
    if (cdev_add(&mycdev, major_number, 1) == -1)
        goto error;
    return 0;
error:
    cleanup(device_created);
    return -1;
    
}

void __exit simple_hook_cleanup(void)
{

/**hook**/
	struct klist_packet_list  *first = NULL;
     
 struct packet_info info;

simple_rule_table_cleanup();

printk("deleting the info list using list_for_each_safe()\n");
	list_for_each_safe(pos, q, &mylist.list){
		 first= list_entry(pos, struct klist_packet_list, list);
                 info = first->info;
		 printk("info details: protocol = %u , src_ip =   %u, dst_ip =%u\n",  info.protocol, info.src_ip, info.dst_ip);
		 list_del(pos);
		 kfree( first);
	}



//nf_unregister_net_hook(&init_net,&pre_routing_hook);
nf_unregister_net_hook(&init_net,&pre_routing_hook);
//nf_unregister_net_hook(&init_net,&local_out_hook);
/**show log**/

cleanup(1);
simple_conns_cleanup();
simple_reset_log_cleanup();


}

module_init(simple_hook_init);
module_exit(simple_hook_cleanup);
