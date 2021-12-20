#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/skbuff.h>          
#include <linux/init.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <linux/ip.h>              
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 
#include <uapi/linux/netfilter_ipv4.h> 
#include <linux/linkage.h>
#include <linux/uaccess.h>

#include "../hook_module/log.h"

#include "fw.h"


#define MAX 256

 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roee Ashkenazi");


unsigned long ret;
static unsigned char	num_of_rules;
static unsigned int 	next_rule_ctr;
static unsigned int 	rule_index=0;




static rule_t  		fw_rules_table[MAX_RULES];
static rule_t 		*my_ipt;
//static unsigned char 	allowed_users[MAX_RULES];

static int major_number;
 struct class* sysfs_class;
static struct device* sysfs_device = NULL;






static struct file_operations fops = {
	.owner = THIS_MODULE,
          
};

 
// load function for chardev

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show/read implementation
{


char * num = "Number Of Rules:";
 

        
return scnprintf(buf, PAGE_SIZE, "%s%d\n",num,num_of_rules);     
}



direction_t find_direction(char * direction_string){
if(strcmp(direction_string,"any")==0){
return DIRECTION_ANY;
}
if(strcmp(direction_string,"in")==0){
return DIRECTION_IN;
}
if(strcmp(direction_string,"out")==0){
return DIRECTION_OUT;
}
return 0;
}



ack_t find_ack(char * ack_string){
if(strcmp(ack_string,"any")==0){
return ACK_ANY;
}
if(strcmp(ack_string,"yes")==0){
return ACK_YES;
}
if(strcmp(ack_string,"no")==0){
return ACK_NO;
}
return 0;
}

// get prefix from ip address
int get_prefix_from_ip(char * ip){

char * str;
long val=0;
int i;
int err=0;

if(strchr(ip,'/')!=NULL){
for(i=0;i<2;i++)
  str = strsep(&ip,"/");
err = kstrtol(str,10,&val);
if(err)
   return err;
}

return val;


}

__be16 get_port_number(char * port){

int val;
__be16 nval; // output

if(strcmp(port,"any")==0){
nval = 0 ;
}
else if (strcmp(port,">1023")==0 || strlen(port)>4){
nval = 1023 ;
}
else{
kstrtoint(port, 10, &val);
nval = val;
}


return nval;
}

int get_protocol(char *protocol){

//__u8 b;

if(strcmp(protocol,"ICMP")==0){
//b=(__u8)(1);
return 1;
}
if(strcmp(protocol,"TCP")==0){
//b=(__u8)(6);
return 6;
}
if(strcmp(protocol,"UDP")==0){
//b=(__u8)(17);
return 17;
}
if(strcmp(protocol,"OTHER")==0){
//b=(__u8)(255);
return 255;
}
if(strcmp(protocol,"any")==0){
printk("any");
//b=(__u8)(143);
return 143;
}
//return b;
return 0;
}


__u8 get_action(char * action){
if(strcmp(action,"accept")==0){
return (__u8)(NF_ACCEPT);
}
if(strcmp(action,"drop")==0){
return (__u8)(NF_DROP);
}
return (__u8)(-1);
}


int is_rule_in_table(rule_t rule){

int i;
for(i=0;i<rule_index;i++){

if (strcmp(fw_rules_table[i].rule_name,rule.rule_name)==0
&&			
	 fw_rules_table[i].direction == rule.direction   
&&
	 fw_rules_table[i].src_ip == rule.src_ip   
&&	
		 fw_rules_table[i].src_prefix_mask == rule.src_prefix_mask   
&&  	 
	 fw_rules_table[i].src_prefix_size == rule.src_prefix_size 
&&  	
								
		  fw_rules_table[i].dst_ip == rule.dst_ip 
&& 
		fw_rules_table[i].dst_prefix_mask == rule.dst_prefix_mask 
&& 	
	  	 fw_rules_table[i].dst_prefix_size == rule.dst_prefix_size 
&&   		
		 fw_rules_table[i].src_port == rule.src_port 
&&  			  
		 fw_rules_table[i].dst_port == rule.dst_port 
&&  			 
		 fw_rules_table[i].protocol == rule.protocol 
&&  			
		 fw_rules_table[i].ack == rule.ack 
&& 				
	   fw_rules_table[i].action == rule.action 
){

return 1;
}

}
return 0;

}

char *get_sub_array(const char *array, int from, int to){
    size_t size = (to - from + 1) * sizeof(char);
    char *sub_array = kmalloc_array(size,sizeof(char),
GFP_KERNEL);

    if (sub_array) {
        memcpy(sub_array, array + from, size);
    }

    return sub_array;
} 



unsigned long inet_addr(char *str)
{
    int a, b, c, d;
    //char arr[4];

if(strcmp(str,"any")==0){
return 0;
}
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    //arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return (a*256*256*256+b*256*256+c*256+d);
}

//store function for chardev

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store/write implementation - add new rule
{

rule_t rule; 
char rule_name[20];
char direction_string[5];
char src_ip[20];

char dst_ip[20];
//unsigned long ip_long;
char src_port_string[5];
char dst_port_string[5];
char protocol_string[5];
char ack_string[5];
char action_string[10];
int readCharCount;



//int matching_flag=0;
int i;
//int j;
//int offset =0 ;



/**


**/



int rules_remaining = MAX_RULES - rule_index + 1;		
int num = count / sizeof(rule_t);
//int lines =3;
char *it = (char *)buf;
//int old_offset=0;						
//const char * str;




if (num > rules_remaining) {
printk(KERN_INFO "rule table module: rule table is out of memory. Will exit now..\n");
     return -ENOSPC;
}


while(sscanf(it,"%s%s%s%s%s%s%s%s%s%n",rule_name,direction_string,src_ip,
dst_ip,protocol_string,src_port_string,dst_port_string,ack_string,action_string,&readCharCount)==9){



it += readCharCount;
printk("readChars= %u",readCharCount);

for(i=0;i<20;i++){
rule.rule_name[i] = rule_name[i];
}

rule.direction = find_direction(direction_string);



rule.src_ip = inet_addr(src_ip);

//printk("test print, 10.1.1.1 is : %lu", inet_addr("10.1.1.1"));





rule.src_prefix_size = get_prefix_from_ip(src_ip);
rule.src_prefix_mask = cpu_to_be32((-1) << (32-rule.src_prefix_size));




rule.dst_prefix_size = get_prefix_from_ip(dst_ip);
rule.dst_prefix_mask = cpu_to_be32((-1) << (32-rule.dst_prefix_size));



rule.dst_ip =  inet_addr(dst_ip);



rule.src_port = get_port_number(src_port_string);
rule.dst_port = get_port_number(dst_port_string);
rule.protocol = get_protocol(protocol_string);
rule.ack = find_ack(ack_string);


rule.action = get_action(action_string);

fw_rules_table[rule_index] = rule;

//printk("rule name :%s",fw_rules_table[rule_index].rule_name);
//printk("direction :%s",direction_string);
//printk("rule direction :%u",fw_rules_table[rule_index].direction);
//printk("src_ip :%s",src_ip);
//printk("rule src_ip :%u",fw_rules_table[rule_index].src_ip);
//printk("rule.src_prefix_size :%u",fw_rules_table[rule_index].src_prefix_size);
//printk("rule.src_prefix_mask :%u",fw_rules_table[rule_index].src_prefix_mask);
//printk("dst_ip :%s",dst_ip);
//printk("rule dst_ip :%u",fw_rules_table[rule_index].dst_ip);
//printk("rule.dst_prefix_size :%u",fw_rules_table[rule_index].dst_prefix_size);

//printk("src_port :%s",src_port_string);
//printk("rule.src_port :%u",fw_rules_table[rule_index].src_port);
//printk("dst_port :%s",dst_port_string);
//printk("rule.dst_port :%u",fw_rules_table[rule_index].dst_port);
//printk("protocol :%s",protocol_string);
//printk("rule.protocol :%u",fw_rules_table[rule_index].protocol);
//printk("ack :%s",ack_string);
//printk("rule ack :%u",fw_rules_table[rule_index].ack);
//printk("action :%s",action_string);
//printk("rule action :%u",fw_rules_table[rule_index].action);




rule_index++;

printk("number of rules is %d",rule_index);

}






	
return count;	


 
}

// 0 is the defualt value for "any", so if any parameter is 0
// we should just ignore it and check the others


int if_any_are_zero_but_others_match(struct packet_info *info,rule_t rule){

int items[4];
int i;


items[0]= rule.src_ip;
items[1]= rule.dst_ip;
items[0]= rule.src_port;
items[1]= rule.dst_port;


for(i=0;i<4;i++){

if(items[i] != 0){

if(i==0 && rule.src_ip != info->src_ip)
return 0;

else if (i==1 && rule.dst_ip != info->dst_ip)
return 0;

else if (i==2 && rule.src_port!= info->src_port)
return 0;

else if (i==3 && rule.dst_port!= info->dst_port)
return 0;

} 

}


return 1;


}

// a function that checks if a packet matches a rule
int packet_matches_rule(int k,struct packet_info *info){

rule_t rule;

if(rule_index < k){
printk(KERN_INFO "rule table module: less than %d rules. Will exit now..\n",k);
     return -EIO;
}



else{

rule = fw_rules_table[k];




//printk("comparing to rule number %d",k);

//printk("rule data = \n");
//printk("rule.src_ip = %u\n",rule.src_ip);
//printk("rule.dst_ip = %u\n",rule.dst_ip);
//printk("protocol = %u\n",rule.protocol);
//printk("rule.src_port = %u\n",rule.src_port);
//printk("rule.dst_port = %u\n",rule.dst_port);





//printk("info data = \n");
//printk("info->src_ip = %u\n",info->src_ip);
//printk("info->dst_ip = %u\n",info->dst_ip);
//printk("protocol = %u\n",info->protocol);
//printk("info->src_port = %u\n",info->src_port);
//printk("info->dst_port= %u\n",info->dst_port);


if ((rule.src_ip == info->src_ip

&&
rule.dst_ip == info->dst_ip

&&
rule.src_port == info->src_port

&&
rule.dst_port == info->dst_port)

||

if_any_are_zero_but_others_match(info,rule) == 1)




{



printk("rule in table!");






return 1;
}

}

return 0;


}

int decide_on_packet(struct packet_info *info){
int i;
rule_t rule;


for(i=0;i<rule_index;i++){


rule = fw_rules_table[i];

if(packet_matches_rule(i,info)==1)
    return 1;

}

return 0;

}




static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO , display, modify);

int simple_rule_table_init(void)
{

int ret;


	//create char device
	major_number = register_chrdev(0, "rules", &fops);\
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	sysfs_class = (struct class*)class_create(THIS_MODULE, "fw");
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(major_number, "rules");
		return -1;
	}
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "rules");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "rules");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "rules");
		return -1;
	}




   //actual module related init 	
   ret = 0;
        my_ipt = (rule_t *)vmalloc(sizeof(rule_t));
    
    if (!my_ipt)
        ret = -ENOMEM;

    else{

        memset((char *)my_ipt, 0, sizeof(rule_t));
        rule_index = 0;
       next_rule_ctr = 0;
       num_of_rules = 0;
     
}


	return 0;
}

void simple_rule_table_cleanup(void)
{
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	//class_destroy(sysfs_class);
	unregister_chrdev(major_number, "rules");

}

EXPORT_SYMBOL(decide_on_packet);
EXPORT_SYMBOL(sysfs_class);
//module_init(simple_rule_table_init);
//module_exit(simple_rule_table_exit);



