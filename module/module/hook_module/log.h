#ifndef __LOG_H
#define __LOG_H
#include <linux/klist.h>

#include "../rule_table_module/fw.h"

typedef struct packet_info {
__be32	src_ip;
__be32	dst_ip;
__be16	src_port;
__be16	dst_port;
__u8	protocol;
__u8	action;
reason_t reason;
int count;
unsigned long time;
}packet_info;


struct klist_packet_list {
    struct packet_info info;
    struct list_head list;
    int size;
};




typedef struct connection_info {
__be32	src_ip;
__be32	dst_ip;
__be16	src_port;
__be16	dst_port;
int state;
}connection_info;


struct klist_conns_list {
    struct connection_info info;
    struct list_head list;
    int size;
};

/**rule table**/
int decide_on_packet(struct packet_info *info);


void insert_to_conns_list(log_row_t * log_row);

int if_connection_in_connections_list(connection_info * connection);


void change_state(log_row_t * log_row,int ack);

#endif 






