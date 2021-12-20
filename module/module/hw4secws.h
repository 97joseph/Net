#ifndef __FIREWALL_H
#define __FIREWALL_H

#define BUFFER_SIZE 256


/**rule_table**/
 //struct class* sysfs_class;
 int simple_rule_table_init(void);
void simple_rule_table_cleanup(void);
/**hook**/

 int simple_hook_init(void);
void simple_hook_cleanup(void);
/**show_log**/

static log_row_t log_array[BUFFER_SIZE+1][BUFFER_SIZE];

 int simple_show_log_init(void);
void simple_show_log_cleanup(void);


/**reset_log**/
 int simple_reset_log_init(void);
void simple_reset_log_cleanup(void);

/**connections**/
 int simple_conns_init(void);
void simple_conns_cleanup(void);
#endif 
