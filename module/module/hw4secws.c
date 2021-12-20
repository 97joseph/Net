#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#include "hook_module/log.h"
#include "hw4secws.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roee Ashkenazi");







static int __init simple_init(void)
{

simple_hook_init();
return 0;


}

static void __exit simple_exit(void)
{

simple_hook_cleanup();

}

module_init(simple_init);
module_exit(simple_exit);
