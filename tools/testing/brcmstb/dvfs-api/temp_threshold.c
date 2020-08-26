#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/clk.h>
#include <linux/brcmstb/brcmstb.h>
#include <linux/delay.h>

/*
 * USAGE:
 *   insmod temp_threshold.ko  [temp=<int>]
 *
 * EXAMPLES:
 *
 *   insmod temp_threshold.ko temp=99
 *
 * NOTE:
 *   The insmod will always fail to do the insmod operation but
 *   should execute the temp thresold setting this is by design so the
 *   user does not have to keep running an rmmod for every insmod.
 */


/*
 * Stand-alone build example:
 *
 * $ cat Makefile
 * obj-m += temp_threshold.o
 * $ make ARCH=arm64 CROSS_COMPILE=aarch64-linux- \
 *	-C /work3/kd923030/git/stblinux-49/linux SUBDIRS=$PWD modules
 */


static int temp = 80;
module_param(temp, int, 0660);

static int temp_threshold_init(void)
{
	int ret;

	if (temp > 120 || temp < 40) {
		pr_info("USAGE:\n  insmod temp_threshold.ko [temp=<int>]\n");
		pr_info("EXAMPLE:\n");
		pr_info("\tinsmod temp_threshold.ko temp=75\n");
		return -EIO;
	}

	ret = brcm_overtemp_reset(temp);

	pr_info("%s:%d reset temp %d\n\n", ret ? "FAILED" : "Succeeded",
		ret, temp);

	return -EIO;
}


static void temp_threshold_exit(void)
{
}

module_init(temp_threshold_init);
module_exit(temp_threshold_exit);
MODULE_LICENSE("GPL");
