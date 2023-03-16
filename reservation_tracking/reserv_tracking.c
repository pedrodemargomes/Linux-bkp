#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/console.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/bootmem.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mm_inline.h>
#include <linux/huge_mm.h>
#include <linux/page_idle.h>
#include <linux/ksm.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/freezer.h>
#include <linux/compaction.h>
#include <linux/mmzone.h>
#include <linux/node.h>
#include <linux/workqueue.h>
#include <linux/khugepaged.h>
#include <linux/hugetlb.h>
#include <linux/migrate.h>
#include <linux/balloon_compaction.h>
#include <linux/pagevec.h>
#include <linux/random.h>
#include <asm/uaccess.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <linux/jiffies.h>
#include "../../../fs/proc/internal.h" 
#include "../mm/internal.h"

#include <reservation_tracking/reserv_tracking.h>
#include <linux/mem_reservations.h>

DEFINE_SPINLOCK(osa_hpage_list_lock);
DECLARE_WAIT_QUEUE_HEAD(osa_hpage_scand_wait);
static struct workqueue_struct *osa_hpage_scand_wq __read_mostly;
static struct work_struct osa_hpage_scan_work;

static unsigned int scan_sleep_millisecs = 4000;
static unsigned long sleep_expire;

static ssize_t alloc_scan_sleep_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
	return sprintf(buf, "%u\n", scan_sleep_millisecs);
}

static ssize_t alloc_scan_sleep_store(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	unsigned long msecs;
	int err;

	err = kstrtoul(buf, 10, &msecs);
	if (err || msecs > UINT_MAX)
		return -EINVAL;

	scan_sleep_millisecs = msecs;
	sleep_expire = 0;
	// wake_up_interruptible(&osa_hpage_scand_wait);
	return count;
}
static struct kobj_attribute alloc_sleep_millisecs_attr =
	__ATTR(scan_sleep_millisecs, 0644, alloc_scan_sleep_show,
	       alloc_scan_sleep_store);

static struct attribute *reserve_tracking_attr[] = {
	&alloc_sleep_millisecs_attr.attr,
	NULL,
};

struct attribute_group reserve_tracking_attr_group = {
	.attrs = reserve_tracking_attr,
	.name = "reserv_tracking",
};


static int osa_hpage_scand_wait_event(void)
{
	return scan_sleep_millisecs; //&& !list_empty(&osa_hpage_scan_list);
}

static int osa_hpage_scand_has_work(void)
{
	return scan_sleep_millisecs; //&& !list_empty(&osa_hpage_scan_list);
}


static void osa_hpage_scand_wait_work(void) 
{
	if (osa_hpage_scand_has_work()) {
		sleep_expire = jiffies + msecs_to_jiffies(scan_sleep_millisecs);
		wait_event_freezable_timeout(osa_hpage_scand_wait,
				kthread_should_stop() || time_after_eq(jiffies, sleep_expire),
				msecs_to_jiffies(scan_sleep_millisecs));
	}

	wait_event_freezable(osa_hpage_scand_wait, osa_hpage_scand_wait_event());
}

void osa_hpage_enter_list(struct rm_entry *rm_entry)
{
	spin_lock(&osa_hpage_list_lock);
	rm_entry->part_pop = true;
	list_add_tail(&rm_entry->osa_hpage_scan_link, &osa_hpage_scan_list);
	spin_unlock(&osa_hpage_list_lock);
}

void osa_hpage_exit_list(struct rm_entry *rm_entry)
{
	VM_BUG_ON(!rm_entry);
	if (!rm_entry->part_pop)
		return;
	
	spin_lock(&osa_hpage_list_lock);
	list_del(&rm_entry->osa_hpage_scan_link);
	rm_entry->part_pop = false;
	spin_unlock(&osa_hpage_list_lock);
}

void osa_hpage_do_scan(void)
{
	struct rm_entry *rm_entry, *aux;
	int err, i;
	unsigned int timestamp;
	spinlock_t  *next_lock;

	// pr_alert("osa_hpage_do_scan");

	int list_size = 0;
	int num_freed = 0;

	// PROBLEMA
	/*
	COMPACT									PROCESS rm_release_reservation
	spin_lock(&osa_hpage_list_lock);		
											spin_lock(next_lock);
	spin_lock(next_lock);					
											spin_lock(&osa_hpage_list_lock);
	
	*/
	
	// Scanning partial populated reservations
	spin_lock(&osa_hpage_list_lock);
	list_for_each_entry_safe(rm_entry, aux, &osa_hpage_scan_list, osa_hpage_scan_link) {
		list_size++;
		timestamp = rm_entry->timestamp;
		if (jiffies_to_msecs(jiffies) - timestamp > 5000) {
			// pr_alert("timestamp = %u", jiffies_to_msecs(jiffies) - timestamp);

			next_lock = &rm_entry->lock;
			if (spin_trylock(next_lock)) {
				// pr_alert("rm_release_reservation_fast rm_entry->head = %ld", page_to_pfn(get_page_from_rm((unsigned long)(rm_entry->next_node))) );
				rm_release_reservation_fast(rm_entry);
				spin_unlock(next_lock);
				num_freed++;
			}
			if (num_freed > 1000)
				break;

		}
	}
	spin_unlock(&osa_hpage_list_lock);

	pr_info("list_size = %d", list_size);

	return;
}


static void osa_hpage_scand(struct work_struct *ws)
{
	set_freezable();
	set_user_nice(current, MAX_NICE);

	while(1) {
		osa_hpage_do_scan();
		osa_hpage_scand_wait_work();
	}

	return ;
}

static int start_stop_osa_hpage_scand(void)
{
	int err = 0;

	pr_alert("start_stop_osa_hpage_scand");

	if (!osa_hpage_scand_wq) {
		osa_hpage_scand_wq = create_singlethread_workqueue("osa_hpage_scand");

		if (osa_hpage_scand_wq) {
			//schedule_work(osa_hpage_scan_work);
			INIT_WORK(&osa_hpage_scan_work, osa_hpage_scand);
			queue_work(osa_hpage_scand_wq, &osa_hpage_scan_work);
		}
	}

	// if (!list_empty(&osa_hpage_scan_list))
	wake_up_interruptible(&osa_hpage_scand_wait);

fail:
	return err;
}

int reserve_tracking_init_sysfs(void) {
	int err;

	struct kobject *sysfs_reserve_tracking_kobj = kobject_create_and_add("reserve_tracking", mm_kobj);
	if (unlikely(!sysfs_reserve_tracking_kobj)) {
		pr_err("failed to create reserv tracking kobject\n");
		return -ENOMEM;
	}

	if (unlikely(!sysfs_reserve_tracking_kobj)) {
		pr_err("failed to create reserv tracking sys kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(sysfs_reserve_tracking_kobj, &reserve_tracking_attr_group);
	if (err) {
		pr_err("failed to register reserv tracking sys group\n");
		goto delete_kobj;
	}

	return 0;

delete_kobj:
	kobject_put(sysfs_reserve_tracking_kobj);
	return err;
}

static int __init osa_hugepage_init(void)
{
	int err;

	INIT_LIST_HEAD(&osa_hpage_scan_list);

	// err = start_stop_osa_hpage_scand();
	// if (err)
	// 	goto err_sysfs;

	// /* init sysfs */
	// err = reserve_tracking_init_sysfs();
	// if (err)
	// 	goto err_sysfs;

	return 0;

	/* not need yet */
	// osa_hugepage_exit_sysfs(hugepage_kobj);
err_sysfs:
	return err;
}
subsys_initcall(osa_hugepage_init);