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
#include "../../../fs/proc/internal.h" 
#include "../mm/internal.h"

#include <reservation_tracking/reserv_tracking.h>

#define SEC_SCAN_COUNT 0x8

unsigned long active_bpage_count = 0;

DEFINE_SPINLOCK(osa_page_set_lock);
DEFINE_SPINLOCK(osa_hpage_list_lock);
DECLARE_WAIT_QUEUE_HEAD(osa_hpage_scand_wait);
static struct workqueue_struct *osa_hpage_scand_wq __read_mostly;
static struct work_struct osa_hpage_scan_work;

unsigned int deferred_mode = 1;
struct list_head hugepage_worklist;
static util_node_t *_util_node[512];

static struct list_head osa_hot_page_set[5];
static unsigned int freq_scan_count = 0;
static unsigned int scan_sleep_millisecs = 4000;
static unsigned long count[5];

struct osa_walker_stats {
	unsigned int hpage_requirement;
	unsigned int total_hpage_count;
	unsigned long total_bpage_count;
	unsigned int idle_hpage_count;
	unsigned long idle_bpage_count;
	unsigned int idle_tau; //idle page penalty parameter
	unsigned int weight;
	//up-to-here it is the same as osa_hpage_stats
	//so casting to osa_hpage_stat is safe.
	unsigned int hit;
	unsigned int miss;
	unsigned long nopromote;
};

static int osa_hpage_scand_wait_event(void)
{
	return scan_sleep_millisecs && !list_empty(&osa_hpage_scan_list);
}

void *osa_util_node_lookup_fast(struct page *page)
{
	return (void *)&page->util_info;
}

void frequency_update(util_node_t *node) 
{
    int i;

	if (!node) 
    	return;

	node->frequency[1] = bitmap_weight(node->freq_bitmap, FREQ_BITMAP_SIZE);
	node->frequency[1] -= (3 * FREQ_BITMAP_SIZE / 4);
	node->frequency[0] = (node->frequency[0] * 70) + (node->frequency[1] * 30);
	node->frequency[0] = node->frequency[0] / 100;
}

static int osa_bpage_pte_walker(pte_t *pte, unsigned long addr,
		unsigned long end, struct mm_walk *walk)
{
    struct page *page = NULL;
	struct osa_walker_stats *walker_stats;
	unsigned long pfn;
    util_node_t *f_node;
    struct mm_struct *mm;
	int ret = 0;
	unsigned long lottery;
	uint8_t lottery_selected = 0;

	mm = (struct mm_struct *)walk->mm;
	walker_stats = (struct osa_walker_stats *)walk->private;

    if (pte && !pte_none(*pte))
        page = pte_page(*pte);

    if (page && !PageTransCompound(page)) {
		walker_stats->total_bpage_count++;

		pfn = (pte_val(*pte) & PTE_PFN_MASK) >> PAGE_SHIFT;
		page = page_idle_get_page(pfn);

		if (page) {
			page_idle_clear_pte_refs(page);

            //f_node = osa_util_node_lookup(mm, PAGE_ALIGN_FLOOR(addr));
            f_node = osa_util_node_lookup_fast(page);
			f_node->page = page;

			if (!f_node) 
				goto out;

			bitmap_shift_right(f_node->freq_bitmap, f_node->freq_bitmap, 1,
					FREQ_BITMAP_SIZE);

			if (deferred_mode >= 2) {
				// hot page: run lottery for a random sampling.
				if (f_node->frequency[0] >= 0) {
					//get_random_bytes(&lottery, sizeof(unsigned long));
					get_random_bytes_arch(&lottery, sizeof(unsigned long));
					if (!active_bpage_count)
						active_bpage_count++;
					if (lottery % active_bpage_count > 
							((active_bpage_count * 20) / 100)) {
						lottery_selected = 1;
					} else {
						lottery_selected = 0;
						clear_page_idle(page);
					}
				} else {
					// cold page: lottery is always selected.
					lottery_selected = 1;
				}
			} else
				lottery_selected = 1;

			// Clearing access bit causes a TLB miss of the address.
			if (lottery_selected) {
				page_idle_clear_pte_refs(page);

				bitmap_shift_right(f_node->freq_bitmap, f_node->freq_bitmap, 1,
						FREQ_BITMAP_SIZE);
			}

			if (page_is_idle(page)) {
				walker_stats->idle_bpage_count++;
                bitmap_clear(f_node->freq_bitmap, FREQ_BITMAP_SIZE-1, 1);
                if (f_node->frequency[0] >= 0) {
					walker_stats->miss++;
				} else {
					walker_stats->hit++;
				}
			} else {
                bitmap_set(f_node->freq_bitmap, FREQ_BITMAP_SIZE-1, 1);
                if (f_node->frequency[0] < 0) {
					walker_stats->miss++;
				} else {
					walker_stats->hit++;
				}
			}

			frequency_update(f_node);
			set_page_idle(page);
			put_page(page);

			if ((freq_scan_count % SEC_SCAN_COUNT) == 0) {
				unsigned int weight = 0, i = 0;
				if (!spin_trylock(&osa_page_set_lock))
					goto out;

				//Clear osa_flag to enable re-aggregation
				if ((freq_scan_count & 0xff) == 0)
					clear_bit(OSA_PF_AGGR, &page->osa_flag);

				for (i = FREQ_BITMAP_SIZE - 1; i > FREQ_BITMAP_SIZE - 5; i--) 
					if (test_bit(i, f_node->freq_bitmap))
						weight++;

				if (weight == 4) {
					list_add(&f_node->link, &osa_hot_page_set[0]);
					count[0]++;
				}

				spin_unlock(&osa_page_set_lock);
			}
		}
    }
out:
    return ret;
}

static int osa_hpage_pmd_walker(pmd_t *pmd, unsigned long addr,
		unsigned long end, struct mm_walk *walk)
{
	struct osa_walker_stats *walker_stats;
	struct page *page;
	unsigned long _addr, pfn;
    util_node_t *f_node;
	pte_t *pte;
    struct mm_struct *mm;
	int ret = 0;

	mm = (struct mm_struct *)walk->mm;
	walker_stats = (struct osa_walker_stats *)walk->private;

	if (pmd_trans_huge(*pmd)) {
		// Count total huge page
		walker_stats->total_hpage_count++;

		// Count Idle huge page
		pfn = (pmd_val(*pmd) & PTE_PFN_MASK) >> PAGE_SHIFT;
		page = page_idle_get_page(pfn);

		if (page) {
			page_idle_clear_pte_refs(page);
			//f_node = osa_util_node_lookup(mm, HPAGE_ALIGN_FLOOR(addr));

			VM_BUG_ON(!PageCompound(page));
			f_node = osa_util_node_lookup_fast(page);
			f_node->page = page;

			if (!f_node)
				goto out;

			bitmap_shift_right(f_node->freq_bitmap, f_node->freq_bitmap, 1,
					FREQ_BITMAP_SIZE);

			if (page_is_idle(page)) {
				walker_stats->idle_hpage_count++;
				bitmap_clear(f_node->freq_bitmap, FREQ_BITMAP_SIZE-1, 1);
				if (f_node->frequency[0] > 0) {
					walker_stats->miss += 512;
				} else {
					walker_stats->hit += 512;
				}
			}
			else {
				bitmap_set(f_node->freq_bitmap, FREQ_BITMAP_SIZE-1, 1);
				if (f_node->frequency[0] < 0) {
					walker_stats->miss += 512;
				} else {
					walker_stats->hit += 512;
				}
			}

			frequency_update(f_node);
			set_page_idle(page);
			put_page(page);
		}
	} else {
		// Walk PTE
		pte = pte_offset_map(pmd, addr);

		_addr = addr;

		for (;;) {
			ret = osa_bpage_pte_walker(pte, _addr, _addr + PAGE_SIZE, walk);
			if (ret)
				break;

			_addr += PAGE_SIZE;
			if (_addr == end)
				break;

			pte++;
		}
	}
out:
	return ret;
}

static int osa_hpage_scand_has_work(void)
{
	return scan_sleep_millisecs && !list_empty(&osa_hpage_scan_list);
}


static void osa_hpage_scand_wait_work(void) 
{
	if (osa_hpage_scand_has_work()) {
		wait_event_freezable_timeout(osa_hpage_scand_wait,
				0,
				msecs_to_jiffies(scan_sleep_millisecs));
	}

	wait_event_freezable(osa_hpage_scand_wait, osa_hpage_scand_wait_event());
}

/* scanner kthread */
static int osa_hpage_do_walk(struct mm_struct *mm, 
		struct osa_walker_stats *walker_stats) 
{
	int err = 0;
	unsigned int hpage_requirement = 0;
	unsigned long haddr;
	unsigned int anon_rss;
	struct vm_area_struct *vma = NULL;
	struct mm_walk _hpage_walker = {
		.pmd_entry = osa_hpage_pmd_walker,
		.mm = mm,
		.private = walker_stats,
	};

	VM_BUG_ON(!mm);

	vma = mm->mmap;

	walker_stats->hpage_requirement = 0;
	walker_stats->miss = 0;
	walker_stats->hit = 0;
	walker_stats->nopromote = 0;

	for ( ;vma != NULL; vma = vma->vm_next) {
		if (!vma_is_anonymous(vma))
			continue;
			
		//Entire VMA scanning.
		err = walk_page_vma(vma, &_hpage_walker);

		if (err) {
			trace_printk("error in vma walk\n");
			return err;
		}

		if (transparent_hugepage_enabled(vma)) {
			for (haddr = HPAGE_ALIGN_FLOOR(vma->vm_start); haddr < vma->vm_end; 
					haddr += HPAGE_PMD_SIZE) 
				hpage_requirement++;
		}

		cond_resched();
	}

	mm->hpage_stats.total_hpage_count = walker_stats->total_hpage_count;
	mm->hpage_stats.total_bpage_count = walker_stats->total_bpage_count;
	mm->hpage_stats.idle_hpage_count = walker_stats->idle_hpage_count;
	mm->hpage_stats.idle_bpage_count = walker_stats->idle_bpage_count;

	active_bpage_count = walker_stats->total_bpage_count - 
		walker_stats->idle_bpage_count;

	anon_rss = get_mm_counter(mm, MM_ANONPAGES);
	/* hpage_requirment is represented in terms of # of huge page */
	mm->hpage_stats.hpage_requirement = anon_rss / 512;

	return 0;
}

void osa_hpage_enter_list(struct mm_struct *mm)
{
	spin_lock(&osa_hpage_list_lock);
	list_add_tail_rcu(&mm->osa_hpage_scan_link, &osa_hpage_scan_list);
	spin_unlock(&osa_hpage_list_lock);
}

void osa_hpage_exit_list(struct mm_struct *mm)
{
	spin_lock(&osa_hpage_list_lock);

	VM_BUG_ON(!mm);

	list_del_rcu(&mm->osa_hpage_scan_link);

	spin_unlock(&osa_hpage_list_lock);
}

void osa_hpage_do_scan(void)
{
	struct mm_struct *mm;
	struct task_struct *tsk;
	struct osa_walker_stats walker_stats; 
	int err, i;

	/* check the performance of this function */
	drain_all_pages(NULL);

	freq_scan_count &= 0xffffffff;

	freq_scan_count++;

	if ((freq_scan_count % SEC_SCAN_COUNT) == 0) {
		spin_lock(&osa_page_set_lock);

		for (i = 0; i < 5; i++) {
			INIT_LIST_HEAD(&osa_hot_page_set[i]);
			count[i] = 0;
		}

		spin_unlock(&osa_page_set_lock);
	}

	pr_alert("osa_hpage_do_scan");

	// Scanning per-application anonymous pages
	list_for_each_entry_rcu(mm, &osa_hpage_scan_list, osa_hpage_scan_link) {
		pr_alert("mm = %p", mm);
		if (!mm) 
			continue;

		pr_alert("atomic_read(&mm->mm_users) = %d", atomic_read(&mm->mm_users));
		if (atomic_read(&mm->mm_users) == 0)
			continue;

		pr_alert("mm->hpage_stats.weight = %d", mm->hpage_stats.weight);
		// for debugging
		if (!mm->hpage_stats.weight)
			continue;

		rcu_read_lock();
		tsk = rcu_dereference(mm->owner);

		pr_alert("tsk = %p", tsk);
        if (!tsk) 
            goto unlock_exit;

		pr_alert("atomic_read(&(tsk)->usage) = %d", atomic_read(&(tsk)->usage));
		if (atomic_read(&(tsk)->usage) == 0)
			goto unlock_exit;

		get_task_struct(tsk);
		mm = get_task_mm(tsk);
		rcu_read_unlock();

		VM_BUG_ON(!mm);

		memset(&walker_stats, 0, sizeof(struct osa_walker_stats));
		err = osa_hpage_do_walk(mm, &walker_stats);

		pr_alert("err = %d", err);

		if (!err) {

			pr_alert("[%d] pid %d: \n\tidle_hpage %u hpage %u idle_bpage %lu bpage %lu\n",
					current->pid, tsk->pid, 
					walker_stats.idle_hpage_count,
					walker_stats.total_hpage_count,
					walker_stats.idle_bpage_count,
					walker_stats.total_bpage_count);
			/*
			trace_printk("[%d] pid %d: hit %u miss %u\n",
					current->pid, tsk->pid, 
					walker_stats.hit, walker_stats.miss);
			*/
			/*
			trace_printk("[%d] pid %d: nopromote %lu\n",
					current->pid, tsk->pid, 
					walker_stats.nopromote);
			trace_printk("count(0) = %lu, count(1) = %lu, count(2) = %lu "
					"count(3) = %lu, count(4) = %lu\n",
					count[0], count[1], count[2], count[3], count[4]);
			*/
		}

		mmput(mm);
		put_task_struct(tsk);
	}

#if 0
	//entire physical page scan: only used for debugging
	{
	unsigned long pfn;
	struct page *page;
	//struct page_ext *page_ext;
	unsigned long total_file_mapped = 1; //avoid divided by zero
	unsigned long idle_file_mapped = 0;

	/* Buffer cache scanning */
	/* It might be overlapped with idle tracking in the above page walker
	 * when app do mmap with file. Deal with the case */
	pfn = min_low_pfn;

	while (!pfn_valid(pfn) && (pfn & (MAX_ORDER_NR_PAGES - 1)) != 0)
		pfn++;

	for (; pfn < max_pfn; pfn++) {
		if ((pfn & (MAX_ORDER_NR_PAGES - 1)) == 0 && !pfn_valid(pfn)) {
			pfn += MAX_ORDER_NR_PAGES - 1;
			continue;
		}

		/* Check for holes within a MAX_ORDER area */
		if (!pfn_valid_within(pfn))
			continue;

		//page = pfn_to_page(pfn);
		page = page_idle_get_page(pfn);

		// checked only filemapped page
		if (page && PageMappedToDisk(page)) {
			//page_ext = lookup_page_ext(page);

			total_file_mapped++;
			if (page_is_idle(page))
				idle_file_mapped++;
			
			set_page_idle(page);
			put_page(page);
		}
	}

	trace_printk("idle file page %lu, total file page %lu (ratio %ld) \n",
			idle_file_mapped, total_file_mapped, 
			(idle_file_mapped * 100) / total_file_mapped);
	}
#endif

	return;

unlock_exit:
	rcu_read_unlock();
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

	if (!list_empty(&osa_hpage_scan_list))
		wake_up_interruptible(&osa_hpage_scand_wait);

fail:
	return err;
}

static int __init osa_hugepage_init(void)
{
	int err;
	struct kobject *hugepage_kobj;

	INIT_LIST_HEAD(&osa_hpage_scan_list);
	{
		int i;
		for (i = 0; i < 5; i++) 
			INIT_LIST_HEAD(&osa_hot_page_set[i]);
	}

	err = start_stop_osa_hpage_scand();
	if (err)
		goto err_sysfs;

	/* init sysfs */
	// err = osa_hugepage_init_sysfs(&hugepage_kobj);
	// if (err)
	// 	goto err_sysfs;

	return 0;

	/* not need yet */
	// osa_hugepage_exit_sysfs(hugepage_kobj);
err_sysfs:
	return err;
}
subsys_initcall(osa_hugepage_init);