#ifndef _RESERV_TRACKING_H_
#define _RESERV_TRACKING_H_
#include <linux/mm.h>
#include <linux/mem_reservations.h>
#define AGGR_BITMAP_SIZE 4

#define OSA_PF_AGGR 0x1

struct pageblock {
	unsigned long start_pfn; // end_pfn = start_pfn + 512
	struct list_head list;
};

extern wait_queue_head_t osa_hpage_scand_wait;

extern spinlock_t osa_hpage_list_lock;

void osa_hpage_enter_list(struct rm_entry *rm_entry);
void osa_hpage_exit_list(struct rm_entry *rm_entry);

#endif 
