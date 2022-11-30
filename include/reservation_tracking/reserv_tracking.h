#ifndef _RESERV_TRACKING_H_
#define _RESERV_TRACKING_H_
#include <linux/mm.h>

#define AGGR_BITMAP_SIZE 4

#define OSA_PF_AGGR 0x1

extern wait_queue_head_t osa_hpage_scand_wait;

extern spinlock_t osa_hpage_list_lock;

void osa_hpage_enter_list(struct mm_struct *mm);
void osa_hpage_exit_list(struct mm_struct *mm);

#endif 
