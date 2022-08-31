/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_MEM_RESEVATIONS_H
#define _LINUX_MEM_RESEVATIONS_H

#include <linux/spinlock.h>
#include <linux/mm_types.h>
#include <linux/types.h>

#define RESERV_ORDER           9
#define RESERV_SHIFT           (RESERV_ORDER + PAGE_SHIFT) // 9 + 12 = 21
#define RESERV_SIZE            ((1UL) << RESERV_SHIFT)     // 00000000001000000000000000000000
#define RESERV_MASK            (~( RESERV_SIZE - 1))       // 11111111111000000000000000000000 
#define RESERV_NR              ((1UL) << RESERV_ORDER)     // 00000000000000000000001000000000 
#define RESERV_GROUP_NR_IN_PMD (HPAGE_PMD_NR / RESERV_NR)  // 512 / 512 = 1
#define RESERV_OFFSET_MASK     ((1UL << RESERV_ORDER) - 1) // 00000000000000000000000111111111 

#define CHECK_BIT(var,pos) ((var) &  (1<<(pos)))
#define SET_BIT(var,pos)   ((var) |= (1<<(pos)))
#define UNSET_BIT(var,pos) ((var) &= (~(1<<(pos))))

#define NUM_RT_LEVELS         4
#define RT_LEVEL_INDEX_LENGTH 9 
#define RT_NODE_RANGE_SIZE    ((1 << RT_LEVEL_INDEX_LENGTH)) // 512
#define GET_RM_ROOT(vma)      (vma->vm_mm->memory_reservations)

struct rm_entry {
  void       *next_node;
  spinlock_t lock;
  DECLARE_BITMAP(mask, 512); // unsigned long *
};

struct rm_node {
  struct rm_entry items[RT_NODE_RANGE_SIZE];
};

static inline unsigned int get_node_index(unsigned char level, unsigned long address) {
  unsigned int level_mask = (1 << RT_LEVEL_INDEX_LENGTH) - 1;
  unsigned int total_bit_num_shift = RESERV_SHIFT + ((NUM_RT_LEVELS - level) * RT_LEVEL_INDEX_LENGTH);
  return (address >> total_bit_num_shift) & level_mask;
}

static inline unsigned long create_value(struct page *page) {
  unsigned long new_value = (unsigned long)(page);
  // unsigned long new_mask = mask;
  new_value &= ((1L << 56) - 1);
  // new_value |= (new_mask << 56);
  return new_value;
}

static inline struct page *get_page_from_rm(unsigned long leaf_value) {
  const unsigned long kernel_addr_begin = 255;
  leaf_value &= ((1L << 56) - 1);
  leaf_value |= (kernel_addr_begin << 56); //ff0000...0000
  return (struct page*)(leaf_value);
}

static inline unsigned char get_mask_from_rm(unsigned long leaf_value) {
  return (unsigned char)(leaf_value >> 56);
}

// static inline unsigned long update_mask(unsigned long leaf_value, unsigned char new_mask) {
//   struct page *page = get_page_from_rm(leaf_value); 
//   return create_value(page, new_mask);
// }

extern struct rm_node *rm_node_create(void); 
extern struct page *rm_alloc_from_reservation(struct vm_area_struct *vma, unsigned long address);
extern int rm_set_unused(struct vm_area_struct *vma, unsigned long address);
extern void rm_destroy(struct rm_node *node, unsigned char level); 

extern bool check_from_reservation(struct vm_area_struct *vma, unsigned long address);

extern void rm_release_reservation(struct vm_area_struct *vma, unsigned long address);

#endif /* _LINUX_MEM_RESEVATIONS_H */