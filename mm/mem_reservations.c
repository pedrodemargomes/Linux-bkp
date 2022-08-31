/*
 * mm/mem_reservations.c - mechanism for reserving 32KB chunks of physical memory 
 *                         to accelerate page walks when running under virtualization
 *
 * Copyright 2020, Artemiy Margaritov <artemiy.margaritov@ed.ac.uk>
 * Released under the General Public License (GPL).
 *
 */

#include <linux/mm.h>
#include <linux/slab.h> 
#include <linux/highmem.h>
#include <linux/vmstat.h>
#include <linux/mem_reservations.h>
#include <linux/pagemap.h>

struct rm_node* rm_node_create() {
  struct rm_node* new = NULL;
  unsigned int i;
  new = kmalloc(sizeof(struct rm_node), GFP_KERNEL & ~__GFP_DIRECT_RECLAIM);
  if (new) {
    for (i = 0; i < RT_NODE_RANGE_SIZE; i++) {
      spin_lock_init(&new->items[i].lock);
      new->items[i].next_node = NULL;
    }
  }
  return new;
}

extern void rm_release_reservation(struct vm_area_struct *vma, unsigned long address) {
  unsigned char level;
  unsigned int i;
  unsigned int index;
  int unused;

  struct rm_node *cur_node = GET_RM_ROOT(vma);
  struct rm_node *next_node;
  
  unsigned long leaf_value;
  unsigned long *mask;

  struct page *page;
  spinlock_t  *next_lock;

  gfp_t gfp           = ((GFP_HIGHUSER | __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM);
	unsigned long haddr = address & RESERV_MASK; 
  int region_offset   = (address & (~RESERV_MASK)) >> PAGE_SHIFT;
  bool my_app         = true;//(vma->vm_mm->owner->pid == 5555);

  if (!my_app) 
    return;
  if (cur_node == NULL) 
    return;
  if (!vma_is_anonymous(vma)) {
    return;
  }

  // traverse the reservation map radix tree
  // firstly, go through all levels but don't go to the leaf node
  for (level = 1; level < NUM_RT_LEVELS; level++) {
    index = get_node_index(level, address);
    next_lock = &cur_node->items[index].lock;
    next_node = cur_node->items[index].next_node;

    if (unlikely(next_node == NULL)) {
      spin_lock(next_lock);
      if (next_node == NULL) {
        cur_node->items[index].next_node = rm_node_create();
      }
      spin_unlock(next_lock);
    }

    cur_node = cur_node->items[index].next_node;
  }

  // secondly, process the leaf node
  level = NUM_RT_LEVELS;
  index = get_node_index(level, address); 
  next_lock = &cur_node->items[index].lock;

  spin_lock(next_lock);
  leaf_value = (unsigned long)(cur_node->items[index].next_node);
  mask = (unsigned long *)(cur_node->items[index].mask);
  if (leaf_value != 0) { 
    page = get_page_from_rm(leaf_value);
    unused = 512 - bitmap_weight(mask, 512);
    if (unused) {
      mod_node_page_state(page_pgdat(page), NR_MEM_RESERVATIONS_RESERVED, -unused);
    }
    
    pr_alert("rm_release PageTransCompound(page) = %d page_to_pfn(page) = %ld page_count(page) = %d", PageTransCompound(page), page_to_pfn(page), page_count(page));
    if (PageTransCompound(page)) {
      // pr_alert("rm_release huge page page_to_pfn(page) = %ld", page_to_pfn(page));
      // lock_page(page);
      // int ret = split_huge_page(page);
      // unlock_page(page);
      // if (ret) {
      //   pr_alert("rm_release split_huge_page FAIL ret = %d page_to_pfn(page) = %ld page_count(page) = %d", ret, page_to_pfn(page), page_count(page));
      //   put_page(page);
      // } else {
      //   pr_alert("rm_release split_huge_page SUC page_to_pfn(page) = %ld page_count(page) = %d", page_to_pfn(page), page_count(page));
      //   for (i = 0; i < RESERV_NR; i++) {
      //     put_page(page + i);
      //   }
      // }
      put_page(page);
    } else {
      for (i = 0; i < RESERV_NR; i++) {
        put_page(page + i);
      }
    }
    // pr_alert("rm_release END page_count(page) = %d PageTransCompound(page) = %d", page_count(page), PageTransCompound(page)); // 0 1 2 3

    cur_node->items[index].next_node = 0; 
  }
  spin_unlock(next_lock);
  return;
}

bool check_from_reservation(struct vm_area_struct *vma, unsigned long address) {
  unsigned char level;
  unsigned int i;
  unsigned int index;

  struct rm_node *cur_node = GET_RM_ROOT(vma);
  struct rm_node *next_node;
  
  unsigned long leaf_value;

  struct page *page;
  spinlock_t  *next_lock;

  gfp_t gfp           = ((GFP_HIGHUSER | __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM);
	unsigned long haddr = address & RESERV_MASK; 
  int region_offset   = (address & (~RESERV_MASK)) >> PAGE_SHIFT;
  bool my_app         = true;//(vma->vm_mm->owner->pid == 5555);

  if (!my_app) 
    return false;
  if (cur_node == NULL) 
    return false;
  if (!vma_is_anonymous(vma)) {
    return false;
  }

  // traverse the reservation map radix tree
  // firstly, go through all levels but don't go to the leaf node
  for (level = 1; level < NUM_RT_LEVELS; level++) {
    index = get_node_index(level, address);
    next_lock = &cur_node->items[index].lock;
    next_node = cur_node->items[index].next_node;

    if (unlikely(next_node == NULL)) {
      spin_lock(next_lock);
      if (next_node == NULL) {
        cur_node->items[index].next_node = rm_node_create();
      }
      spin_unlock(next_lock);
    }

    cur_node = cur_node->items[index].next_node;
  }

  // secondly, process the leaf node
  level = NUM_RT_LEVELS;
  index = get_node_index(level, address); 
  next_lock = &cur_node->items[index].lock;

  spin_lock(next_lock);
  leaf_value = (unsigned long)(cur_node->items[index].next_node);
  spin_unlock(next_lock);
  if (leaf_value != 0) { 
    return true;
  } else {
    return false;
  }
}

struct page *rm_alloc_from_reservation(struct vm_area_struct *vma, unsigned long address) {
  int retPrmtHugePage;

  unsigned char level;
  unsigned int i;
  unsigned int index;

  struct rm_node *cur_node = GET_RM_ROOT(vma);
  struct rm_node *next_node;
  
  unsigned long leaf_value;
  unsigned long *mask;

  struct page *page, *head;
  spinlock_t  *next_lock;

  gfp_t gfp           = ((GFP_HIGHUSER | __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM);
	unsigned long haddr = address & RESERV_MASK; 
  int region_offset   = (address & (~RESERV_MASK)) >> PAGE_SHIFT;
  bool my_app         = true;//(vma->vm_mm->owner->pid == 5555);

  if (!my_app) 
    return NULL;
  if (cur_node == NULL) 
    return false;
  if (!vma_is_anonymous(vma)) {
    return NULL;
  }

  // traverse the reservation map radix tree
  // firstly, go through all levels but don't go to the leaf node
  for (level = 1; level < NUM_RT_LEVELS; level++) {
    index = get_node_index(level, address);
    next_lock = &cur_node->items[index].lock;
    next_node = cur_node->items[index].next_node;

    if (unlikely(next_node == NULL)) {
      spin_lock(next_lock);
      if (next_node == NULL) {
        cur_node->items[index].next_node = rm_node_create();
      }
      spin_unlock(next_lock);
    }

    cur_node = cur_node->items[index].next_node;
  }

  // secondly, process the leaf node
  level = NUM_RT_LEVELS;
  index = get_node_index(level, address); 
  next_lock = &cur_node->items[index].lock;

  spin_lock(next_lock);
  leaf_value = (unsigned long)(cur_node->items[index].next_node);
  mask = (unsigned long *)(cur_node->items[index].mask);
  head = page = get_page_from_rm(leaf_value);
  if (leaf_value == 0) { //create a new reservation if not present
    // allocate pages 
    page = alloc_pages_vma(gfp, RESERV_ORDER, vma, haddr, numa_node_id(), false);
    if (!page){
      pr_alert("alloc_pages_vma FAILED");
      return page;
    }
    for (i = 0; i < RESERV_NR; i++) {
      set_page_count(page + i, 1);
    }
    // create a leaf node
    leaf_value = create_value(page);
    bitmap_zero(mask, 512);

    mod_node_page_state(page_pgdat(page), NR_MEM_RESERVATIONS_RESERVED, RESERV_NR - 1);
    count_vm_event(MEM_RESERVATIONS_ALLOC);
  } else {
    mod_node_page_state(page_pgdat(page), NR_MEM_RESERVATIONS_RESERVED, -1);
    if (PageTransCompound(page)) {
      // pr_alert("rm_alloc INIT page_count(page) = %d PageTransCompound(page) = %d", page_count(page), PageTransCompound(page));
      goto out_unlock;
    }
  }
  page = page + region_offset;
  
  // mark the page as used
  set_bit(region_offset, mask);
  cur_node->items[index].next_node = (void*)(leaf_value);
  get_page(page);
  clear_user_highpage(page, address);

  if (PageTransCompound(page)) {
    pr_alert("rm_alloc INIT page_count(page) = %d PageTransCompound(page) = %d bitmap_weight(mask, 512) = %d page_to_pfn(head) = %ld", page_count(page), PageTransCompound(page), bitmap_weight(mask, 512), page_to_pfn(page)); // 2
  }
  if (bitmap_weight(mask, 512) >= 400) {
    if (PageTransCompound(page)) {
      // pr_alert("rm_alloc INIT page_count(page) = %d PageTransCompound(page) = %d", page_count(page), PageTransCompound(page));
      goto out_unlock;
    }
    retPrmtHugePage = promote_huge_page_address(vma, head, haddr);
    pr_alert("rm_alloc promote page retPrmtHugePage = %d page_to_pfn(head) = %ld page_count(page) = %d", retPrmtHugePage, page_to_pfn(head), page_count(page));
    // pr_alert("END page_count(head) = %d PageTransHuge(head) = %d ret promote_huge_pmd_address = %d", page_count(head), PageTransHuge(head), retPrmtHugePage);
    spin_unlock(next_lock);
    if (!retPrmtHugePage) {
      // pr_alert("total_mapcount(head) = %d  == page_count(head) = %d ", total_mapcount(head), page_count(head));
      return head;
    }
    return page;
  }

out_unlock:
  spin_unlock(next_lock);
  return page;
}

void rm_destroy(struct rm_node *node, unsigned char level) { //not thread-safe 
  unsigned int index;
  int i;
  struct rm_node *cur_node = node;
  unsigned long *mask;
  unsigned char unused;
  struct page *page;
  unsigned long leaf_value;

  // traverse the reservaton map radix tree
  for (index = 0; index < RT_NODE_RANGE_SIZE; index++) {
    if (cur_node->items[index].next_node != NULL) {
      if (level != 4) {
        rm_destroy(cur_node->items[index].next_node, level + 1);
      } else {
        leaf_value = (unsigned long)(cur_node->items[index].next_node);
        mask = (unsigned long *)(cur_node->items[index].mask);
        page = get_page_from_rm(leaf_value);

        unused = 512 - bitmap_weight(mask, 512);
        if (unused) {
          mod_node_page_state(page_pgdat(page), NR_MEM_RESERVATIONS_RESERVED, -unused);
        }
        
        // pr_alert("rm_destroy INIT page_count(page) = %d PageTransCompound(page) = %d", page_count(page), PageTransCompound(page));
        pr_alert("rm_destroy PageTransCompound(page) = %d page_to_pfn(page) = %ld page_count(page) = %d", PageTransCompound(page), page_to_pfn(page), page_count(page));
        if (PageTransCompound(page)) {
        //   lock_page(page);
        //   int ret = split_huge_page(page);
        //   unlock_page(page);
        //   if (ret) {
        //     pr_alert("rm_destroy split_huge_page FAIL ret = %d page_to_pfn(page) = %ld", ret, page_to_pfn(page));
        //     put_page(page);
        //   } else {
        //     pr_alert("rm_destroy split_huge_page SUC page_to_pfn(page) = %ld", page_to_pfn(page));
        //     for (i = 0; i < RESERV_NR; i++) {
        //       put_page(page + i);
        //     }
        //   }
          put_page(page);
        } else {
          for (i = 0; i < RESERV_NR; i++) {
            put_page(page + i);
          }
        }
        // pr_alert("rm_destroy END page_count(page) = %d PageTransCompound(page) = %d", page_count(page), PageTransCompound(page)); // 0

      }
    }
  }
  kfree(cur_node);
  return;
}
