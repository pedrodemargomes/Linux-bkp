/*
 * mm/mem_reservations.c - mechanism for reserving 32KB chunks of physical memory 
 *                         to accelerate page walks when running under virtualization
 *
 * Copyright 2020, Artemiy Margaritov <artemiy.margaritov@ed.ac.uk>
 * Released under the General Public License (GPL).
 *
 */

#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/slab.h> 
#include <linux/highmem.h>
#include <linux/vmstat.h>
#include <linux/mem_reservations.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/jiffies.h>
#include <reservation_tracking/reserv_tracking.h>
#include "internal.h"

static int hugepage_vma_revalidate(struct mm_struct *mm, unsigned long address,
		struct vm_area_struct **vmap)
{
	struct vm_area_struct *vma;
	unsigned long hstart, hend;

	*vmap = vma = find_vma(mm, address);
	if (!vma)
		return -1;

	hstart = (vma->vm_start + ~HPAGE_PMD_MASK) & HPAGE_PMD_MASK;
	hend = vma->vm_end & HPAGE_PMD_MASK;
	if (address < hstart || address + HPAGE_PMD_SIZE > hend)
		return -1;
	return 0;
}

struct rm_node* rm_node_create() {
  struct rm_node* new = NULL;
  unsigned int i;
  new = kmalloc(sizeof(struct rm_node), (GFP_KERNEL | __GFP_NOWARN) & ~__GFP_RECLAIM);
  if (new) {
    for (i = 0; i < RT_NODE_RANGE_SIZE; i++) {
      spin_lock_init(&new->items[i].lock);
      new->items[i].next_node = NULL;
    }
  } else {
    pr_alert("rm_node_create failed kmalloc");
  }
  return new;
}

extern void rm_release_reservation(struct vm_area_struct *vma, unsigned long address, bool leave_valid) {
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

	unsigned long haddr = address & RESERV_MASK; 
  int region_offset   = (address & (~RESERV_MASK)) >> PAGE_SHIFT;

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

    spin_lock(next_lock);
    if (cur_node->items[index].next_node == NULL) {
      spin_unlock(next_lock);
      return;
    }
    spin_unlock(next_lock);
    cur_node = cur_node->items[index].next_node;

  }

  // secondly, process the leaf node
  level = NUM_RT_LEVELS;
  index = get_node_index(level, address); 
  next_lock = &cur_node->items[index].lock;

  spin_lock(next_lock);
  leaf_value = (unsigned long)(cur_node->items[index].next_node);
  mask = (unsigned long *)(cur_node->items[index].mask);
  if (mark_valid_rm(leaf_value) != 0) {
    page = get_page_from_rm(leaf_value);
    osa_hpage_exit_list(&cur_node->items[index]);
    // #ifdef DEBUG_RESERV_THP
    // pr_info("rm_release PageTransCompound(page) = %d haddr = %lx address = %lx page_to_pfn(page) = %lx page_count(page) = %d total_mapcount(page) = %d page_mapcount(page) = %d is_invalid = %d", PageTransCompound(page), haddr, address, page_to_pfn(page), page_count(page), total_mapcount(page), page_mapcount(page), is_invalid_rm(leaf_value));
    // #endif
    if (PageTransCompound(page)) {
      // #ifdef DEBUG_RESERV_THP
      // struct anon_vma_chain *vmac;
      // struct vm_area_struct *vma;
      // struct anon_vma *anon_vma;
      // for (i = 0; i < RESERV_NR; i++) {
      //   // ClearPageActive(page+i);
      //   // ClearPageLRU(page+i);
      //   // struct lruvec *lruvec = mem_cgroup_page_lruvec(page, page_pgdat(page));
		  //   // del_page_from_lru_list(page, lruvec, page_lru(page));
      //   anon_vma = page_get_anon_vma(page+i);
      //   if (!anon_vma) {
      //     pr_alert("rm_release anon_vma = NULL page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
      //     continue;
      //   }
      //   pr_alert("rm_release page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
      //   anon_vma_lock_read(anon_vma);
      //   anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root, 0, ULONG_MAX) {
      //     vma = vmac->vma;
      //     if (vma && vma->vm_mm)
      //       pr_alert("vma->vm_mm->owner->pid = %d", vma->vm_mm->owner->pid);
      //   }
      //   anon_vma_unlock_read(anon_vma);
      // }
      // pr_alert("put_page");
      // #endif
      
      // pr_alert("rm_release PageTransCompound(page) = %d address = %lx page_to_pfn(page) = %ld page_count(page) = %d total_mapcount(page) = %d page_mapcount(page) = %d", PageTransCompound(page), address, page_to_pfn(page), page_count(page), total_mapcount(page), page_mapcount(page));
      // lock_page(page);
      // if(split_huge_page(page))
      //   pr_alert("split_huge_page failed");
      // unlock_page(page);
      put_page(page);

      // #ifdef DEBUG_RESERV_THP
      // for (i = 0; i < RESERV_NR; i++) {
      //   // ClearPageActive(page+i);
      //   // ClearPageLRU(page+i);
      //   // struct lruvec *lruvec = mem_cgroup_page_lruvec(page, page_pgdat(page));
		  //   // del_page_from_lru_list(page, lruvec, page_lru(page));
      //   anon_vma = page_get_anon_vma(page+i);
      //   if (!anon_vma) {
      //     pr_alert("rm_release anon_vma = NULL page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
      //     continue;
      //   }
      //   pr_alert("rm_release page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
      //   anon_vma_lock_read(anon_vma);
      //   anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root, 0, ULONG_MAX) {
      //     vma = vmac->vma;
      //     if (vma && vma->vm_mm)
      //       pr_alert("vma->vm_mm->owner->pid = %d", vma->vm_mm->owner->pid);
      //   }
      //   anon_vma_unlock_read(anon_vma);
      // }
      // #endif
    } else {
      for (i = 0; i < RESERV_NR; i++) {
        put_page(page+i);
      }
    }
    bitmap_zero(mask, 512);
    if (leave_valid)
      cur_node->items[index].next_node = 0;
    else {
      // pr_info("rm_release_reservation mark_invalid_rm Caller is %pS %pS %pS %pS %pS", __builtin_return_address(0), __builtin_return_address(1), __builtin_return_address(2), __builtin_return_address(3), __builtin_return_address(4));
      cur_node->items[index].next_node = mark_invalid_rm(0);
    }
    for (i = 0; i < RESERV_NR; i++)
      (page+i)->reservation = NULL;
  }
  spin_unlock(next_lock);
  return;
}

extern void rm_release_reservation_fast(struct rm_entry *rm_entry) {
  unsigned char level;
  unsigned int i;
  unsigned int index;
  int unused;
  
  unsigned long leaf_value;
  unsigned long *mask;

  struct page *page;

  leaf_value = (unsigned long)(rm_entry->next_node);
  mask = (unsigned long *)(rm_entry->mask);
  if (leaf_value != 0) { 
    page = get_page_from_rm(leaf_value);
    // #ifdef DEBUG_RESERV_THP
    // pr_alert("rm_release PageTransCompound(page) = %d page_to_pfn(page) = %ld PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page_zonenum(page) = %d", PageTransCompound(page), page_to_pfn(page), PageLRU(page), page_count(page), total_mapcount(page), page_zonenum(page));
    // #endif
    if (PageTransCompound(page)) {
      // #ifdef DEBUG_RESERV_THP
      // struct anon_vma_chain *vmac;
      // struct vm_area_struct *vma;
      // struct anon_vma *anon_vma;
      // for (i = 0; i < RESERV_NR; i++) {
      //   anon_vma = page_get_anon_vma(page+i);
      //   if (!anon_vma) {
      //     pr_alert("rm_release anon_vma = NULL page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
      //     continue;
      //   }
      //   pr_alert("rm_release page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
      //   anon_vma_lock_read(anon_vma);
      //   anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root, 0, ULONG_MAX) {
      //     vma = vmac->vma;
      //     if (vma && vma->vm_mm)
      //       pr_alert("vma->vm_mm->owner->pid = %d", vma->vm_mm->owner->pid);
      //   }
      //   anon_vma_unlock_read(anon_vma);
      // }
      // pr_alert("put_page");
      // #endif
      put_page(page);
      // #ifdef DEBUG_RESERV_THP
      // for (i = 0; i < RESERV_NR; i++) {
      //   anon_vma = page_get_anon_vma(page+i);
      //   if (!anon_vma) {
      //     pr_alert("rm_release anon_vma = NULL page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
      //     continue;
      //   }
      //   pr_alert("rm_release page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
      //   anon_vma_lock_read(anon_vma);
      //   anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root, 0, ULONG_MAX) {
      //     vma = vmac->vma;
      //     if (vma && vma->vm_mm)
      //       pr_alert("vma->vm_mm->owner->pid = %d", vma->vm_mm->owner->pid);
      //   }
      //   anon_vma_unlock_read(anon_vma);
      // }
      // #endif
    } else {
      for (i = 0; i < RESERV_NR; i++) {
        put_page(page+i);
      }
      // for (i = 0; i < RESERV_NR; i++) {
      //   if (PageLRU(page+i))
      //     pr_alert("rm_release page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d page_zone(page)->zone_start_pfn = %lu", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i), page_zone(page+i)->zone_start_pfn);
      // }

    }
    rm_entry->next_node = mark_invalid_rm(0);
    rm_entry->part_pop = false;
    list_del(&rm_entry->osa_hpage_scan_link);
    for (i = 0; i < RESERV_NR; i++)
      (page+i)->reservation = NULL;
  }
  return;
}

int get_mask_weight_from_reservation(struct vm_area_struct *vma, unsigned long address) {
  unsigned char level;
  unsigned int i;
  unsigned int index;

  struct rm_node *cur_node = GET_RM_ROOT(vma);
  struct rm_node *next_node;
  
  unsigned long leaf_value;
  unsigned long *mask;

  struct page *page;
  spinlock_t  *next_lock;

	unsigned long haddr = address & RESERV_MASK; 
  int region_offset   = (address & (~RESERV_MASK)) >> PAGE_SHIFT;
 
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

    spin_lock(next_lock);
    if (cur_node->items[index].next_node == NULL) {
      cur_node->items[index].next_node = rm_node_create();
    }
    spin_unlock(next_lock);
    cur_node = cur_node->items[index].next_node;

  }
  
  // secondly, process the leaf node
  level = NUM_RT_LEVELS;
  index = get_node_index(level, address); 
  next_lock = &cur_node->items[index].lock;

  spin_lock(next_lock);
  leaf_value = (unsigned long)(cur_node->items[index].next_node);
  mask = (unsigned long *)(cur_node->items[index].mask);
  spin_unlock(next_lock);
  if (leaf_value != 0) { 
    return 0;
  } else {
    return bitmap_weight(mask, 512);
  }
}


struct rm_entry *get_rm_entry_from_reservation(struct vm_area_struct *vma, unsigned long address, unsigned long **_mask) {
  int retPrmtHugePage;

  unsigned char level;
  unsigned int i;
  unsigned int index;

  struct rm_node *cur_node = GET_RM_ROOT(vma);
  struct rm_node *next_node;
  struct rm_entry *entry;
  
  unsigned long leaf_value;
  unsigned long *mask;

  struct page *page, *head;
  spinlock_t  *next_lock;

	unsigned long haddr = address & RESERV_MASK; 
  int region_offset   = (address & (~RESERV_MASK)) >> PAGE_SHIFT;

  if (cur_node == NULL) 
    return NULL;
  if (!vma_is_anonymous(vma)) {
    return NULL;
  }

  // traverse the reservation map radix tree
  // firstly, go through all levels but don't go to the leaf node
  for (level = 1; level < NUM_RT_LEVELS; level++) {
    index = get_node_index(level, address);
    next_lock = &cur_node->items[index].lock;

    spin_lock(next_lock);
    if (cur_node->items[index].next_node == NULL) {
      spin_unlock(next_lock);
      return NULL;
    }
    spin_unlock(next_lock);
    cur_node = cur_node->items[index].next_node;

  }

  // secondly, process the leaf node
  level = NUM_RT_LEVELS;
  index = get_node_index(level, address); 
  next_lock = &cur_node->items[index].lock;

  spin_lock(next_lock);
  entry = &cur_node->items[index];
  if (entry->next_node == 0 || is_invalid_rm((unsigned long)(entry->next_node))) {
    // pr_info("get_rm_entry_from_reservation haddr = %lx is_invalid_rm = %d", haddr, is_invalid_rm((unsigned long)(entry->next_node)));
    bitmap_zero(entry->mask, 512);
  }
  *_mask = entry->mask;
  spin_unlock(next_lock);
  return entry;
}

struct page *rm_alloc_from_reservation(struct vm_area_struct *vma, unsigned long address, bool *out, bool *err_alloc, gfp_t gfp) {
  int retPrmtHugePage;
  *out = false;
  *err_alloc = false;

  unsigned char level;
  unsigned int i;
  unsigned int index;
  struct mm_struct *mm = vma->vm_mm;

  struct rm_node *cur_node = GET_RM_ROOT(vma);
  struct rm_node *next_node;
  struct rm_entry *rm_entry;
  
  unsigned long leaf_value;
  unsigned long *mask;

  struct page *head, *page;
  spinlock_t  *next_lock;

	unsigned long haddr = address & RESERV_MASK;
  int region_offset   = (address & (~RESERV_MASK)) >> PAGE_SHIFT;
  
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

    spin_lock(next_lock);
    if (cur_node->items[index].next_node == NULL) {
      cur_node->items[index].next_node = rm_node_create();
    }
    spin_unlock(next_lock);
    cur_node = cur_node->items[index].next_node;

  }

  // secondly, process the leaf node
  level = NUM_RT_LEVELS;
  index = get_node_index(level, address); 
  next_lock = &cur_node->items[index].lock;

  spin_lock(next_lock);
  leaf_value = (unsigned long)(cur_node->items[index].next_node);
  if (is_invalid_rm(leaf_value)) {
    // pr_alert("is_invalid_rm(leaf_value) haddr = %lx", haddr);
    mask = (unsigned long *)(cur_node->items[index].mask);
    bitmap_zero(mask, 512);
    page = NULL;
    goto out_unlock;
  }
  mask = (unsigned long *)(cur_node->items[index].mask);
  head = page = get_page_from_rm(leaf_value);
  if (leaf_value == 0) { //create a new reservation if not present
    if (haddr < vma->vm_start || (haddr + HPAGE_PMD_SIZE) > vma->vm_end) {
      // pr_info("haddr < vma->vm_start || (haddr + HPAGE_PMD_SIZE) > vma->vm_end INVALID haddr = %lx vma->vm_start = %lx vma->vm_end = %lx", haddr, vma->vm_start, vma->vm_end);
      leaf_value = mark_invalid_rm(leaf_value);
      cur_node->items[index].next_node = (void*)(leaf_value);
      mask = (unsigned long *)(cur_node->items[index].mask);
      bitmap_zero(mask, 512);
      page = NULL;
      goto out_unlock;
    }
    // if (region_offset != 0) {
    //   *create_region_not_alligned = true;
    //   page = NULL;
    //   goto out_unlock;
    // }
    // allocate pages 

    page = alloc_pages_vma(gfp, RESERV_ORDER, vma, haddr, numa_node_id(), false);
    if (!page) {
			// pr_alert("alloc_pages_vma FAILED haddr = %lx weight mask = %d", haddr, bitmap_weight(mask, 512));
      // Mark node as invalid to not use as a reservation anymore
      leaf_value = mark_invalid_rm(leaf_value);
      cur_node->items[index].next_node = (void*)(leaf_value);
      mask = (unsigned long *)(cur_node->items[index].mask);
      bitmap_zero(mask, 512);
      *err_alloc = true;
      goto out_unlock;
    }
    // create a leaf node
    leaf_value = create_value(page);
    bitmap_zero(mask, 512);

    cur_node->items[index].timestamp = jiffies_to_msecs(jiffies);
    // pr_alert("osa_hpage_enter_list");
    osa_hpage_enter_list(&cur_node->items[index]);
    // wake_up_interruptible(&osa_hpage_scand_wait);
  } else {
    if (PageTransCompound(page)) {
      // pr_alert("rm_alloc PageTransCompound(page) goto out_unlock");
      *out = true;
      goto out_unlock;
    }

  }
  page = page + region_offset;
  

  // if (PageTransCompound(page)) {
  //   pr_alert("rm_alloc PageTransCompound(page)");
  // }

  if (!test_bit(region_offset, mask)) {
    clear_highpage(page);
    get_page(page);
  } else {
    // pr_alert("out = true haddr = %lx page_to_pfn(page) = %lx page_to_pfn(head) = %lx", haddr, page_to_pfn(page), page_to_pfn(page - region_offset));
    *out = true;
  }

  // mark the page as used
  set_bit(region_offset, mask);
  cur_node->items[index].next_node = (void*)(leaf_value);

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
  spinlock_t  *next_lock;

  // traverse the reservaton map radix tree
  for (index = 0; index < RT_NODE_RANGE_SIZE; index++) {
    if (cur_node->items[index].next_node != NULL) {
      if (level != NUM_RT_LEVELS) {
        next_lock = &cur_node->items[index].lock;
        rm_destroy(cur_node->items[index].next_node, level + 1);
      } else {
        if (!is_invalid_rm((unsigned long)cur_node->items[index].next_node)) {
          leaf_value = (unsigned long)(cur_node->items[index].next_node);
          next_lock = &cur_node->items[index].lock;
          osa_hpage_exit_list(&cur_node->items[index]);
          page = get_page_from_rm(leaf_value);
            
          // pr_info("rm_destroy PageTransCompound(page) = %d page_to_pfn(page) = %lx page_count(page) = %d total_mapcount(page) = %d page_mapcount(page) = %d", PageTransCompound(page), page_to_pfn(page), page_count(page), total_mapcount(page), page_mapcount(page));

          if (PageTransCompound(page)) {
            put_page(page);
          } else {
            for (i = 0; i < RESERV_NR; i++)
              put_page(page + i);
          }
          for (i = 0; i < RESERV_NR; i++)
            (page+i)->reservation = NULL;
        }
      }
    }
  }
  kfree(cur_node);
  return;
}

// void rm_print_freq(struct rm_node *node, unsigned char level) { //not working
//   unsigned int index;
//   int i;
//   struct rm_node *cur_node = node;
//   unsigned long *mask;
//   unsigned char unused;
//   struct page *page;
//   unsigned long leaf_value;
//   spinlock_t  *next_lock;

//   // traverse the reservaton map radix tree
//   for (index = 0; index < RT_NODE_RANGE_SIZE; index++) {
//     if (cur_node->items[index].next_node != NULL) {
//       if (level != 4) {
//         next_lock = &cur_node->items[index].lock;
//         spin_lock(next_lock);
//         rm_print_freq(cur_node->items[index].next_node, level + 1);
//         spin_unlock(next_lock);
//       } else {
//         leaf_value = (unsigned long)(cur_node->items[index].next_node);
//         mask = (unsigned long *)(cur_node->items[index].mask);
//         next_lock = &cur_node->items[index].lock;
//         spin_lock(next_lock);
//         page = get_page_from_rm(leaf_value);
        
//         if (PageTransCompound(page)) {
//           pr_alert("frequency = %d", (page->util_info).frequency[0]);
//         } else {
//           // for (i = 0; i < RESERV_NR; i++)
//           //   pr_alert("", (page+i)->util_info.frequency[0]);
//         }
//         spin_unlock(next_lock);
//       }
//     }
//   }
//   return;
// }
