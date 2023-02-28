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
    #ifdef DEBUG_RESERV_THP
    pr_alert("rm_release PageTransCompound(page) = %d address = %lx page_to_pfn(page) = %ld page_count(page) = %d total_mapcount(page) = %d", PageTransCompound(page), address, page_to_pfn(page), page_count(page), total_mapcount(page));
    #endif
    if (PageTransCompound(page)) {
      #ifdef DEBUG_RESERV_THP
      struct anon_vma_chain *vmac;
      struct vm_area_struct *vma;
      struct anon_vma *anon_vma;
      for (i = 0; i < RESERV_NR; i++) {
        // ClearPageActive(page+i);
        // ClearPageLRU(page+i);
        // struct lruvec *lruvec = mem_cgroup_page_lruvec(page, page_pgdat(page));
		    // del_page_from_lru_list(page, lruvec, page_lru(page));
        anon_vma = page_get_anon_vma(page+i);
        if (!anon_vma) {
          pr_alert("rm_release anon_vma = NULL page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
          continue;
        }
        pr_alert("rm_release page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
        anon_vma_lock_read(anon_vma);
        anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root, 0, ULONG_MAX) {
          vma = vmac->vma;
          if (vma && vma->vm_mm)
            pr_alert("vma->vm_mm->owner->pid = %d", vma->vm_mm->owner->pid);
        }
        anon_vma_unlock_read(anon_vma);
      }
      pr_alert("put_page");
      #endif
      lock_page(page);
      split_huge_page(page);
      unlock_page(page);
      put_page(page);
      #ifdef DEBUG_RESERV_THP
      for (i = 0; i < RESERV_NR; i++) {
        // ClearPageActive(page+i);
        // ClearPageLRU(page+i);
        // struct lruvec *lruvec = mem_cgroup_page_lruvec(page, page_pgdat(page));
		    // del_page_from_lru_list(page, lruvec, page_lru(page));
        anon_vma = page_get_anon_vma(page+i);
        if (!anon_vma) {
          pr_alert("rm_release anon_vma = NULL page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
          continue;
        }
        pr_alert("rm_release page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
        anon_vma_lock_read(anon_vma);
        anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root, 0, ULONG_MAX) {
          vma = vmac->vma;
          if (vma && vma->vm_mm)
            pr_alert("vma->vm_mm->owner->pid = %d", vma->vm_mm->owner->pid);
        }
        anon_vma_unlock_read(anon_vma);
      }
      #endif
    } else {
      for (i = 0; i < RESERV_NR; i++) {
        put_page(page+i);
      }
    }
    // pr_alert("osa_hpage_exit_list release");
    osa_hpage_exit_list(&cur_node->items[index]);
    cur_node->items[index].next_node = 0; 
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
    unused = 512 - bitmap_weight(mask, 512);
    if (unused) {
      mod_node_page_state(page_pgdat(page), NR_MEM_RESERVATIONS_RESERVED, -unused);
    }
    #ifdef DEBUG_RESERV_THP
    pr_alert("rm_release PageTransCompound(page) = %d page_to_pfn(page) = %ld PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page_zonenum(page) = %d", PageTransCompound(page), page_to_pfn(page), PageLRU(page), page_count(page), total_mapcount(page), page_zonenum(page));
    #endif
    if (PageTransCompound(page)) {
      #ifdef DEBUG_RESERV_THP
      struct anon_vma_chain *vmac;
      struct vm_area_struct *vma;
      struct anon_vma *anon_vma;
      for (i = 0; i < RESERV_NR; i++) {
        anon_vma = page_get_anon_vma(page+i);
        if (!anon_vma) {
          pr_alert("rm_release anon_vma = NULL page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
          continue;
        }
        pr_alert("rm_release page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
        anon_vma_lock_read(anon_vma);
        anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root, 0, ULONG_MAX) {
          vma = vmac->vma;
          if (vma && vma->vm_mm)
            pr_alert("vma->vm_mm->owner->pid = %d", vma->vm_mm->owner->pid);
        }
        anon_vma_unlock_read(anon_vma);
      }
      pr_alert("put_page");
      #endif
      put_page(page);
      #ifdef DEBUG_RESERV_THP
      for (i = 0; i < RESERV_NR; i++) {
        anon_vma = page_get_anon_vma(page+i);
        if (!anon_vma) {
          pr_alert("rm_release anon_vma = NULL page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
          continue;
        }
        pr_alert("rm_release page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i));
        anon_vma_lock_read(anon_vma);
        anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root, 0, ULONG_MAX) {
          vma = vmac->vma;
          if (vma && vma->vm_mm)
            pr_alert("vma->vm_mm->owner->pid = %d", vma->vm_mm->owner->pid);
        }
        anon_vma_unlock_read(anon_vma);
      }
      #endif
    } else {
      for (i = 0; i < RESERV_NR; i++) {
        put_page(page+i);
      }
      // for (i = 0; i < RESERV_NR; i++) {
      //   if (PageLRU(page+i))
      //     pr_alert("rm_release page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d PageTransCompound(page) = %d page_zone(page)->zone_start_pfn = %lu", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), PageTransCompound(page+i), page_zone(page+i)->zone_start_pfn);
      // }

    }

    rm_entry->next_node = 0; 
    rm_entry->part_pop = false;
    list_del(&rm_entry->osa_hpage_scan_link);
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
  mask = (unsigned long *)(cur_node->items[index].mask);
  spin_unlock(next_lock);
  if (leaf_value != 0) { 
    return 0;
  } else {
    return bitmap_weight(mask, 512);
  }
}


struct rm_entry *get_rm_entry_from_reservation(struct vm_area_struct *vma, unsigned long address) {
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

  gfp_t gfp           = ((GFP_HIGHUSER | __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM);
	unsigned long haddr = address & RESERV_MASK; 
  int region_offset   = (address & (~RESERV_MASK)) >> PAGE_SHIFT;
  bool my_app         = true;//(vma->vm_mm->owner->pid == 5555);

  if (!my_app) 
    return NULL;
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
  entry = &cur_node->items[index];
  if (entry->next_node == 0) {
    bitmap_zero(entry->mask, 512);
  }
  spin_unlock(next_lock);
  return entry;
}

struct page *rm_alloc_from_reservation(struct vm_area_struct *vma, unsigned long address, unsigned long **_mask) {
  int retPrmtHugePage;

  unsigned char level;
  unsigned int i;
  unsigned int index;

  struct rm_node *cur_node = GET_RM_ROOT(vma);
  struct rm_node *next_node;
  // struct rm_entry *rm_entry = NULL;
  
  unsigned long leaf_value;
  unsigned long *mask;

  struct page *head, *page;
  spinlock_t  *next_lock;

  gfp_t gfp           = ((GFP_HIGHUSER_MOVABLE | __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM);
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
    if (region_offset != 0) {
      page = NULL;
      goto out_unlock;
    }
    // allocate pages 
    page = alloc_pages_vma(gfp, RESERV_ORDER, vma, haddr, numa_node_id(), false);
    if (!page) {
      // pr_alert("alloc_pages_vma FAILED");
      goto out_unlock;
    }
    for (i = 0; i < RESERV_NR; i++) {
      set_page_count(page + i, 1);
    }
    // clear_huge_page(page, haddr, HPAGE_PMD_NR);
    // create a leaf node
    leaf_value = create_value(page);
    bitmap_zero(mask, 512);

    mod_node_page_state(page_pgdat(page), NR_MEM_RESERVATIONS_RESERVED, RESERV_NR - 1);
    count_vm_event(MEM_RESERVATIONS_ALLOC);
    INIT_LIST_HEAD(&cur_node->items[index].osa_hpage_scan_link);
    cur_node->items[index].timestamp = jiffies_to_msecs(jiffies);
    // pr_alert("osa_hpage_enter_list");
    osa_hpage_enter_list(&cur_node->items[index]);
    // wake_up_interruptible(&osa_hpage_scand_wait);
  } else {
    mod_node_page_state(page_pgdat(page), NR_MEM_RESERVATIONS_RESERVED, -1);
    // if (PageTransCompound(page)) {
    //   pr_alert("rm_alloc PageTransCompound(page) goto out_unlock");
    //   goto out_unlock;
    // }
  }
  page = page + region_offset;
  
  cur_node->items[index].next_node = (void*)(leaf_value);
  get_page(page);
  clear_user_highpage(page, address);

  if (PageTransCompound(page)) {
    pr_alert("rm_alloc PageTransCompound(page)");
  }

  // mark the page as used
  set_bit(region_offset, mask);
  *_mask = mask;

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
      if (level != 4) {
        // next_lock = &cur_node->items[index].lock;
        // spin_lock(next_lock);
        rm_destroy(cur_node->items[index].next_node, level + 1);
        // spin_unlock(next_lock);
      } else {
        leaf_value = (unsigned long)(cur_node->items[index].next_node);
        // mask = (unsigned long *)(cur_node->items[index].mask);
        // next_lock = &cur_node->items[index].lock;
        // spin_lock(next_lock);
        // VM_BUG_ON(!(unsigned long)(cur_node->items[index].next_node));
        // pr_alert("osa_hpage_exit_list destroy");
        osa_hpage_exit_list(&cur_node->items[index]);
        page = get_page_from_rm(leaf_value);

        // unused = 512 - bitmap_weight(mask, 512);
        // if (unused) {
        //   mod_node_page_state(page_pgdat(page), NR_MEM_RESERVATIONS_RESERVED, -unused);
        // }
        // #ifdef DEBUG_RESERV_THP
        // pr_alert("rm_destroy PageTransCompound(page) = %d page_to_pfn(page) = %ld page_count(page) = %d total_mapcount(page) = %d", PageTransCompound(page), page_to_pfn(page), page_count(page), total_mapcount(page));
        // #endif
        if (PageTransCompound(page)) {
          // #ifdef DEBUG_RESERV_THP
          // struct anon_vma_chain *vmac;
          // struct vm_area_struct *vma;
          // struct anon_vma *anon_vma;
          // for (i = 0; i < RESERV_NR; i++) {
          //   anon_vma = page_get_anon_vma(page+i);
          //   if (!anon_vma) {
          //     pr_alert("rm_destroy anon_vma = NULL page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d compound_mapcount(page) = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), compound_mapcount(page+i), PageTransCompound(page+i));
          //     continue;
          //   }
          //   pr_alert("rm_destroy page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d compound_mapcount(page) = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), compound_mapcount(page+i), PageTransCompound(page+i));
          //   anon_vma_lock_read(anon_vma);
          //   anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root, 0, ULONG_MAX) {
          //     vma = vmac->vma;
          //     if (vma && vma->vm_mm)
          //       pr_alert("vma->vm_mm->owner->pid = %d", vma->vm_mm->owner->pid);
          //   }
          //   anon_vma_unlock_read(anon_vma);
          // }
          // #endif
          put_page(page);
        } else {
          for (i = 0; i < RESERV_NR; i++)
            put_page(page + i);
          // #ifdef DEBUG_RESERV_THP
          // for (i = 0; i < RESERV_NR; i++) {
          //   pr_alert("rm_destroy page = %ld PageActive(page) = %d PageLRU(page) = %d page_count(page) = %d total_mapcount(page) = %d page->_mapcount = %d compound_mapcount(page) = %d PageTransCompound(page) = %d", page_to_pfn(page+i), PageActive(page+i), PageLRU(page+i), page_count(page+i), total_mapcount(page+i), atomic_read(&(page+i)->_mapcount), compound_mapcount(page+i), PageTransCompound(page+i));
          // }
          // #endif
        }
        // spin_unlock(next_lock);
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
