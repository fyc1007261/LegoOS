/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SLAB_H_
#define _LEGO_SLAB_H_

#include <lego/mm.h>

void kfree(const void *p);
void *kmalloc(size_t size, gfp_t flags);

/**
 * kzalloc - allocate memory. The memory is set to zero.
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline void *kzalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags | __GFP_ZERO);
}

/* TODO: Using node */
static inline void *kmalloc_node(size_t size, gfp_t flags, int node)
{
	return kmalloc(size, flags);
}

/**
 * kzalloc_node - allocate zeroed memory from a particular memory node.
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 * @node: memory node from which to allocate
 */
static inline void *kzalloc_node(size_t size, gfp_t flags, int node)
{
	return kmalloc_node(size, flags | __GFP_ZERO, node);
}

void kfree_tmp(size_t size, const void *p);

#endif /* _LEGO_SLAB_H_ */