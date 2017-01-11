/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SMP_H_
#define _LEGO_SMP_H_

#include <lego/compiler.h>

#define smp_processor_id()	0

int native_cpu_up(int cpu);

void __init smp_prepare_cpus(unsigned int maxcpus);

#endif /* _LEGO_SMP_H_ */
