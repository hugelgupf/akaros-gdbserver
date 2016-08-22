/* Internal interfaces for the GNU/Linux specific target code for gdbserver.
   Copyright (C) 2002-2016 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* server.h MUST be the first included header file. */
#include "server.h"
#include <stdio.h>
#include "target.h"

#define dprintf(format, ...) printf("[g %s:%d] " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)

void initialize_arch(void);
void akaros_add_process_arch(struct process_info *proc);
void akaros_fetch_registers_arch(int debug_fd, struct regcache *regcache, int regno);
void akaros_store_registers_arch(int debug_fd, struct regcache *regcache, int regno);
