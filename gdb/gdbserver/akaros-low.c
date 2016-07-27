/* Low level interface to ptrace, for the remote server for GDB.
   Copyright (C) 1995-2016 Free Software Foundation, Inc.

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

#include "akaros-low.h"
#include "server.h"
#include "target.h"

extern void initialize_arch(void);
static struct target_ops akaros_target_ops = {};

int using_threads = 1;

void initialize_low(void)
{
  initialize_arch();
  set_target_ops(&akaros_target_ops);
}
