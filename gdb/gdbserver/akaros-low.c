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

/* server.h MUST be the first included header file. */
#include "server.h"
#include "akaros-low.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <parlib/parlib.h>
#include <sys/types.h>
#include <parlib/debug.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ros/fs.h>
#include <pthread.h>
#include <printf.h>

void print_ptid(ptid_t ptid);
struct process_info *akaros_add_process(pid_t pid, int attached);
void *wait_thread(void *arg);
int d9c_hit_breakpoint(pid_t pid, uint64_t tid, uint64_t address);
int d9c_add_thread(pid_t pid, uint64_t tid);

static int debug_fd;

/* Variables and structures to coordinate akaros_wait. */
static uth_mutex_t wait_mutex;
static uth_cond_var_t wait_cv;
struct wait_answer {
  TAILQ_ENTRY(wait_answer) entry;

  struct target_waitstatus status;
  ptid_t ptid;
};
TAILQ_HEAD(wait_answer_queue, wait_answer);
static struct wait_answer_queue wait_answers = TAILQ_HEAD_INITIALIZER(wait_answers);

struct wait_call {
  pid_t pid;
  int options;
};

struct process_info_private {
  struct d9c_ops debug_ops;
  pthread_t debug_read_thread;
  struct wait_call call;
  pthread_t wait_thread;
};

/* debugging only: printf specifier functions for PTID to use %P. */
int printf_ptid(FILE *stream, const struct printf_info *info,
                const void *const *args)
{
  ptid_t *ptid = *(ptid_t**) args[0];
  return fprintf(stream, "{P%d, L%ld, T%ld}", ptid->pid, ptid->lwp, ptid->tid);
}

int printf_ptid_info(const struct printf_info *info, size_t n, int *argtypes,
                     int *size)
{
  /* consume up to 'n' va_args (we only consume 1) */
  if (n > 0) {
    argtypes[0] = PA_POINTER;
    size[0] = sizeof(ptid_t *);
  }
  /* number of args required by format string (return this regardless) */
  return 1;
}

struct process_info *akaros_add_process(pid_t pid, int attached) {
  ptid_t ptid;
  struct process_info *proc = add_process(pid, attached);
  akaros_add_process_arch(proc);
  proc->priv = XCNEW(struct process_info_private);

  /* Add our callbacks. */
  proc->priv->debug_ops.hit_breakpoint = &d9c_hit_breakpoint;
  proc->priv->debug_ops.add_thread = &d9c_add_thread;
  d9c_init(&(proc->priv->debug_ops));

  ptid = pid_to_ptid(pid);
  add_thread(ptid, NULL);
  return proc;
}

void *wait_thread(void *arg) {
  struct wait_answer *answer;
  struct wait_call *args = (struct wait_call *) arg;

  int waitstatus;
  pid_t pid = waitpid(args->pid, &waitstatus, args->options);
  if (pid == -1) {
    return NULL;
  }

  uth_mutex_lock(wait_mutex);
  answer = (struct wait_answer *) malloc(sizeof(struct wait_answer));

  if (pid <= 0) {
    answer->status.kind = TARGET_WAITKIND_IGNORE;
  } else {
    answer->status.kind = TARGET_WAITKIND_EXITED;
    answer->status.value.sig = gdb_signal_from_host(WEXITSTATUS(waitstatus));
    answer->ptid.pid = pid;
    answer->ptid.lwp = 0;
    answer->ptid.tid = 0;
  }
  TAILQ_INSERT_TAIL(&wait_answers, answer, entry);
  uth_mutex_unlock(wait_mutex);
  uth_cond_var_broadcast(wait_cv);

  return NULL;
}

/* Attach to a running process.

   PID is the process ID to attach to, specified by the user
   or a higher layer.

   Returns -1 if attaching is unsupported, 0 on success, and calls
   error() otherwise.  */
int akaros_attach (unsigned long pid) {
  char buf[60];
  struct process_info *proc;
  print_func_entry();

  snprintf(buf, sizeof(buf), "#srv/debug-%lu", pid);
  /* Just retry that. */
  while ((debug_fd = open(buf, O_RDWR)) < 0)
    sys_block(100);

  proc = akaros_add_process(pid, 1);
  if ((errno = pthread_create(&(proc->priv->debug_read_thread), NULL,
                              d9c_read_thread, &debug_fd))) {
    perror("pthread_create");
    print_func_exit();
    return 1;
  }

  wait_mutex = uth_mutex_alloc();
  wait_cv = uth_cond_var_alloc();

  proc->priv->call.options = 0;
  proc->priv->call.pid = pid;
  if ((errno = pthread_create(&(proc->priv->wait_thread), NULL, wait_thread,
                              &(proc->priv->call)))) {
    perror("pthread_create");
    print_func_exit();
    return 1;
  }

  print_func_exit();
  return 0;
}

/* Start a new process.

   PROGRAM is a path to the program to execute.
   ARGS is a standard NULL-terminated array of arguments,
   to be passed to the inferior as ``argv''.

   Returns the new PID on success, -1 on failure.  Registers the new
   process with the process list.  */
int akaros_create_inferior (char *program, char **args) {
  pid_t pid = 0;
  print_func_entry();
  pid = create_child_with_stdfds(program, strlen(program), args, /* envp */ NULL);
  if (pid < 0) {
    perror("proc_create");
    print_func_exit();
    return -1;
  }

  /* TODO(chrisko): Read ELF; find main symbol; then set breakpoint there. */

  sys_proc_run(pid);

  /* Parent attaches to the process. */
  akaros_attach(pid);

  print_func_exit();
  return (int) pid;
}

/* Kill inferior PID.  Return -1 on failure, and 0 on success.  */
int akaros_kill (int pid) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return 0;
}

/* Detach from inferior PID. Return -1 on failure, and 0 on
   success.  */
int akaros_detach (int pid) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return 0;
}

int _delete_thread_callback (struct inferior_list_entry *entry, void *p)
{
  struct process_info *process = (struct process_info *) p;

  if (ptid_get_pid(entry->id) == pid_of(process)) {
    struct thread_info *thr = find_thread_ptid(entry->id);
    remove_thread(thr);
  }
  return 0;
}


/* The inferior process has died.  Do what is right.  */
void akaros_mourn (struct process_info *proc) {
  print_func_entry();
  find_inferior(&all_threads, _delete_thread_callback, proc);
  remove_process(proc);
  print_func_exit();
  return;
}

/* Wait for inferior PID to exit.  */
void akaros_join (int pid) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return;
}

/* Return 1 iff the thread with process ID PID is alive.  */
int akaros_thread_alive (ptid_t pid) {
  /* TODO(chrisko): */
  dprintf("%P\n", &pid);
  return 1;
}

/* Resume the inferior process.  */
void akaros_resume (struct thread_resume *resume_info, size_t n) {
  struct thread_info *thread;

  if (n != 1) {
    dprintf("resuming more than one thing not supported at the moment\n");
    return;
  }

  resume_info->thread.lwp = 0; /* For some reason, this is set to -1. */

  thread = find_thread_ptid(resume_info[0].thread);
  regcache_invalidate_thread (thread);

  uint64_t tid = ptid_get_tid(resume_info[0].thread);
  bool singlestep = (resume_info[0].kind == resume_step);
  d9c_resume(debug_fd, tid, singlestep);

  return;
}

int d9c_add_thread(pid_t pid, uint64_t tid) {
  ptid_t new_ptid = ptid_build(pid, 0, tid);
  add_thread(new_ptid, NULL);
  return 0;
}

int d9c_hit_breakpoint(pid_t pid, uint64_t tid, uint64_t address) {
  struct wait_answer *answer;
  /* notify wait routine that tid has hit a breakpoint. */

  /* TODO TODO */
  uth_mutex_lock(wait_mutex);
  answer = (struct wait_answer *) malloc(sizeof(struct wait_answer));
  answer->status.kind = TARGET_WAITKIND_STOPPED;
  answer->status.value.sig = GDB_SIGNAL_TRAP;

  answer->ptid.pid = pid;
  answer->ptid.lwp = 0;
  answer->ptid.tid = tid;
  TAILQ_INSERT_TAIL(&wait_answers, answer, entry);
  uth_mutex_unlock(wait_mutex);
  uth_cond_var_broadcast(wait_cv);

  return 0;
}

/* Wait for the inferior process or thread to change state.  Store
   status through argument pointer STATUS.

   PTID = -1 to wait for any pid to do something, PTID(pid,0,0) to
   wait for any thread of process pid to do something.  Return ptid
   of child, or -1 in case of error; store status through argument
   pointer STATUS.  OPTIONS is a bit set of options defined as
   TARGET_W* above.  If options contains TARGET_WNOHANG and there's
   no child stop to report, return is
   null_ptid/TARGET_WAITKIND_IGNORE.  */
ptid_t akaros_wait (ptid_t ptid, struct target_waitstatus *status, int options) {
  int pid;
  struct wait_answer *answer;
  print_func_entry();

  uth_mutex_lock(wait_mutex);
  while ((answer = TAILQ_FIRST(&wait_answers)) == NULL) {
    if (options & TARGET_WNOHANG) {
      /* return immediately if WNOHANG was passed. */
      return null_ptid;
    } else {
      uth_cond_var_wait(wait_cv, wait_mutex);
    }
  }
  TAILQ_REMOVE(&wait_answers, answer, entry);
  *status = answer->status;
  ptid = answer->ptid;
  uth_mutex_unlock(wait_mutex);

  print_func_exit();
  return ptid;
}

/* Fetch registers from the inferior process.

   If REGNO is -1, fetch all registers; otherwise, fetch at least REGNO.  */
void akaros_fetch_registers (struct regcache *regcache, int regno) {
  print_func_entry();
  akaros_fetch_registers_arch(debug_fd, regcache, regno);
  print_func_exit();
}

/* Store registers to the inferior process.

   If REGNO is -1, store all registers; otherwise, store at least REGNO.  */
void akaros_store_registers (struct regcache *regcache, int regno) {
  print_func_entry();
  akaros_store_registers_arch(debug_fd, regcache, regno);
  print_func_exit();
}

/* Read memory from the inferior process.  This should generally be
   called through read_inferior_memory, which handles breakpoint shadowing.

   Read LEN bytes at MEMADDR into a buffer at MYADDR.

   Returns 0 on success and errno on failure.  */
int akaros_read_memory (CORE_ADDR memaddr, unsigned char *myaddr, int len) {
  int ret;
  print_func_entry();
  ret = d9c_read_memory(debug_fd, memaddr, len, myaddr);
  print_func_exit();
  return -ret;
}

/* Write memory to the inferior process.  This should generally be
   called through write_inferior_memory, which handles breakpoint shadowing.

   Write LEN bytes from the buffer at MYADDR to MEMADDR.

   Returns 0 on success and errno on failure.  */
int akaros_write_memory (CORE_ADDR memaddr, const unsigned char *myaddr,
                     int len) {
  int ret;
  print_func_entry();
  ret = d9c_store_memory(debug_fd, memaddr, myaddr, len);
  print_func_exit();
  return -ret;
}

/* Query GDB for the values of any symbols we're interested in.
   This function is called whenever we receive a "qSymbols::"
   query, which corresponds to every time more symbols (might)
   become available.  NULL if we aren't interested in any
   symbols.  */
void akaros_look_up_symbols (void) {
  print_func_entry();
  print_func_exit();
  return;
}

/* Send an interrupt request to the inferior process,
   however is appropriate.

   TODO(chrisko): we could support this. is it really useful though? */
void akaros_request_interrupt (void) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return;
}

/* Returns true if GDB Z breakpoint type TYPE is supported, false
   otherwise.  The type is coded as follows:
     '0' - software-breakpoint
     '1' - hardware-breakpoint
     '2' - write watchpoint
     '3' - read watchpoint
     '4' - access watchpoint
*/
int akaros_supports_z_point_type (char z_type) {
  print_func_entry();

  switch (z_type) {
  case '0':
    print_func_exit();
    return 1;

  case '1':
  case '2':
  case '3':
  default:
    print_func_exit();
    return 0;
  }
}

/* Insert and remove a break or watchpoint.
   Returns 0 on success, -1 on failure and 1 on unsupported.  */
int akaros_insert_point (enum raw_bkpt_type type, CORE_ADDR addr,
                     int size, struct raw_breakpoint *bp) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return 0;
}
int akaros_remove_point (enum raw_bkpt_type type, CORE_ADDR addr,
                     int size, struct raw_breakpoint *bp) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return 0;
}

/* Returns 1 if the target stopped because it executed a software
   breakpoint instruction, 0 otherwise.  */
int akaros_stopped_by_sw_breakpoint (void) {
  print_func_entry();
  /* TODO: read DR6 */
  print_func_exit();
  return 1;
}

/* Returns true if the target knows whether a trap was caused by a
   SW breakpoint triggering.  */
int akaros_supports_stopped_by_sw_breakpoint (void) {
  print_func_entry();
  print_func_exit();
  return 1;
}

/* Returns 1 if the target stopped for a hardware breakpoint.  */
int akaros_stopped_by_hw_breakpoint (void) {
  print_func_entry();
  /* TODO: read DR6 */
  print_func_exit();
  return 0;
}

/* Returns true if the target knows whether a trap was caused by a
   HW breakpoint triggering.  */
int akaros_supports_stopped_by_hw_breakpoint (void) {
  print_func_entry();
  print_func_exit();
  return 0;
}

/* Returns true if the target can do hardware single step.  */
int akaros_supports_hardware_single_step (void) {
  print_func_entry();
  /* TODO: hardware single step support */
  print_func_exit();
  return 0;
}

/* Returns 1 if target was stopped due to a watchpoint hit, 0 otherwise.  */

int akaros_stopped_by_watchpoint (void) {
  print_func_entry();
  /* TODO: NO. */
  print_func_exit();
  return 0;
}

/* Returns the address associated with the watchpoint that hit, if any;
   returns 0 otherwise.  */

CORE_ADDR akaros_stopped_data_address (void) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return 0;
}

/* Returns true if the target supports multi-process debugging.  */
int akaros_supports_multi_process (void) {
  print_func_entry();
  /* TODO(chrisko): do we actually? investigate what this actually turns on. */
  print_func_exit();
  return 1;
}

void print_ptid(ptid_t ptid) {
  dprintf("PTID: {PID %d, LWP %ld, TID %ld}\n", ptid.pid, ptid.lwp, ptid.tid);
}

/* Returns the core given a thread, or -1 if not known.  */
int akaros_core_of_thread (ptid_t tid) {
  dprintf("%P\n", &tid);
  // TODO: we can do this.
  return -1;
}

/* Read PC from REGCACHE.  */
CORE_ADDR akaros_read_pc (struct regcache *regcache) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return 0;
}

/* Write PC to REGCACHE.  */
void akaros_write_pc (struct regcache *regcache, CORE_ADDR pc) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return;
}

/* Return true if THREAD is known to be stopped now.  */
int akaros_thread_stopped (struct thread_info *thread) {
  /* TODO(chrisko): nothing is ever stopped */
  dprintf("%P\n", &(ptid_of(thread)));
  return 1;
}

/* Return the full absolute name of the executable file that was
   run to create the process PID.  If the executable file cannot
   be determined, NULL is returned.  Otherwise, a pointer to a
   character string containing the pathname is returned.  This
   string should be copied into a buffer by the client if the string
   will not be immediately used, or if it must persist.  */
char *akaros_pid_to_exec_file (int pid) {
  print_func_entry();
  /* TODO(chrisko): UGH */
  print_func_exit();
  return NULL;
}

/* Return the breakpoint kind for this target based on PC.  The PCPTR is
   adjusted to the real memory location in case a flag (e.g., the Thumb bit on
   ARM) was present in the PC.  */
int akaros_breakpoint_kind_from_pc (CORE_ADDR *pcptr) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return 0;
}

static const gdb_byte x86_breakpoint[] = { 0xCC };
#define x86_breakpoint_len 1

/* Return the software breakpoint from KIND.  KIND can have target
   specific meaning like the Z0 kind parameter.
   SIZE is set to the software breakpoint's length in memory.  */
const gdb_byte *akaros_sw_breakpoint_from_kind (int kind, int *size) {
  print_func_entry();
  *size = x86_breakpoint_len;
  print_func_exit();
  return x86_breakpoint;
}

/* Return the thread's name, or NULL if the target is unable to determine it.
   The returned value must not be freed by the caller.  */
const char *akaros_thread_name (ptid_t thread) {
  dprintf("%P\n", &thread);
  return NULL;
}

/* Return the breakpoint kind for this target based on the current
   processor state (e.g. the current instruction mode on ARM) and the
   PC.  The PCPTR is adjusted to the real memory location in case a flag
   (e.g., the Thumb bit on ARM) is present in the PC.  */
int akaros_breakpoint_kind_from_current_state (CORE_ADDR *pcptr) {
  print_func_entry();
  assert(0);
  print_func_exit();
  return 0;
}

static struct target_ops akaros_target_ops = {
  akaros_create_inferior,
  NULL, //akaros_post_create_inferior,
  akaros_attach,
  akaros_kill,
  akaros_detach,
  akaros_mourn,
  akaros_join,
  akaros_thread_alive,
  akaros_resume,
  akaros_wait,
  akaros_fetch_registers,
  akaros_store_registers,
  NULL, //akaros_prepare_to_access_memory,
  NULL, //akaros_done_accessing_memory,
  akaros_read_memory,
  akaros_write_memory,
  akaros_look_up_symbols,
  akaros_request_interrupt,
  NULL, //akaros_read_auxv,
  NULL, //akaros_supports_z_point_type,
  NULL, //akaros_insert_point,
  NULL, //akaros_remove_point,
  NULL, //akaros_stopped_by_sw_breakpoint,
  NULL, //akaros_supports_stopped_by_sw_breakpoint,
  NULL, //akaros_stopped_by_hw_breakpoint,
  NULL, //akaros_supports_stopped_by_hw_breakpoint,
  NULL, //akaros_supports_hardware_single_step,
  NULL, //akaros_stopped_by_watchpoint,
  NULL, //akaros_stopped_data_address,
  NULL, //akaros_read_offsets,
  NULL, // thread_db_get_tls_address
  NULL, //akaros_qxfer_spu,
  NULL, //akaros_hostio_last_error,
  NULL, //akaros_qxfer_osdata,
  NULL, //akaros_xfer_siginfo,
  NULL, //akaros_supports_non_stop,
  NULL, //akaros_async,
  NULL, //akaros_start_non_stop,
  akaros_supports_multi_process,
  NULL, //akaros_supports_fork_events,
  NULL, //akaros_supports_vfork_events,
  NULL, //akaros_supports_exec_events,
  NULL, //akaros_handle_new_gdb_connection,
  NULL, //thread_db_handle_monitor_command
  NULL, //akaros_core_of_thread,
  NULL, //akaros_read_loadmap,
  NULL, //akaros_process_qsupported,
  NULL, //akaros_supports_tracepoints,
  NULL, //akaros_read_pc,
  NULL, //akaros_write_pc,
  NULL, //akaros_thread_stopped,
  NULL,
  NULL, //akaros_pause_all,
  NULL, //akaros_unpause_all,
  NULL, //akaros_stabilize_threads,
  NULL, //akaros_install_fast_tracepoint_jump_pad,
  NULL, //akaros_emit_ops,
  NULL, //akaros_supports_disable_randomization,
  NULL, //akaros_get_min_fast_tracepoint_insn_len,
  NULL, //akaros_qxfer_libraries_svr4,
  NULL, //akaros_supports_agent,
  NULL, // btrace
  NULL,
  NULL,
  NULL,
  NULL,
  NULL, //akaros_supports_range_stepping,
  NULL, //akaros_pid_to_exec_file,
  NULL, //akaros_multifs_open,
  NULL, //akaros_multifs_unlink,
  NULL, //akaros_multifs_readlink,
  NULL, //akaros_breakpoint_kind_from_pc,
  NULL, //akaros_sw_breakpoint_from_kind,
  NULL, //akaros_thread_name,
  NULL, //akaros_breakpoint_kind_from_current_state,
  NULL, //akaros_supports_software_single_step,
  NULL, //akaros_supports_catch_syscall,
};

int using_threads = 1;

void initialize_low(void)
{
  print_func_entry();
  register_printf_specifier('P', printf_ptid, printf_ptid_info);
  initialize_arch();
  set_target_ops(&akaros_target_ops);
  print_func_exit();
}
