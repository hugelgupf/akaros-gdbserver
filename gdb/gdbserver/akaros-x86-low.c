/* server.h MUST be the first included header file. */
#include "server.h"
#include "akaros-low.h"
#include "target.h"
#include "nat/x86-dregs.h"
#include <parlib/parlib.h>
#include <parlib/debug.h>

void init_registers_amd64 (void);
extern const struct target_desc *tdesc_amd64;

/* Low-level function vector.  */
struct x86_dr_low_type x86_dr_low =
{
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  sizeof (void *)
};

void initialize_arch(void) {
  init_registers_amd64();
}

void akaros_add_process_arch(struct process_info *proc) {
  proc->tdesc = tdesc_amd64;
}

enum gdb_regnums {
  X86_64_RAX_REGNUM,
  X86_64_RBX_REGNUM,
  X86_64_RCX_REGNUM,
  X86_64_RDX_REGNUM,
  X86_64_RSI_REGNUM,
  X86_64_RDI_REGNUM,
  X86_64_RBP_REGNUM,
  X86_64_RSP_REGNUM,
  X86_64_R8_REGNUM,
  X86_64_R9_REGNUM,
  X86_64_R10_REGNUM,
  X86_64_R11_REGNUM,
  X86_64_R12_REGNUM,
  X86_64_R13_REGNUM,
  X86_64_R14_REGNUM,
  X86_64_R15_REGNUM,
  X86_64_RIP_REGNUM,
  X86_64_EFLAGS_REGNUM,
  X86_64_CS_REGNUM,
  X86_64_SS_REGNUM,
  X86_64_DS_REGNUM,
  X86_64_ES_REGNUM,
  X86_64_FS_REGNUM,
  X86_64_GS_REGNUM,
};

void akaros_fetch_registers_arch(int debug_fd, struct regcache *regcache, int regno) {
  struct d9_regs foo = {0};
  d9c_fetch_registers(debug_fd, 0, &foo);

#define akaros_x86_64_supply_gp(regnum, fld) \
  supply_register (regcache, regnum, &(foo.reg_##fld))

  akaros_x86_64_supply_gp (X86_64_RAX_REGNUM, rax);
  akaros_x86_64_supply_gp (X86_64_RBX_REGNUM, rbx);
  akaros_x86_64_supply_gp (X86_64_RCX_REGNUM, rcx);
  akaros_x86_64_supply_gp (X86_64_RDX_REGNUM, rdx);
  akaros_x86_64_supply_gp (X86_64_RSP_REGNUM, rsp);
  akaros_x86_64_supply_gp (X86_64_RBP_REGNUM, rbp);
  akaros_x86_64_supply_gp (X86_64_RSI_REGNUM, rsi);
  akaros_x86_64_supply_gp (X86_64_RDI_REGNUM, rdi);
  akaros_x86_64_supply_gp (X86_64_RIP_REGNUM, rip);
  akaros_x86_64_supply_gp (X86_64_R8_REGNUM, r8);
  akaros_x86_64_supply_gp (X86_64_R9_REGNUM, r9);
  akaros_x86_64_supply_gp (X86_64_R10_REGNUM, r10);
  akaros_x86_64_supply_gp (X86_64_R11_REGNUM, r11);
  akaros_x86_64_supply_gp (X86_64_R12_REGNUM, r12);
  akaros_x86_64_supply_gp (X86_64_R13_REGNUM, r13);
  akaros_x86_64_supply_gp (X86_64_R14_REGNUM, r14);
  akaros_x86_64_supply_gp (X86_64_R15_REGNUM, r15);
  akaros_x86_64_supply_gp (X86_64_EFLAGS_REGNUM, eflags);
  akaros_x86_64_supply_gp (X86_64_CS_REGNUM, cs);
  akaros_x86_64_supply_gp (X86_64_SS_REGNUM, ss);

  return;
}

void akaros_store_registers_arch(int debug_fd, struct regcache *regcache, int regno) {
  struct d9_regs foo = {0};

#define akaros_x86_64_collect_gp(regnum, fld) \
  collect_register (regcache, regnum, &(foo.reg_##fld))

  akaros_x86_64_collect_gp (X86_64_RAX_REGNUM, rax);
  akaros_x86_64_collect_gp (X86_64_RBX_REGNUM, rbx);
  akaros_x86_64_collect_gp (X86_64_RCX_REGNUM, rcx);
  akaros_x86_64_collect_gp (X86_64_RDX_REGNUM, rdx);
  akaros_x86_64_collect_gp (X86_64_RSP_REGNUM, rsp);
  akaros_x86_64_collect_gp (X86_64_RBP_REGNUM, rbp);
  akaros_x86_64_collect_gp (X86_64_RSI_REGNUM, rsi);
  akaros_x86_64_collect_gp (X86_64_RDI_REGNUM, rdi);
  akaros_x86_64_collect_gp (X86_64_RIP_REGNUM, rip);
  akaros_x86_64_collect_gp (X86_64_R8_REGNUM, r8);
  akaros_x86_64_collect_gp (X86_64_R9_REGNUM, r9);
  akaros_x86_64_collect_gp (X86_64_R10_REGNUM, r10);
  akaros_x86_64_collect_gp (X86_64_R11_REGNUM, r11);
  akaros_x86_64_collect_gp (X86_64_R12_REGNUM, r12);
  akaros_x86_64_collect_gp (X86_64_R13_REGNUM, r13);
  akaros_x86_64_collect_gp (X86_64_R14_REGNUM, r14);
  akaros_x86_64_collect_gp (X86_64_R15_REGNUM, r15);
  akaros_x86_64_collect_gp (X86_64_EFLAGS_REGNUM, eflags);
  akaros_x86_64_collect_gp (X86_64_CS_REGNUM, cs);
  akaros_x86_64_collect_gp (X86_64_SS_REGNUM, ss);

  dprintf("RIP IS %p\n", foo.reg_rip);

  d9c_store_registers(debug_fd, 0, &foo);
  return;
}
