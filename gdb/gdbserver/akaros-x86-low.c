#include "akaros-low.h"
#include "server.h"
#include "target.h"
#include "nat/x86-dregs.h"

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

void initialize_arch(void)
{
  init_registers_amd64();
}
