/* test_fixture/src/ops.c - Additional functions referenced via callgraph */

#include <linux/types.h>

extern int g_config_value;

/* Called from driver_ioctl's call chain */
void update_config(int new_value)
{
    /* VULNERABILITY: No synchronization on shared global */
    g_config_value = new_value;  /* race condition with driver_ioctl READ_CONFIG */
}

int get_config(void)
{
    /* Read path — infected by new_value from update_config */
    return g_config_value;
}

/* Indirect call target */
int default_handler(void *data, size_t len)
{
    /* VULNERABILITY: No bounds check on len before memcpy-like operation */
    if (data && len > 0)
        return 0;
    return -1;
}
