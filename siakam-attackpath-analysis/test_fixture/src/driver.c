/* test_fixture/src/driver.c - Fake kernel driver with known vulnerabilities */

#include <linux/types.h>
#include <linux/slab.h>

#define MAX_DATA_SIZE 256
#define HARDCODED_KEY "deadbeefcafebabedeadbeefcafebabe"

struct driver_data {
    void *buffer;
    size_t buf_size;
    int is_initialized;
};

static struct driver_data *g_drv = NULL;
static int g_config_value = 0;

/* Entry function: ioctl handler exposed to userspace */
int driver_ioctl(unsigned int cmd, unsigned long arg)
{
    struct driver_data *drv;
    void *user_buf;
    size_t user_len;
    int ret = 0;

    if (!g_drv) {
        g_drv = kmalloc(sizeof(struct driver_data), GFP_KERNEL);
        if (!g_drv)
            return -1;
        g_drv->is_initialized = 0;
    }
    drv = g_drv;

    switch (cmd) {
    case 0x01: /* SETUP */
        user_len = *(size_t *)arg;
        /* VULNERABILITY: No upper bound check on user_len */
        drv->buffer = kmalloc(user_len, GFP_KERNEL);
        if (!drv->buffer)
            return -1;
        drv->buf_size = user_len;
        drv->is_initialized = 1;
        break;

    case 0x02: /* WRITE */
        user_buf = (void *)(*(unsigned long *)(arg + 8));
        user_len = *(size_t *)arg;
        /* VULNERABILITY: user_len not checked against drv->buf_size */
        if (!drv->is_initialized) {
            ret = -1;
            break;
        }
        memcpy(drv->buffer, user_buf, user_len);  /* VULNERABILITY: buffer overflow */
        break;

    case 0x03: /* READ_CONFIG */
        user_buf = (void *)(*(unsigned long *)(arg + 8));
        /* VULNERABILITY: g_config_value read without lock in multi-threaded context */
        *(int *)user_buf = g_config_value;
        break;

    case 0x04: /* VALIDATE */
        user_buf = (void *)(*(unsigned long *)(arg + 8));
        /* VULNERABILITY: use-after-free — drv freed but pointer accessible */
        kfree(drv->buffer);
        drv->buffer = NULL;
        /* VULNERABILITY: uses freed buffer */
        if (*(int *)user_buf > 0)
            drv->buf_size = *(size_t *)user_buf;  /* VULNERABILITY: writes to freed struct */
        break;

    case 0x05: /* AUTH */
        /* VULNERABILITY: No authentication check before privileged operation */
        /* Direct physical memory access without capability check */
        ioremap(*(unsigned long *)arg, PAGE_SIZE);
        break;

    case 0x06: /* RESET */
        kfree(drv->buffer);
        drv->buffer = NULL;
        /* Missing: drv->is_initialized = 0 — stale state */
        break;

    default:
        ret = -1;
        break;
    }

    return ret;
}

/* Helper functions in the call chain */

int validate_input(void *data, size_t len)
{
    /* Pass-through — simply forwards user data to process_input */
    return process_input(data, len);
}

int process_input(void *data, size_t len)
{
    /* VULNERABILITY: Missing validation — data from external source used directly */
    /* Also: no integrity check on shared-memory-style buffer */
    return 0;
}

int send_response(void *data, size_t len)
{
    /* Sink function — writes data out */
    if (len > MAX_DATA_SIZE)
        return -1;
    /* copy_to_user or similar would go here */
    return 0;
}
