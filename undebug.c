/*
 * This module hides the TracerPid field in /proc/<pid>/status and hides the VMA for specific processes.
 * 
 * Tested with Kernel 5.10 on arm64
 * 
 * Original code by ilammy https://github.com/ilammy/ftrace-hook and LWS https://github.com/LWSS/TracerHid
 *
 * Ported to arm64 and added trace hiding for VMA by tfoldi
 */

#define DEBUG

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/sysctl.h>
#include <linux/string.h>
#include <linux/mutex.h>

MODULE_DESCRIPTION("Hide TracerPid and VMA");
MODULE_AUTHOR("tfoldi <tfoldi@nospam>");
MODULE_LICENSE("GPL");

#define HIDE_MAPS_MAX_LEN 4096
#define MAX_ENTRIES 100
static char hide_maps[HIDE_MAPS_MAX_LEN];
static char *hide_maps_array[MAX_ENTRIES];
static int hide_maps_count = 0;
static DEFINE_MUTEX(hide_maps_lock);

/**
 * @brief Parses the hide_maps string and tokenizes it into an array of strings.
 *
 * This function takes the hide_maps string and tokenizes it using commas as delimiters.
 * The resulting tokens are stored in the hide_maps_array.
 */
static void parse_hide_maps(void)
{
	char *str, *token;
	int i = 0;

	mutex_lock(&hide_maps_lock);

	// Free previous entries
	for (i = 0; i < hide_maps_count; i++)
	{
		kfree(hide_maps_array[i]);
		hide_maps_array[i] = NULL;
	}
	hide_maps_count = 0;

	// Duplicate the hide_maps string for tokenization
	str = kstrdup(hide_maps, GFP_KERNEL);
	if (!str)
	{
		pr_err("Memory allocation failed during hide_maps parsing\n");
		mutex_unlock(&hide_maps_lock);
		return;
	}

	// Tokenize the string
	for (i = 0; i < MAX_ENTRIES; i++)
	{
		token = strsep(&str, ",");
		if (!token)
			break;

		// Trim whitespace
		token = strim(token);

		if (strlen(token) == 0)
			continue;

		hide_maps_array[hide_maps_count] = kstrdup(token, GFP_KERNEL);
		if (!hide_maps_array[hide_maps_count])
		{
			pr_err("Memory allocation failed for hide_maps entry\n");
			break;
		}
		hide_maps_count++;
	}

	kfree(str);
	mutex_unlock(&hide_maps_lock);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name};
	unsigned long retval;

	if (register_kprobe(&kp) < 0)
		return 0;
	retval = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook
{
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address)
	{
		pr_err("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long *)hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
									struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
#ifdef CONFIG_ARM64
	regs->pc = (unsigned long)hook->function;
#else
	regs->ip = (unsigned long)hook->function;
#endif
#else
	if (!within_module(parent_ip, THIS_MODULE))
#ifdef CONFIG_ARM64
		regs->pc = (unsigned long)hook->function;
#else
		regs->ip = (unsigned long)hook->function;
#endif
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	pr_debug("address to hook: %s=0x%lx", hook->name, hook->address);

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;

#ifdef CONFIG_ARM64
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;
#else
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
#endif

	err = ftrace_set_filter(&hook->ops, (unsigned char *)hook->name, strlen(hook->name), 0);
	if (err)
	{
		pr_err("ftrace_set_filter() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err)
	{
		pr_err("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err)
	{
		pr_err("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter(&hook->ops, NULL, 0, 1);
	if (err)
	{
		pr_err("ftrace_set_filter() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++)
	{
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0)
	{
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#if !defined(CONFIG_X86_64) && !defined(CONFIG_ARM64)
#error Currently only x86_64 and arm64 architecture are supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static asmlinkage void (*orig_show_map_vma)(struct seq_file *m, struct vm_area_struct *vma);
static asmlinkage void handle_show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
{

	int i;
	bool hide = false;
	struct file *file = vma->vm_file;
	const char *name = NULL;

	mutex_lock(&hide_maps_lock);
	for (i = 0; (i < hide_maps_count) && file; i++)
	{
		pr_debug("file->f_path.dentry->d_iname = %s\n", name);
		pr_debug("hide_maps_array[i] = %s\n", hide_maps_array[i]);

		if (strstr(file->f_path.dentry->d_iname, hide_maps_array[i]))
		{
			hide = true;
			break;
		}
	}
	mutex_unlock(&hide_maps_lock);

	if (hide)
	{
		pr_info("Hiding VMA for %s\n", vma->vm_file->f_path.dentry->d_iname);
		return;
	}

	orig_show_map_vma(m, vma);
	return;
}

static asmlinkage int (*orig_proc_pid_status)(struct seq_file *m, struct pid_namespace *ns,
											  struct pid *pid, struct task_struct *task);

static asmlinkage int hooked_proc_pid_status(struct seq_file *m, struct pid_namespace *ns,
											 struct pid *pid, struct task_struct *task)
{
	char *pathname, *p;
	bool more_info = false;
	int ret;
	unsigned int backup_ptrace;

	if (!task)
	{
		return orig_proc_pid_status(m, ns, pid, task); // might happen, idk
	}

	if (task->mm)
	{
		mmap_read_lock(task->mm);
		if (task->mm->exe_file)
		{
			pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (pathname)
			{
				p = d_path(&task->mm->exe_file->f_path, pathname, PATH_MAX);
				pr_info("Hiding TracerPid on Process(%s)\n", p);
				more_info = true;
				kfree(pathname);
			}
		}
		mmap_read_unlock(task->mm);
	}
	if (!more_info)
	{
		pr_info("Hiding TracerPid on Process(%d)", task->pid);
	}
	backup_ptrace = task->ptrace;
	task->ptrace = 0;
	ret = orig_proc_pid_status(m, ns, pid, task);
	task->ptrace = backup_ptrace;
	return ret;
}

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#ifdef CONFIG_ARM64
#define SYSCALL_NAME(name) ("__arm64_" name)
#else
#define SYSCALL_NAME(name) ("__x64_" name)
#endif
#else
#ifdef CONFIG_ARM64
#define SYSCALL_NAME(name) (name)
#else
#define SYSCALL_NAME(name) (name)
#endif
#endif

#define HOOK(_name, _function, _original) \
	{                                     \
		.name = SYSCALL_NAME(_name),      \
		.function = (_function),          \
		.original = (_original),          \
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("proc_pid_status", hooked_proc_pid_status, &orig_proc_pid_status),
	HOOK("show_map_vma", handle_show_map_vma, &orig_show_map_vma),
};

static int hide_maps_proc_handler(struct ctl_table *table, int write,
								  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dostring(table, write, buffer, lenp, ppos);
	if (ret == 0 && write)
	{
		parse_hide_maps();
		pr_info("hide_maps updated: %s\n", hide_maps);
	}

	return ret;
}

static struct ctl_table undebug_table[] = {
	{
		.procname = "hide_maps",
		.data = hide_maps,
		.maxlen = HIDE_MAPS_MAX_LEN,
		.mode = 0644,
		.proc_handler = hide_maps_proc_handler,
		.extra1 = NULL,
		.extra2 = NULL,
	},
	{}};

static struct ctl_table undebug_dir_table[] = {
	{
		.procname = "undebug",
		.mode = 0555,
		.child = undebug_table,
	},
	{}};

static struct ctl_table_header *undebug_sysctl_header;

static int undebug_init(void)
{
	int err;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	undebug_sysctl_header = register_sysctl_table(undebug_dir_table);
	if (!undebug_sysctl_header)
	{
		pr_err("Failed to register sysctl table\n");
		return -ENOMEM;
	}

	// Initialize hide_maps to an empty string
	hide_maps[0] = '\0';

	pr_info("module loaded\n");

	return 0;
}
module_init(undebug_init);

static void undebug_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	unregister_sysctl_table(undebug_sysctl_header);

	pr_info("module unloaded\n");
}
module_exit(undebug_exit);
