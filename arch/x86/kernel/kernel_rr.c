#include <asm/kernel_rr.h>
#include <asm/traps.h>
#include <linux/ptrace.h>


static void rr_record_syscall(struct pt_regs *regs, int cpu_id, unsigned long spin_count)
{
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        printk(KERN_ERR "Failed to allocate entry");
        return;
    }

    event->type = EVENT_TYPE_SYSCALL;
    event->id = cpu_id;
    event->event.syscall.regs.rax = regs->orig_ax;
    event->event.syscall.regs.rbx = regs->bx;
    event->event.syscall.regs.rcx = regs->cx;
    event->event.syscall.regs.rdx = regs->dx;
    event->event.syscall.regs.rsi = regs->si;
    event->event.syscall.regs.rdi = regs->di;
    event->event.syscall.regs.rsp = regs->sp;
    event->event.syscall.regs.rbp = regs->bp;
    event->event.syscall.regs.r8 = regs->r8;
    event->event.syscall.regs.r9 = regs->r9;
    event->event.syscall.regs.r10 = regs->r10;
    event->event.syscall.regs.r11 = regs->r11;
    event->event.syscall.regs.r12 = regs->r12;
    event->event.syscall.regs.r13 = regs->r13;
    event->event.syscall.regs.r14 = regs->r14;
    event->event.syscall.regs.r15 = regs->r15;
    event->event.syscall.cr3 = __read_cr3(); 
    event->event.syscall.spin_count = spin_count;
}

static void rr_record_exception(struct pt_regs *regs,
                                int vector, int error_code,
                                unsigned long cr2, int cpu_id,
                                unsigned long spin_count)
{
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        return;
    }

    event->type = EVENT_TYPE_EXCEPTION;
    event->id = cpu_id;
    event->event.exception.exception_index = vector;
    event->event.exception.cr2 = cr2;
    event->event.exception.error_code = error_code;
    event->event.exception.regs.rax = regs->orig_ax;
    event->event.exception.regs.rbx = regs->bx;
    event->event.exception.regs.rcx = regs->cx;
    event->event.exception.regs.rdx = regs->dx;
    event->event.exception.regs.rsi = regs->si;
    event->event.exception.regs.rdi = regs->di;
    event->event.exception.regs.rsp = regs->sp;
    event->event.exception.regs.rbp = regs->bp;
    event->event.exception.regs.r8 = regs->r8;
    event->event.exception.regs.r9 = regs->r9;
    event->event.exception.regs.r10 = regs->r10;
    event->event.exception.regs.r11 = regs->r11;
    event->event.exception.regs.r12 = regs->r12;
    event->event.exception.regs.r13 = regs->r13;
    event->event.exception.regs.r14 = regs->r14;
    event->event.exception.regs.r15 = regs->r15;
    event->event.exception.spin_count = spin_count;
}


void rr_handle_syscall(struct pt_regs *regs)
{
    int cpu_id;
    unsigned long flags;
    long spin_count;

    local_irq_save(flags);

    preempt_disable();
    cpu_id = smp_processor_id();

    spin_count = rr_do_acquire_smp_exec(0, cpu_id, CTX_SYSCALL);

    if (spin_count < 0)
        spin_count = 0;

    rr_record_syscall(regs, cpu_id, spin_count);

    preempt_enable();
    local_irq_restore(flags);
}


void rr_handle_exception(struct pt_regs *regs, int vector, int error_code, unsigned long cr2)
{
    int cpu_id;
    unsigned long flags;
    long spin_count;

    local_irq_save(flags);

    preempt_disable();
    cpu_id = smp_processor_id();

    spin_count = rr_do_acquire_smp_exec(0, cpu_id, CTX_EXCP);

    if (spin_count < 0)
        spin_count = 0;

    rr_record_exception(regs, vector, error_code, cr2, cpu_id, spin_count);

    preempt_enable();
    local_irq_restore(flags);
}


static void rr_record_irqentry(int cpu_id, unsigned long spin_count)
{
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        return;
    }

    event->type = EVENT_TYPE_INTERRUPT;
    event->id = cpu_id;
    event->event.interrupt.from = 3;
    event->event.interrupt.spin_count = spin_count;
}


void rr_handle_irqentry(void)
{
    int cpu_id;
    unsigned long flags;
    long spin_count;

    local_irq_save(flags);

    preempt_disable();
    cpu_id = smp_processor_id();

    spin_count = rr_do_acquire_smp_exec(0, cpu_id, CTX_INTR);
    if (spin_count < 0) {
        goto finish;
    }

    rr_record_irqentry(cpu_id, spin_count);

finish:
    preempt_enable();
    local_irq_restore(flags);
}

void rr_record_random(void *buf, int len)
{
    unsigned long flags;
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        goto finish;
        return;
    }

    event->type = EVENT_TYPE_RANDOM;
    event->event.rand.len = len;
    event->event.rand.buf = (unsigned long)buf;
    memcpy(event->event.rand.data, buf, len);

finish:
    local_irq_restore(flags);
}

void rr_record_cfu(const void __user *from, void *to, long unsigned int n)
{
    unsigned long flags;
    long ret;
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    if (n > CFU_BUFFER_SIZE) {
        BUG();
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        goto finish;
    }

    event->type = EVENT_TYPE_CFU;
    event->event.cfu.src_addr = (unsigned long)from;
    event->event.cfu.dest_addr = (unsigned long)to;
    event->event.cfu.len = n;
    ret = raw_copy_from_user(event->event.cfu.data, from, n);

finish:
    local_irq_restore(flags);
}

void rr_record_gfu(unsigned long val)
{
    unsigned long flags;
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        goto finish;
    }

    event->type = EVENT_TYPE_GFU;
    event->event.gfu.val = val;

finish:
    local_irq_restore(flags);
}


void rr_record_strnlen_user(unsigned long val)
{
    unsigned long flags;
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        goto finish;
    }

    event->type = EVENT_TYPE_STRNLEN;
    event->event.cfu.len = val;

finish:
    local_irq_restore(flags);
}

void rr_record_strncpy_user(const void __user *from, void *to, long unsigned int n)
{
    unsigned long flags;
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        goto finish;
    }

    event->type = EVENT_TYPE_CFU;
    event->event.cfu.src_addr = (unsigned long)from;
    event->event.cfu.dest_addr = (unsigned long)to;
    event->event.cfu.len = n;
    memcpy(event->event.cfu.data, to, n);

finish:
    local_irq_restore(flags);
}

void rr_record_rdseed(unsigned long val)
{
    unsigned long flags;
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        goto finish;
    }

    event->type = EVENT_TYPE_RDSEED;
    event->event.gfu.val = val;

finish:
    local_irq_restore(flags);
}

void rr_record_release(int cpu_id)
{
    rr_event_log_guest *event;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    event = rr_alloc_new_event_entry();
    if (event == NULL) {
        return;
    }

    event->type = EVENT_TYPE_RELEASE;
    event->id = cpu_id;
}