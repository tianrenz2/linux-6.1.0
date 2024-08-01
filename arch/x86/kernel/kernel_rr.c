#include <asm/kernel_rr.h>
#include <asm/traps.h>
#include <linux/ptrace.h>

__visible noinstr void rr_record_syscall(struct pt_regs *regs)
{
    unsigned long flags;
    void *event = NULL;
    rr_syscall *syscall = NULL;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_syscall), EVENT_TYPE_SYSCALL);
    if (event == NULL) {
	    panic("Failed to allocate entry");
        //goto finish;
    }

    syscall = (rr_syscall *)event;

    syscall->id = 0;
    syscall->spin_count = 0;
    syscall->regs.rax = regs->orig_ax;
    syscall->regs.rbx = regs->bx;
    syscall->regs.rcx = regs->cx;
    syscall->regs.rdx = regs->dx;
    syscall->regs.rsi = regs->si;
    syscall->regs.rdi = regs->di;
    syscall->regs.rsp = regs->sp;
    syscall->regs.rbp = regs->bp;
    syscall->regs.r8 = regs->r8;
    syscall->regs.r9 = regs->r9;
    syscall->regs.r10 = regs->r10;
    syscall->regs.r11 = regs->r11;
    syscall->regs.r12 = regs->r12;
    syscall->regs.r13 = regs->r13;
    syscall->regs.r14 = regs->r14;
    syscall->regs.r15 = regs->r15;
    syscall->cr3 = __read_cr3(); 

    local_irq_restore(flags);
}

void rr_record_exception(struct pt_regs *regs, int vector, int error_code, unsigned long cr2)
{
    unsigned long flags;
    void *event;
    rr_exception *exception = NULL;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_exception), EVENT_TYPE_EXCEPTION);
    if (event == NULL) {
	    panic("Failed to allocate entry");
        //goto finish;
    }

    exception = (rr_exception *)event;

    exception->id = 0;
    exception->spin_count = 0;
    exception->exception_index = vector;
    exception->cr2 = cr2;
    exception->error_code = error_code;
    exception->regs.rax = regs->orig_ax;
    exception->regs.rbx = regs->bx;
    exception->regs.rcx = regs->cx;
    exception->regs.rdx = regs->dx;
    exception->regs.rsi = regs->si;
    exception->regs.rdi = regs->di;
    exception->regs.rsp = regs->sp;
    exception->regs.rbp = regs->bp;
    exception->regs.r8 = regs->r8;
    exception->regs.r9 = regs->r9;
    exception->regs.r10 = regs->r10;
    exception->regs.r11 = regs->r11;
    exception->regs.r12 = regs->r12;
    exception->regs.r13 = regs->r13;
    exception->regs.r14 = regs->r14;
    exception->regs.r15 = regs->r15;
}


void rr_record_random(void *buf, int len)
{
    unsigned long flags;
    void *event;
    rr_random *random;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_random), EVENT_TYPE_RANDOM);
    if (event == NULL) {
	panic("Failed to allocate entry");
    }

    random = (rr_random *)event;

    random->id = 0;
    random->len = len;
    random->buf = (unsigned long)buf;
    memcpy(random->data, buf, len);

    local_irq_restore(flags);
}

void *rr_record_cfu(const void __user *from, void *to, long unsigned int n)
{
    unsigned long flags;
    long ret;
    void *event;
    rr_cfu *cfu;
    void *addr;

    if (!rr_queue_inited()) {
        return NULL;
    }

    if (!rr_enabled()) {
        return NULL;
    }

    local_irq_save(flags);

    /* We reserve one more byte here for the buffer so in the replay, the extra byte is filled with
       zero, same as rr_record_strncpy_user */
    event = rr_alloc_new_event_entry(sizeof(rr_cfu) + (n + 1) * sizeof(unsigned char), EVENT_TYPE_CFU);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }

    cfu = (rr_cfu *)event;

    cfu->id = 0;
    cfu->src_addr = (unsigned long)from;
    cfu->dest_addr = (unsigned long)to;
    cfu->len = n + 1;
    cfu->data = NULL;

    addr = (void *)((unsigned long)cfu + sizeof(rr_cfu));
    ret = raw_copy_from_user(addr, from, n);

    local_irq_restore(flags);

    return addr;
}

void rr_record_gfu(unsigned long val)
{
    unsigned long flags;
    void *event;
    rr_gfu *gfu;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_gfu), EVENT_TYPE_GFU);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }

    gfu = (rr_gfu *)event;

    gfu->id = 0;
    gfu->val = val;

    local_irq_restore(flags);
}


void rr_record_strnlen_user(unsigned long val)
{
    unsigned long flags;
    void *event;
    rr_cfu *cfu = NULL;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_cfu), EVENT_TYPE_STRNLEN);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }
    cfu = (rr_cfu *)event;

    cfu->id = 0;
    cfu->len = val;

    local_irq_restore(flags);
}

void rr_record_strncpy_user(const void __user *from, void *to, long unsigned int n)
{
    unsigned long flags;
    void *event;
    rr_cfu *cfu = NULL;
    unsigned long len;
    void *addr;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    len = sizeof(rr_cfu) + (n + 1) * sizeof(unsigned char);
    event = rr_alloc_new_event_entry(len, EVENT_TYPE_CFU);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }

    cfu = (rr_cfu *)event;

    cfu->id = 0;
    cfu->src_addr = (unsigned long)from;
    cfu->dest_addr = (unsigned long)to;
    cfu->len = n + 1;
    cfu->data = NULL;
    addr = (void *)((unsigned long)cfu + sizeof(rr_cfu));

    memcpy(addr, to, n);

    local_irq_restore(flags);
}

void rr_record_rdseed(unsigned long val)
{
    unsigned long flags;
    void *event;
    rr_gfu *gfu = NULL;

    if (!rr_queue_inited()) {
        return;
    }

    if (!rr_enabled()) {
        return;
    }

    local_irq_save(flags);

    event = rr_alloc_new_event_entry(sizeof(rr_gfu), EVENT_TYPE_RDSEED);
    if (event == NULL) {
        panic("Failed to allocate entry");
    }

    gfu = (rr_gfu *)event;

    gfu->id = 0;
    gfu->val = val;

    local_irq_restore(flags);
}
