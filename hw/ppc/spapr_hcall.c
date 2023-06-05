#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qapi/error.h"
#include "sysemu/hw_accel.h"
#include "sysemu/runstate.h"
#include "sysemu/tcg.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qemu/compiler.h"
#include "qemu/bswap.h"
#include "exec/exec-all.h"
#include "helper_regs.h"
#include "hw/ppc/ppc.h"
#include "hw/ppc/spapr.h"
#include "hw/ppc/spapr_cpu_core.h"
#include "mmu-hash64.h"
#include "cpu-models.h"
#include "trace.h"
#include "kvm_ppc.h"
#include "hw/ppc/fdt.h"
#include "hw/ppc/spapr_ovec.h"
#include "hw/ppc/spapr_numa.h"
#include "mmu-book3s-v3.h"
#include "hw/mem/memory-device.h"
#include "exec/tb-flush.h"

bool is_ram_address(SpaprMachineState *spapr, hwaddr addr)
{
    MachineState *machine = MACHINE(spapr);
    DeviceMemoryState *dms = machine->device_memory;

    if (addr < machine->ram_size) {
        return true;
    }
    if ((addr >= dms->base)
        && ((addr - dms->base) < memory_region_size(&dms->mr))) {
        return true;
    }

    return false;
}

/* Convert a return code from the KVM ioctl()s implementing resize HPT
 * into a PAPR hypercall return code */
static target_ulong resize_hpt_convert_rc(int ret)
{
    if (ret >= 100000) {
        return H_LONG_BUSY_ORDER_100_SEC;
    } else if (ret >= 10000) {
        return H_LONG_BUSY_ORDER_10_SEC;
    } else if (ret >= 1000) {
        return H_LONG_BUSY_ORDER_1_SEC;
    } else if (ret >= 100) {
        return H_LONG_BUSY_ORDER_100_MSEC;
    } else if (ret >= 10) {
        return H_LONG_BUSY_ORDER_10_MSEC;
    } else if (ret > 0) {
        return H_LONG_BUSY_ORDER_1_MSEC;
    }

    switch (ret) {
    case 0:
        return H_SUCCESS;
    case -EPERM:
        return H_AUTHORITY;
    case -EINVAL:
        return H_PARAMETER;
    case -ENXIO:
        return H_CLOSED;
    case -ENOSPC:
        return H_PTEG_FULL;
    case -EBUSY:
        return H_BUSY;
    case -ENOMEM:
        return H_NO_MEM;
    default:
        return H_HARDWARE;
    }
}

static target_ulong h_resize_hpt_prepare(PowerPCCPU *cpu,
                                         SpaprMachineState *spapr,
                                         target_ulong opcode,
                                         target_ulong *args)
{
    target_ulong flags = args[0];
    int shift = args[1];
    uint64_t current_ram_size;
    int rc;

    if (spapr->resize_hpt == SPAPR_RESIZE_HPT_DISABLED) {
        return H_AUTHORITY;
    }

    if (!spapr->htab_shift) {
        /* Radix guest, no HPT */
        return H_NOT_AVAILABLE;
    }

    trace_spapr_h_resize_hpt_prepare(flags, shift);

    if (flags != 0) {
        return H_PARAMETER;
    }

    if (shift && ((shift < 18) || (shift > 46))) {
        return H_PARAMETER;
    }

    current_ram_size = MACHINE(spapr)->ram_size + get_plugged_memory_size();

    /* We only allow the guest to allocate an HPT one order above what
     * we'd normally give them (to stop a small guest claiming a huge
     * chunk of resources in the HPT */
    if (shift > (spapr_hpt_shift_for_ramsize(current_ram_size) + 1)) {
        return H_RESOURCE;
    }

    rc = kvmppc_resize_hpt_prepare(cpu, flags, shift);
    if (rc != -ENOSYS) {
        return resize_hpt_convert_rc(rc);
    }

    if (kvm_enabled()) {
        return H_HARDWARE;
    }

    return softmmu_resize_hpt_prepare(cpu, spapr, shift);
}

static void do_push_sregs_to_kvm_pr(CPUState *cs, run_on_cpu_data data)
{
    int ret;

    cpu_synchronize_state(cs);

    ret = kvmppc_put_books_sregs(POWERPC_CPU(cs));
    if (ret < 0) {
        error_report("failed to push sregs to KVM: %s", strerror(-ret));
        exit(1);
    }
}

void push_sregs_to_kvm_pr(SpaprMachineState *spapr)
{
    CPUState *cs;

    /*
     * This is a hack for the benefit of KVM PR - it abuses the SDR1
     * slot in kvm_sregs to communicate the userspace address of the
     * HPT
     */
    if (!kvm_enabled() || !spapr->htab) {
        return;
    }

    CPU_FOREACH(cs) {
        run_on_cpu(cs, do_push_sregs_to_kvm_pr, RUN_ON_CPU_NULL);
    }
}

static target_ulong h_resize_hpt_commit(PowerPCCPU *cpu,
                                        SpaprMachineState *spapr,
                                        target_ulong opcode,
                                        target_ulong *args)
{
    target_ulong flags = args[0];
    target_ulong shift = args[1];
    int rc;

    if (spapr->resize_hpt == SPAPR_RESIZE_HPT_DISABLED) {
        return H_AUTHORITY;
    }

    if (!spapr->htab_shift) {
        /* Radix guest, no HPT */
        return H_NOT_AVAILABLE;
    }

    trace_spapr_h_resize_hpt_commit(flags, shift);

    rc = kvmppc_resize_hpt_commit(cpu, flags, shift);
    if (rc != -ENOSYS) {
        rc = resize_hpt_convert_rc(rc);
        if (rc == H_SUCCESS) {
            /* Need to set the new htab_shift in the machine state */
            spapr->htab_shift = shift;
        }
        return rc;
    }

    if (kvm_enabled()) {
        return H_HARDWARE;
    }

    return softmmu_resize_hpt_commit(cpu, spapr, flags, shift);
}



static target_ulong h_set_sprg0(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                target_ulong opcode, target_ulong *args)
{
    cpu_synchronize_state(CPU(cpu));
    cpu->env.spr[SPR_SPRG0] = args[0];

    return H_SUCCESS;
}

static target_ulong h_set_dabr(PowerPCCPU *cpu, SpaprMachineState *spapr,
                               target_ulong opcode, target_ulong *args)
{
    if (!ppc_has_spr(cpu, SPR_DABR)) {
        return H_HARDWARE;              /* DABR register not available */
    }
    cpu_synchronize_state(CPU(cpu));

    if (ppc_has_spr(cpu, SPR_DABRX)) {
        cpu->env.spr[SPR_DABRX] = 0x3;  /* Use Problem and Privileged state */
    } else if (!(args[0] & 0x4)) {      /* Breakpoint Translation set? */
        return H_RESERVED_DABR;
    }

    cpu->env.spr[SPR_DABR] = args[0];
    return H_SUCCESS;
}

static target_ulong h_set_xdabr(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                target_ulong opcode, target_ulong *args)
{
    target_ulong dabrx = args[1];

    if (!ppc_has_spr(cpu, SPR_DABR) || !ppc_has_spr(cpu, SPR_DABRX)) {
        return H_HARDWARE;
    }

    if ((dabrx & ~0xfULL) != 0 || (dabrx & H_DABRX_HYPERVISOR) != 0
        || (dabrx & (H_DABRX_KERNEL | H_DABRX_USER)) == 0) {
        return H_PARAMETER;
    }

    cpu_synchronize_state(CPU(cpu));
    cpu->env.spr[SPR_DABRX] = dabrx;
    cpu->env.spr[SPR_DABR] = args[0];

    return H_SUCCESS;
}

static target_ulong h_page_init(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                target_ulong opcode, target_ulong *args)
{
    target_ulong flags = args[0];
    hwaddr dst = args[1];
    hwaddr src = args[2];
    hwaddr len = TARGET_PAGE_SIZE;
    uint8_t *pdst, *psrc;
    target_long ret = H_SUCCESS;

    if (flags & ~(H_ICACHE_SYNCHRONIZE | H_ICACHE_INVALIDATE
                  | H_COPY_PAGE | H_ZERO_PAGE)) {
        qemu_log_mask(LOG_UNIMP, "h_page_init: Bad flags (" TARGET_FMT_lx "\n",
                      flags);
        return H_PARAMETER;
    }

    /* Map-in destination */
    if (!is_ram_address(spapr, dst) || (dst & ~TARGET_PAGE_MASK) != 0) {
        return H_PARAMETER;
    }
    pdst = cpu_physical_memory_map(dst, &len, true);
    if (!pdst || len != TARGET_PAGE_SIZE) {
        return H_PARAMETER;
    }

    if (flags & H_COPY_PAGE) {
        /* Map-in source, copy to destination, and unmap source again */
        if (!is_ram_address(spapr, src) || (src & ~TARGET_PAGE_MASK) != 0) {
            ret = H_PARAMETER;
            goto unmap_out;
        }
        psrc = cpu_physical_memory_map(src, &len, false);
        if (!psrc || len != TARGET_PAGE_SIZE) {
            ret = H_PARAMETER;
            goto unmap_out;
        }
        memcpy(pdst, psrc, len);
        cpu_physical_memory_unmap(psrc, len, 0, len);
    } else if (flags & H_ZERO_PAGE) {
        memset(pdst, 0, len);          /* Just clear the destination page */
    }

    if (kvm_enabled() && (flags & H_ICACHE_SYNCHRONIZE) != 0) {
        kvmppc_dcbst_range(cpu, pdst, len);
    }
    if (flags & (H_ICACHE_SYNCHRONIZE | H_ICACHE_INVALIDATE)) {
        if (kvm_enabled()) {
            kvmppc_icbi_range(cpu, pdst, len);
        } else {
            tb_flush(CPU(cpu));
        }
    }

unmap_out:
    cpu_physical_memory_unmap(pdst, TARGET_PAGE_SIZE, 1, len);
    return ret;
}

#define FLAGS_REGISTER_VPA         0x0000200000000000ULL
#define FLAGS_REGISTER_DTL         0x0000400000000000ULL
#define FLAGS_REGISTER_SLBSHADOW   0x0000600000000000ULL
#define FLAGS_DEREGISTER_VPA       0x0000a00000000000ULL
#define FLAGS_DEREGISTER_DTL       0x0000c00000000000ULL
#define FLAGS_DEREGISTER_SLBSHADOW 0x0000e00000000000ULL

static target_ulong register_vpa(PowerPCCPU *cpu, target_ulong vpa)
{
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);
    uint16_t size;
    uint8_t tmp;

    if (vpa == 0) {
        hcall_dprintf("Can't cope with registering a VPA at logical 0\n");
        return H_HARDWARE;
    }

    if (vpa % env->dcache_line_size) {
        return H_PARAMETER;
    }
    /* FIXME: bounds check the address */

    size = lduw_be_phys(cs->as, vpa + 0x4);

    if (size < VPA_MIN_SIZE) {
        return H_PARAMETER;
    }

    /* VPA is not allowed to cross a page boundary */
    if ((vpa / 4096) != ((vpa + size - 1) / 4096)) {
        return H_PARAMETER;
    }

    spapr_cpu->vpa_addr = vpa;

    tmp = ldub_phys(cs->as, spapr_cpu->vpa_addr + VPA_SHARED_PROC_OFFSET);
    tmp |= VPA_SHARED_PROC_VAL;
    stb_phys(cs->as, spapr_cpu->vpa_addr + VPA_SHARED_PROC_OFFSET, tmp);

    return H_SUCCESS;
}

static target_ulong deregister_vpa(PowerPCCPU *cpu, target_ulong vpa)
{
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);

    if (spapr_cpu->slb_shadow_addr) {
        return H_RESOURCE;
    }

    if (spapr_cpu->dtl_addr) {
        return H_RESOURCE;
    }

    spapr_cpu->vpa_addr = 0;
    return H_SUCCESS;
}

static target_ulong register_slb_shadow(PowerPCCPU *cpu, target_ulong addr)
{
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);
    uint32_t size;

    if (addr == 0) {
        hcall_dprintf("Can't cope with SLB shadow at logical 0\n");
        return H_HARDWARE;
    }

    size = ldl_be_phys(CPU(cpu)->as, addr + 0x4);
    if (size < 0x8) {
        return H_PARAMETER;
    }

    if ((addr / 4096) != ((addr + size - 1) / 4096)) {
        return H_PARAMETER;
    }

    if (!spapr_cpu->vpa_addr) {
        return H_RESOURCE;
    }

    spapr_cpu->slb_shadow_addr = addr;
    spapr_cpu->slb_shadow_size = size;

    return H_SUCCESS;
}

static target_ulong deregister_slb_shadow(PowerPCCPU *cpu, target_ulong addr)
{
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);

    spapr_cpu->slb_shadow_addr = 0;
    spapr_cpu->slb_shadow_size = 0;
    return H_SUCCESS;
}

static target_ulong register_dtl(PowerPCCPU *cpu, target_ulong addr)
{
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);
    uint32_t size;

    if (addr == 0) {
        hcall_dprintf("Can't cope with DTL at logical 0\n");
        return H_HARDWARE;
    }

    size = ldl_be_phys(CPU(cpu)->as, addr + 0x4);

    if (size < 48) {
        return H_PARAMETER;
    }

    if (!spapr_cpu->vpa_addr) {
        return H_RESOURCE;
    }

    spapr_cpu->dtl_addr = addr;
    spapr_cpu->dtl_size = size;

    return H_SUCCESS;
}

static target_ulong deregister_dtl(PowerPCCPU *cpu, target_ulong addr)
{
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);

    spapr_cpu->dtl_addr = 0;
    spapr_cpu->dtl_size = 0;

    return H_SUCCESS;
}

static target_ulong h_register_vpa(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                   target_ulong opcode, target_ulong *args)
{
    target_ulong flags = args[0];
    target_ulong procno = args[1];
    target_ulong vpa = args[2];
    target_ulong ret = H_PARAMETER;
    PowerPCCPU *tcpu;

    tcpu = spapr_find_cpu(procno);
    if (!tcpu) {
        return H_PARAMETER;
    }

    switch (flags) {
    case FLAGS_REGISTER_VPA:
        ret = register_vpa(tcpu, vpa);
        break;

    case FLAGS_DEREGISTER_VPA:
        ret = deregister_vpa(tcpu, vpa);
        break;

    case FLAGS_REGISTER_SLBSHADOW:
        ret = register_slb_shadow(tcpu, vpa);
        break;

    case FLAGS_DEREGISTER_SLBSHADOW:
        ret = deregister_slb_shadow(tcpu, vpa);
        break;

    case FLAGS_REGISTER_DTL:
        ret = register_dtl(tcpu, vpa);
        break;

    case FLAGS_DEREGISTER_DTL:
        ret = deregister_dtl(tcpu, vpa);
        break;
    }

    return ret;
}

static target_ulong h_cede(PowerPCCPU *cpu, SpaprMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);

    env->msr |= (1ULL << MSR_EE);
    hreg_compute_hflags(env);
    ppc_maybe_interrupt(env);

    if (spapr_cpu->prod) {
        spapr_cpu->prod = false;
        return H_SUCCESS;
    }

    if (!cpu_has_work(cs)) {
        cs->halted = 1;
        cs->exception_index = EXCP_HLT;
        cs->exit_request = 1;
        ppc_maybe_interrupt(env);
    }

    return H_SUCCESS;
}

/*
 * Confer to self, aka join. Cede could use the same pattern as well, if
 * EXCP_HLT can be changed to ECXP_HALTED.
 */
static target_ulong h_confer_self(PowerPCCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);

    if (spapr_cpu->prod) {
        spapr_cpu->prod = false;
        return H_SUCCESS;
    }
    cs->halted = 1;
    cs->exception_index = EXCP_HALTED;
    cs->exit_request = 1;
    ppc_maybe_interrupt(&cpu->env);

    return H_SUCCESS;
}

static target_ulong h_join(PowerPCCPU *cpu, SpaprMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    CPUState *cs;
    bool last_unjoined = true;

    if (env->msr & (1ULL << MSR_EE)) {
        return H_BAD_MODE;
    }

    /*
     * Must not join the last CPU running. Interestingly, no such restriction
     * for H_CONFER-to-self, but that is probably not intended to be used
     * when H_JOIN is available.
     */
    CPU_FOREACH(cs) {
        PowerPCCPU *c = POWERPC_CPU(cs);
        CPUPPCState *e = &c->env;
        if (c == cpu) {
            continue;
        }

        /* Don't have a way to indicate joined, so use halted && MSR[EE]=0 */
        if (!cs->halted || (e->msr & (1ULL << MSR_EE))) {
            last_unjoined = false;
            break;
        }
    }
    if (last_unjoined) {
        return H_CONTINUE;
    }

    return h_confer_self(cpu);
}

static target_ulong h_confer(PowerPCCPU *cpu, SpaprMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    target_long target = args[0];
    uint32_t dispatch = args[1];
    CPUState *cs = CPU(cpu);
    SpaprCpuState *spapr_cpu;

    /*
     * -1 means confer to all other CPUs without dispatch counter check,
     *  otherwise it's a targeted confer.
     */
    if (target != -1) {
        PowerPCCPU *target_cpu = spapr_find_cpu(target);
        uint32_t target_dispatch;

        if (!target_cpu) {
            return H_PARAMETER;
        }

        /*
         * target == self is a special case, we wait until prodded, without
         * dispatch counter check.
         */
        if (cpu == target_cpu) {
            return h_confer_self(cpu);
        }

        spapr_cpu = spapr_cpu_state(target_cpu);
        if (!spapr_cpu->vpa_addr || ((dispatch & 1) == 0)) {
            return H_SUCCESS;
        }

        target_dispatch = ldl_be_phys(cs->as,
                                  spapr_cpu->vpa_addr + VPA_DISPATCH_COUNTER);
        if (target_dispatch != dispatch) {
            return H_SUCCESS;
        }

        /*
         * The targeted confer does not do anything special beyond yielding
         * the current vCPU, but even this should be better than nothing.
         * At least for single-threaded tcg, it gives the target a chance to
         * run before we run again. Multi-threaded tcg does not really do
         * anything with EXCP_YIELD yet.
         */
    }

    cs->exception_index = EXCP_YIELD;
    cs->exit_request = 1;
    cpu_loop_exit(cs);

    return H_SUCCESS;
}

static target_ulong h_prod(PowerPCCPU *cpu, SpaprMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    target_long target = args[0];
    PowerPCCPU *tcpu;
    CPUState *cs;
    SpaprCpuState *spapr_cpu;

    tcpu = spapr_find_cpu(target);
    cs = CPU(tcpu);
    if (!cs) {
        return H_PARAMETER;
    }

    spapr_cpu = spapr_cpu_state(tcpu);
    spapr_cpu->prod = true;
    cs->halted = 0;
    ppc_maybe_interrupt(&cpu->env);
    qemu_cpu_kick(cs);

    return H_SUCCESS;
}

static target_ulong h_rtas(PowerPCCPU *cpu, SpaprMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    target_ulong rtas_r3 = args[0];
    uint32_t token = rtas_ld(rtas_r3, 0);
    uint32_t nargs = rtas_ld(rtas_r3, 1);
    uint32_t nret = rtas_ld(rtas_r3, 2);

    return spapr_rtas_call(cpu, spapr, token, nargs, rtas_r3 + 12,
                           nret, rtas_r3 + 12 + 4*nargs);
}

static target_ulong h_logical_load(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                   target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    target_ulong size = args[0];
    target_ulong addr = args[1];

    switch (size) {
    case 1:
        args[0] = ldub_phys(cs->as, addr);
        return H_SUCCESS;
    case 2:
        args[0] = lduw_phys(cs->as, addr);
        return H_SUCCESS;
    case 4:
        args[0] = ldl_phys(cs->as, addr);
        return H_SUCCESS;
    case 8:
        args[0] = ldq_phys(cs->as, addr);
        return H_SUCCESS;
    }
    return H_PARAMETER;
}

static target_ulong h_logical_store(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                    target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);

    target_ulong size = args[0];
    target_ulong addr = args[1];
    target_ulong val  = args[2];

    switch (size) {
    case 1:
        stb_phys(cs->as, addr, val);
        return H_SUCCESS;
    case 2:
        stw_phys(cs->as, addr, val);
        return H_SUCCESS;
    case 4:
        stl_phys(cs->as, addr, val);
        return H_SUCCESS;
    case 8:
        stq_phys(cs->as, addr, val);
        return H_SUCCESS;
    }
    return H_PARAMETER;
}

static target_ulong h_logical_memop(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                    target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);

    target_ulong dst   = args[0]; /* Destination address */
    target_ulong src   = args[1]; /* Source address */
    target_ulong esize = args[2]; /* Element size (0=1,1=2,2=4,3=8) */
    target_ulong count = args[3]; /* Element count */
    target_ulong op    = args[4]; /* 0 = copy, 1 = invert */
    uint64_t tmp;
    unsigned int mask = (1 << esize) - 1;
    int step = 1 << esize;

    if (count > 0x80000000) {
        return H_PARAMETER;
    }

    if ((dst & mask) || (src & mask) || (op > 1)) {
        return H_PARAMETER;
    }

    if (dst >= src && dst < (src + (count << esize))) {
            dst = dst + ((count - 1) << esize);
            src = src + ((count - 1) << esize);
            step = -step;
    }

    while (count--) {
        switch (esize) {
        case 0:
            tmp = ldub_phys(cs->as, src);
            break;
        case 1:
            tmp = lduw_phys(cs->as, src);
            break;
        case 2:
            tmp = ldl_phys(cs->as, src);
            break;
        case 3:
            tmp = ldq_phys(cs->as, src);
            break;
        default:
            return H_PARAMETER;
        }
        if (op == 1) {
            tmp = ~tmp;
        }
        switch (esize) {
        case 0:
            stb_phys(cs->as, dst, tmp);
            break;
        case 1:
            stw_phys(cs->as, dst, tmp);
            break;
        case 2:
            stl_phys(cs->as, dst, tmp);
            break;
        case 3:
            stq_phys(cs->as, dst, tmp);
            break;
        }
        dst = dst + step;
        src = src + step;
    }

    return H_SUCCESS;
}

static target_ulong h_logical_icbi(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                   target_ulong opcode, target_ulong *args)
{
    /* Nothing to do on emulation, KVM will trap this in the kernel */
    return H_SUCCESS;
}

static target_ulong h_logical_dcbf(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                   target_ulong opcode, target_ulong *args)
{
    /* Nothing to do on emulation, KVM will trap this in the kernel */
    return H_SUCCESS;
}

static target_ulong h_set_mode_resource_le(PowerPCCPU *cpu,
                                           SpaprMachineState *spapr,
                                           target_ulong mflags,
                                           target_ulong value1,
                                           target_ulong value2)
{
    if (value1) {
        return H_P3;
    }
    if (value2) {
        return H_P4;
    }

    switch (mflags) {
    case H_SET_MODE_ENDIAN_BIG:
        spapr_set_all_lpcrs(0, LPCR_ILE);
        spapr_pci_switch_vga(spapr, true);
        return H_SUCCESS;

    case H_SET_MODE_ENDIAN_LITTLE:
        spapr_set_all_lpcrs(LPCR_ILE, LPCR_ILE);
        spapr_pci_switch_vga(spapr, false);
        return H_SUCCESS;
    }

    return H_UNSUPPORTED_FLAG;
}

static target_ulong h_set_mode_resource_addr_trans_mode(PowerPCCPU *cpu,
                                                        target_ulong mflags,
                                                        target_ulong value1,
                                                        target_ulong value2)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);

    if (!(pcc->insns_flags2 & PPC2_ISA207S)) {
        return H_P2;
    }
    if (value1) {
        return H_P3;
    }
    if (value2) {
        return H_P4;
    }

    if (mflags == 1) {
        /* AIL=1 is reserved in POWER8/POWER9/POWER10 */
        return H_UNSUPPORTED_FLAG;
    }

    if (mflags == 2 && (pcc->insns_flags2 & PPC2_ISA310)) {
        /* AIL=2 is reserved in POWER10 (ISA v3.1) */
        return H_UNSUPPORTED_FLAG;
    }

    spapr_set_all_lpcrs(mflags << LPCR_AIL_SHIFT, LPCR_AIL);

    return H_SUCCESS;
}

static target_ulong h_set_mode(PowerPCCPU *cpu, SpaprMachineState *spapr,
                               target_ulong opcode, target_ulong *args)
{
    target_ulong resource = args[1];
    target_ulong ret = H_P2;

    switch (resource) {
    case H_SET_MODE_RESOURCE_LE:
        ret = h_set_mode_resource_le(cpu, spapr, args[0], args[2], args[3]);
        break;
    case H_SET_MODE_RESOURCE_ADDR_TRANS_MODE:
        ret = h_set_mode_resource_addr_trans_mode(cpu, args[0],
                                                  args[2], args[3]);
        break;
    }

    return ret;
}

static target_ulong h_clean_slb(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                target_ulong opcode, target_ulong *args)
{
    qemu_log_mask(LOG_UNIMP, "Unimplemented SPAPR hcall 0x"TARGET_FMT_lx"%s\n",
                  opcode, " (H_CLEAN_SLB)");
    return H_FUNCTION;
}

static target_ulong h_invalidate_pid(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                     target_ulong opcode, target_ulong *args)
{
    qemu_log_mask(LOG_UNIMP, "Unimplemented SPAPR hcall 0x"TARGET_FMT_lx"%s\n",
                  opcode, " (H_INVALIDATE_PID)");
    return H_FUNCTION;
}

static void spapr_check_setup_free_hpt(SpaprMachineState *spapr,
                                       uint64_t patbe_old, uint64_t patbe_new)
{
    /*
     * We have 4 Options:
     * HASH->HASH || RADIX->RADIX || NOTHING->RADIX : Do Nothing
     * HASH->RADIX                                  : Free HPT
     * RADIX->HASH                                  : Allocate HPT
     * NOTHING->HASH                                : Allocate HPT
     * Note: NOTHING implies the case where we said the guest could choose
     *       later and so assumed radix and now it's called H_REG_PROC_TBL
     */

    if ((patbe_old & PATE1_GR) == (patbe_new & PATE1_GR)) {
        /* We assume RADIX, so this catches all the "Do Nothing" cases */
    } else if (!(patbe_old & PATE1_GR)) {
        /* HASH->RADIX : Free HPT */
        spapr_free_hpt(spapr);
    } else if (!(patbe_new & PATE1_GR)) {
        /* RADIX->HASH || NOTHING->HASH : Allocate HPT */
        spapr_setup_hpt(spapr);
    }
    return;
}

#define FLAGS_MASK              0x01FULL
#define FLAG_MODIFY             0x10
#define FLAG_REGISTER           0x08
#define FLAG_RADIX              0x04
#define FLAG_HASH_PROC_TBL      0x02
#define FLAG_GTSE               0x01

static target_ulong h_register_process_table(PowerPCCPU *cpu,
                                             SpaprMachineState *spapr,
                                             target_ulong opcode,
                                             target_ulong *args)
{
    target_ulong flags = args[0];
    target_ulong proc_tbl = args[1];
    target_ulong page_size = args[2];
    target_ulong table_size = args[3];
    target_ulong update_lpcr = 0;
    target_ulong table_byte_size;
    uint64_t cproc;

    if (flags & ~FLAGS_MASK) { /* Check no reserved bits are set */
        return H_PARAMETER;
    }
    if (flags & FLAG_MODIFY) {
        if (flags & FLAG_REGISTER) {
            /* Check process table alignment */
            table_byte_size = 1ULL << (table_size + 12);
            if (proc_tbl & (table_byte_size - 1)) {
                qemu_log_mask(LOG_GUEST_ERROR,
                    "%s: process table not properly aligned: proc_tbl 0x"
                    TARGET_FMT_lx" proc_tbl_size 0x"TARGET_FMT_lx"\n",
                    __func__, proc_tbl, table_byte_size);
            }
            if (flags & FLAG_RADIX) { /* Register new RADIX process table */
                if (proc_tbl & 0xfff || proc_tbl >> 60) {
                    return H_P2;
                } else if (page_size) {
                    return H_P3;
                } else if (table_size > 24) {
                    return H_P4;
                }
                cproc = PATE1_GR | proc_tbl | table_size;
            } else { /* Register new HPT process table */
                if (flags & FLAG_HASH_PROC_TBL) { /* Hash with Segment Tables */
                    /* TODO - Not Supported */
                    /* Technically caused by flag bits => H_PARAMETER */
                    return H_PARAMETER;
                } else { /* Hash with SLB */
                    if (proc_tbl >> 38) {
                        return H_P2;
                    } else if (page_size & ~0x7) {
                        return H_P3;
                    } else if (table_size > 24) {
                        return H_P4;
                    }
                }
                cproc = (proc_tbl << 25) | page_size << 5 | table_size;
            }

        } else { /* Deregister current process table */
            /*
             * Set to benign value: (current GR) | 0. This allows
             * deregistration in KVM to succeed even if the radix bit
             * in flags doesn't match the radix bit in the old PATE.
             */
            cproc = spapr->patb_entry & PATE1_GR;
        }
    } else { /* Maintain current registration */
        if (!(flags & FLAG_RADIX) != !(spapr->patb_entry & PATE1_GR)) {
            /* Technically caused by flag bits => H_PARAMETER */
            return H_PARAMETER; /* Existing Process Table Mismatch */
        }
        cproc = spapr->patb_entry;
    }

    /* Check if we need to setup OR free the hpt */
    spapr_check_setup_free_hpt(spapr, spapr->patb_entry, cproc);

    spapr->patb_entry = cproc; /* Save new process table */

    /* Update the UPRT, HR and GTSE bits in the LPCR for all cpus */
    if (flags & FLAG_RADIX)     /* Radix must use process tables, also set HR */
        update_lpcr |= (LPCR_UPRT | LPCR_HR);
    else if (flags & FLAG_HASH_PROC_TBL) /* Hash with process tables */
        update_lpcr |= LPCR_UPRT;
    if (flags & FLAG_GTSE)      /* Guest translation shootdown enable */
        update_lpcr |= LPCR_GTSE;

    spapr_set_all_lpcrs(update_lpcr, LPCR_UPRT | LPCR_HR | LPCR_GTSE);

    if (kvm_enabled()) {
        return kvmppc_configure_v3_mmu(cpu, flags & FLAG_RADIX,
                                       flags & FLAG_GTSE, cproc);
    }
    return H_SUCCESS;
}

#define H_SIGNAL_SYS_RESET_ALL         -1
#define H_SIGNAL_SYS_RESET_ALLBUTSELF  -2

static target_ulong h_signal_sys_reset(PowerPCCPU *cpu,
                                       SpaprMachineState *spapr,
                                       target_ulong opcode, target_ulong *args)
{
    target_long target = args[0];
    CPUState *cs;

    if (target < 0) {
        /* Broadcast */
        if (target < H_SIGNAL_SYS_RESET_ALLBUTSELF) {
            return H_PARAMETER;
        }

        CPU_FOREACH(cs) {
            PowerPCCPU *c = POWERPC_CPU(cs);

            if (target == H_SIGNAL_SYS_RESET_ALLBUTSELF) {
                if (c == cpu) {
                    continue;
                }
            }
            run_on_cpu(cs, spapr_do_system_reset_on_cpu, RUN_ON_CPU_NULL);
        }
        return H_SUCCESS;

    } else {
        /* Unicast */
        cs = CPU(spapr_find_cpu(target));
        if (cs) {
            run_on_cpu(cs, spapr_do_system_reset_on_cpu, RUN_ON_CPU_NULL);
            return H_SUCCESS;
        }
        return H_PARAMETER;
    }
}

/* Returns either a logical PVR or zero if none was found */
static uint32_t cas_check_pvr(PowerPCCPU *cpu, uint32_t max_compat,
                              target_ulong *addr, bool *raw_mode_supported)
{
    bool explicit_match = false; /* Matched the CPU's real PVR */
    uint32_t best_compat = 0;
    int i;

    /*
     * We scan the supplied table of PVRs looking for two things
     *   1. Is our real CPU PVR in the list?
     *   2. What's the "best" listed logical PVR
     */
    for (i = 0; i < 512; ++i) {
        uint32_t pvr, pvr_mask;

        pvr_mask = ldl_be_phys(&address_space_memory, *addr);
        pvr = ldl_be_phys(&address_space_memory, *addr + 4);
        *addr += 8;

        if (~pvr_mask & pvr) {
            break; /* Terminator record */
        }

        if ((cpu->env.spr[SPR_PVR] & pvr_mask) == (pvr & pvr_mask)) {
            explicit_match = true;
        } else {
            if (ppc_check_compat(cpu, pvr, best_compat, max_compat)) {
                best_compat = pvr;
            }
        }
    }

    *raw_mode_supported = explicit_match;

    /* Parsing finished */
    trace_spapr_cas_pvr(cpu->compat_pvr, explicit_match, best_compat);

    return best_compat;
}

static
target_ulong do_client_architecture_support(PowerPCCPU *cpu,
                                            SpaprMachineState *spapr,
                                            target_ulong vec,
                                            target_ulong fdt_bufsize)
{
    target_ulong ov_table; /* Working address in data buffer */
    uint32_t cas_pvr;
    SpaprOptionVector *ov1_guest, *ov5_guest;
    bool guest_radix;
    bool raw_mode_supported = false;
    bool guest_xive;
    CPUState *cs;
    void *fdt;
    uint32_t max_compat = spapr->max_compat_pvr;

    /* CAS is supposed to be called early when only the boot vCPU is active. */
    CPU_FOREACH(cs) {
        if (cs == CPU(cpu)) {
            continue;
        }
        if (!cs->halted) {
            warn_report("guest has multiple active vCPUs at CAS, which is not allowed");
            return H_MULTI_THREADS_ACTIVE;
        }
    }

    cas_pvr = cas_check_pvr(cpu, max_compat, &vec, &raw_mode_supported);
    if (!cas_pvr && (!raw_mode_supported || max_compat)) {
        /*
         * We couldn't find a suitable compatibility mode, and either
         * the guest doesn't support "raw" mode for this CPU, or "raw"
         * mode is disabled because a maximum compat mode is set.
         */
        error_report("Couldn't negotiate a suitable PVR during CAS");
        return H_HARDWARE;
    }

    /* Update CPUs */
    if (cpu->compat_pvr != cas_pvr) {
        Error *local_err = NULL;

        if (ppc_set_compat_all(cas_pvr, &local_err) < 0) {
            /* We fail to set compat mode (likely because running with KVM PR),
             * but maybe we can fallback to raw mode if the guest supports it.
             */
            if (!raw_mode_supported) {
                error_report_err(local_err);
                return H_HARDWARE;
            }
            error_free(local_err);
        }
    }

    /* For the future use: here @ov_table points to the first option vector */
    ov_table = vec;

    ov1_guest = spapr_ovec_parse_vector(ov_table, 1);
    if (!ov1_guest) {
        warn_report("guest didn't provide option vector 1");
        return H_PARAMETER;
    }
    ov5_guest = spapr_ovec_parse_vector(ov_table, 5);
    if (!ov5_guest) {
        spapr_ovec_cleanup(ov1_guest);
        warn_report("guest didn't provide option vector 5");
        return H_PARAMETER;
    }
    if (spapr_ovec_test(ov5_guest, OV5_MMU_BOTH)) {
        error_report("guest requested hash and radix MMU, which is invalid.");
        exit(EXIT_FAILURE);
    }
    if (spapr_ovec_test(ov5_guest, OV5_XIVE_BOTH)) {
        error_report("guest requested an invalid interrupt mode");
        exit(EXIT_FAILURE);
    }

    guest_radix = spapr_ovec_test(ov5_guest, OV5_MMU_RADIX_300);

    guest_xive = spapr_ovec_test(ov5_guest, OV5_XIVE_EXPLOIT);

    /*
     * HPT resizing is a bit of a special case, because when enabled
     * we assume an HPT guest will support it until it says it
     * doesn't, instead of assuming it won't support it until it says
     * it does.  Strictly speaking that approach could break for
     * guests which don't make a CAS call, but those are so old we
     * don't care about them.  Without that assumption we'd have to
     * make at least a temporary allocation of an HPT sized for max
     * memory, which could be impossibly difficult under KVM HV if
     * maxram is large.
     */
    if (!guest_radix && !spapr_ovec_test(ov5_guest, OV5_HPT_RESIZE)) {
        int maxshift = spapr_hpt_shift_for_ramsize(MACHINE(spapr)->maxram_size);

        if (spapr->resize_hpt == SPAPR_RESIZE_HPT_REQUIRED) {
            error_report(
                "h_client_architecture_support: Guest doesn't support HPT resizing, but resize-hpt=required");
            exit(1);
        }

        if (spapr->htab_shift < maxshift) {
            /* Guest doesn't know about HPT resizing, so we
             * pre-emptively resize for the maximum permitted RAM.  At
             * the point this is called, nothing should have been
             * entered into the existing HPT */
            spapr_reallocate_hpt(spapr, maxshift, &error_fatal);
            push_sregs_to_kvm_pr(spapr);
        }
    }

    /* NOTE: there are actually a number of ov5 bits where input from the
     * guest is always zero, and the platform/QEMU enables them independently
     * of guest input. To model these properly we'd want some sort of mask,
     * but since they only currently apply to memory migration as defined
     * by LoPAPR 1.1, 14.5.4.8, which QEMU doesn't implement, we don't need
     * to worry about this for now.
     */

    /* full range of negotiated ov5 capabilities */
    spapr_ovec_intersect(spapr->ov5_cas, spapr->ov5, ov5_guest);
    spapr_ovec_cleanup(ov5_guest);

    spapr_check_mmu_mode(guest_radix);

    spapr->cas_pre_isa3_guest = !spapr_ovec_test(ov1_guest, OV1_PPC_3_00);
    spapr_ovec_cleanup(ov1_guest);

    /*
     * Check for NUMA affinity conditions now that we know which NUMA
     * affinity the guest will use.
     */
    spapr_numa_associativity_check(spapr);

    /*
     * Ensure the guest asks for an interrupt mode we support;
     * otherwise terminate the boot.
     */
    if (guest_xive) {
        if (!spapr->irq->xive) {
            error_report(
"Guest requested unavailable interrupt mode (XIVE), try the ic-mode=xive or ic-mode=dual machine property");
            exit(EXIT_FAILURE);
        }
    } else {
        if (!spapr->irq->xics) {
            error_report(
"Guest requested unavailable interrupt mode (XICS), either don't set the ic-mode machine property or try ic-mode=xics or ic-mode=dual");
            exit(EXIT_FAILURE);
        }
    }

    spapr_irq_update_active_intc(spapr);

    /*
     * Process all pending hot-plug/unplug requests now. An updated full
     * rendered FDT will be returned to the guest.
     */
    spapr_drc_reset_all(spapr);
    spapr_clear_pending_hotplug_events(spapr);

    /*
     * If spapr_machine_reset() did not set up a HPT but one is necessary
     * (because the guest isn't going to use radix) then set it up here.
     */
    if ((spapr->patb_entry & PATE1_GR) && !guest_radix) {
        /* legacy hash or new hash: */
        spapr_setup_hpt(spapr);
    }

    fdt = spapr_build_fdt(spapr, spapr->vof != NULL, fdt_bufsize);
    g_free(spapr->fdt_blob);
    spapr->fdt_size = fdt_totalsize(fdt);
    spapr->fdt_initial_size = spapr->fdt_size;
    spapr->fdt_blob = fdt;

    /*
     * Set the machine->fdt pointer again since we just freed
     * it above (by freeing spapr->fdt_blob). We set this
     * pointer to enable support for the 'dumpdtb' QMP/HMP
     * command.
     */
    MACHINE(spapr)->fdt = fdt;

    return H_SUCCESS;
}

static target_ulong h_client_architecture_support(PowerPCCPU *cpu,
                                                  SpaprMachineState *spapr,
                                                  target_ulong opcode,
                                                  target_ulong *args)
{
    target_ulong vec = ppc64_phys_to_real(args[0]);
    target_ulong fdt_buf = args[1];
    target_ulong fdt_bufsize = args[2];
    target_ulong ret;
    SpaprDeviceTreeUpdateHeader hdr = { .version_id = 1 };

    if (fdt_bufsize < sizeof(hdr)) {
        error_report("SLOF provided insufficient CAS buffer "
                     TARGET_FMT_lu " (min: %zu)", fdt_bufsize, sizeof(hdr));
        exit(EXIT_FAILURE);
    }

    fdt_bufsize -= sizeof(hdr);

    ret = do_client_architecture_support(cpu, spapr, vec, fdt_bufsize);
    if (ret == H_SUCCESS) {
        _FDT((fdt_pack(spapr->fdt_blob)));
        spapr->fdt_size = fdt_totalsize(spapr->fdt_blob);
        spapr->fdt_initial_size = spapr->fdt_size;

        cpu_physical_memory_write(fdt_buf, &hdr, sizeof(hdr));
        cpu_physical_memory_write(fdt_buf + sizeof(hdr), spapr->fdt_blob,
                                  spapr->fdt_size);
        trace_spapr_cas_continue(spapr->fdt_size + sizeof(hdr));
    }

    return ret;
}

target_ulong spapr_vof_client_architecture_support(MachineState *ms,
                                                   CPUState *cs,
                                                   target_ulong ovec_addr)
{
    SpaprMachineState *spapr = SPAPR_MACHINE(ms);

    target_ulong ret = do_client_architecture_support(POWERPC_CPU(cs), spapr,
                                                      ovec_addr, FDT_MAX_SIZE);

    /*
     * This adds stdout and generates phandles for boottime and CAS FDTs.
     * It is alright to update the FDT here as do_client_architecture_support()
     * does not pack it.
     */
    spapr_vof_client_dt_finalize(spapr, spapr->fdt_blob);

    return ret;
}

static target_ulong h_get_cpu_characteristics(PowerPCCPU *cpu,
                                              SpaprMachineState *spapr,
                                              target_ulong opcode,
                                              target_ulong *args)
{
    uint64_t characteristics = H_CPU_CHAR_HON_BRANCH_HINTS &
                               ~H_CPU_CHAR_THR_RECONF_TRIG;
    uint64_t behaviour = H_CPU_BEHAV_FAVOUR_SECURITY;
    uint8_t safe_cache = spapr_get_cap(spapr, SPAPR_CAP_CFPC);
    uint8_t safe_bounds_check = spapr_get_cap(spapr, SPAPR_CAP_SBBC);
    uint8_t safe_indirect_branch = spapr_get_cap(spapr, SPAPR_CAP_IBS);
    uint8_t count_cache_flush_assist = spapr_get_cap(spapr,
                                                     SPAPR_CAP_CCF_ASSIST);

    switch (safe_cache) {
    case SPAPR_CAP_WORKAROUND:
        characteristics |= H_CPU_CHAR_L1D_FLUSH_ORI30;
        characteristics |= H_CPU_CHAR_L1D_FLUSH_TRIG2;
        characteristics |= H_CPU_CHAR_L1D_THREAD_PRIV;
        behaviour |= H_CPU_BEHAV_L1D_FLUSH_PR;
        break;
    case SPAPR_CAP_FIXED:
        behaviour |= H_CPU_BEHAV_NO_L1D_FLUSH_ENTRY;
        behaviour |= H_CPU_BEHAV_NO_L1D_FLUSH_UACCESS;
        break;
    default: /* broken */
        assert(safe_cache == SPAPR_CAP_BROKEN);
        behaviour |= H_CPU_BEHAV_L1D_FLUSH_PR;
        break;
    }

    switch (safe_bounds_check) {
    case SPAPR_CAP_WORKAROUND:
        characteristics |= H_CPU_CHAR_SPEC_BAR_ORI31;
        behaviour |= H_CPU_BEHAV_BNDS_CHK_SPEC_BAR;
        break;
    case SPAPR_CAP_FIXED:
        break;
    default: /* broken */
        assert(safe_bounds_check == SPAPR_CAP_BROKEN);
        behaviour |= H_CPU_BEHAV_BNDS_CHK_SPEC_BAR;
        break;
    }

    switch (safe_indirect_branch) {
    case SPAPR_CAP_FIXED_NA:
        break;
    case SPAPR_CAP_FIXED_CCD:
        characteristics |= H_CPU_CHAR_CACHE_COUNT_DIS;
        break;
    case SPAPR_CAP_FIXED_IBS:
        characteristics |= H_CPU_CHAR_BCCTRL_SERIALISED;
        break;
    case SPAPR_CAP_WORKAROUND:
        behaviour |= H_CPU_BEHAV_FLUSH_COUNT_CACHE;
        if (count_cache_flush_assist) {
            characteristics |= H_CPU_CHAR_BCCTR_FLUSH_ASSIST;
        }
        break;
    default: /* broken */
        assert(safe_indirect_branch == SPAPR_CAP_BROKEN);
        break;
    }

    args[0] = characteristics;
    args[1] = behaviour;
    return H_SUCCESS;
}

static target_ulong h_update_dt(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                target_ulong opcode, target_ulong *args)
{
    target_ulong dt = ppc64_phys_to_real(args[0]);
    struct fdt_header hdr = { 0 };
    unsigned cb;
    SpaprMachineClass *smc = SPAPR_MACHINE_GET_CLASS(spapr);
    void *fdt;

    cpu_physical_memory_read(dt, &hdr, sizeof(hdr));
    cb = fdt32_to_cpu(hdr.totalsize);

    if (!smc->update_dt_enabled) {
        return H_SUCCESS;
    }

    /* Check that the fdt did not grow out of proportion */
    if (cb > spapr->fdt_initial_size * 2) {
        trace_spapr_update_dt_failed_size(spapr->fdt_initial_size, cb,
                                          fdt32_to_cpu(hdr.magic));
        return H_PARAMETER;
    }

    fdt = g_malloc0(cb);
    cpu_physical_memory_read(dt, fdt, cb);

    /* Check the fdt consistency */
    if (fdt_check_full(fdt, cb)) {
        trace_spapr_update_dt_failed_check(spapr->fdt_initial_size, cb,
                                           fdt32_to_cpu(hdr.magic));
        return H_PARAMETER;
    }

    g_free(spapr->fdt_blob);
    spapr->fdt_size = cb;
    spapr->fdt_blob = fdt;
    trace_spapr_update_dt(cb);

    return H_SUCCESS;
}

static spapr_hcall_fn papr_hypercall_table[(MAX_HCALL_OPCODE / 4) + 1];
static spapr_hcall_fn kvmppc_hypercall_table[KVMPPC_HCALL_MAX - KVMPPC_HCALL_BASE + 1];
static spapr_hcall_fn svm_hypercall_table[(SVM_HCALL_MAX - SVM_HCALL_BASE) / 4 + 1];

void spapr_register_hypercall(target_ulong opcode, spapr_hcall_fn fn)
{
    spapr_hcall_fn *slot;

    if (opcode <= MAX_HCALL_OPCODE) {
        assert((opcode & 0x3) == 0);

        slot = &papr_hypercall_table[opcode / 4];
    } else if (opcode >= SVM_HCALL_BASE && opcode <= SVM_HCALL_MAX) {
        /* we only have SVM-related hcall numbers assigned in multiples of 4 */
        assert((opcode & 0x3) == 0);

        slot = &svm_hypercall_table[(opcode - SVM_HCALL_BASE) / 4];
    } else {
        assert((opcode >= KVMPPC_HCALL_BASE) && (opcode <= KVMPPC_HCALL_MAX));

        slot = &kvmppc_hypercall_table[opcode - KVMPPC_HCALL_BASE];
    }

    assert(!(*slot));
    *slot = fn;
}

target_ulong spapr_hypercall(PowerPCCPU *cpu, target_ulong opcode,
                             target_ulong *args)
{
    SpaprMachineState *spapr = SPAPR_MACHINE(qdev_get_machine());

    if ((opcode <= MAX_HCALL_OPCODE)
        && ((opcode & 0x3) == 0)) {
        spapr_hcall_fn fn = papr_hypercall_table[opcode / 4];

        if (fn) {
            return fn(cpu, spapr, opcode, args);
        }
    } else if ((opcode >= SVM_HCALL_BASE) &&
               (opcode <= SVM_HCALL_MAX)) {
        spapr_hcall_fn fn = svm_hypercall_table[(opcode - SVM_HCALL_BASE) / 4];

        if (fn) {
            return fn(cpu, spapr, opcode, args);
        }
    } else if ((opcode >= KVMPPC_HCALL_BASE) &&
               (opcode <= KVMPPC_HCALL_MAX)) {
        spapr_hcall_fn fn = kvmppc_hypercall_table[opcode - KVMPPC_HCALL_BASE];

        if (fn) {
            return fn(cpu, spapr, opcode, args);
        }
    }

    qemu_log_mask(LOG_UNIMP, "Unimplemented SPAPR hcall 0x" TARGET_FMT_lx "\n",
                  opcode);
    return H_FUNCTION;
}

#ifdef CONFIG_TCG

#define PRTS_MASK      0x1f

static target_ulong h_set_ptbl(PowerPCCPU *cpu,
                               SpaprMachineState *spapr,
                               target_ulong opcode,
                               target_ulong *args)
{
    target_ulong ptcr = args[0];

    if (!spapr_get_cap(spapr, SPAPR_CAP_NESTED_KVM_HV)) {
        return H_FUNCTION;
    }

    if ((ptcr & PRTS_MASK) + 12 - 4 > 12) {
        return H_PARAMETER;
    }

    spapr->nested.ptcr = ptcr; /* Save new partition table */

    return H_SUCCESS;
}

static target_ulong h_tlb_invalidate(PowerPCCPU *cpu,
                                     SpaprMachineState *spapr,
                                     target_ulong opcode,
                                     target_ulong *args)
{
    /*
     * The spapr virtual hypervisor nested HV implementation retains no L2
     * translation state except for TLB. And the TLB is always invalidated
     * across L1<->L2 transitions, so nothing is required here.
     */

    return H_SUCCESS;
}

static target_ulong h_copy_tofrom_guest(PowerPCCPU *cpu,
                                        SpaprMachineState *spapr,
                                        target_ulong opcode,
                                        target_ulong *args)
{
    /*
     * This HCALL is not required, L1 KVM will take a slow path and walk the
     * page tables manually to do the data copy.
     */
    return H_FUNCTION;
}

static void restore_common_regs(CPUPPCState *dst, CPUPPCState *src)
{
    memcpy(dst->gpr, src->gpr, sizeof(dst->gpr));
    memcpy(dst->crf, src->crf, sizeof(dst->crf));
    memcpy(dst->vsr, src->vsr, sizeof(dst->vsr));
    dst->nip = src->nip;
    dst->msr = src->msr;
    dst->lr  = src->lr;
    dst->ctr = src->ctr;
    dst->cfar = src->cfar;
    cpu_write_xer(dst, src->xer);
    ppc_store_vscr(dst, ppc_get_vscr(src));
    ppc_store_fpscr(dst, src->fpscr);

    memcpy(dst->spr, src->spr, sizeof(dst->spr));
}

static void restore_hdec_from_hvstate_env(CPUPPCState *dst,
                                          struct kvmppc_hv_guest_state *hv_state,
                                          CPUPPCState *src, target_ulong now)
{
    target_ulong hdec;
    if (hv_state) {
        hdec = hv_state->hdec_expiry - now;
    } else if (src) {
        hdec = src->tb_env->hdecr_expiry_tb - now;
    } else {
        assert(0); /* shall not reach here */
    }
    cpu_ppc_hdecr_init(dst);
    cpu_ppc_store_hdecr(dst, hdec);
}

static void restore_lpcr_from_hvstate_env(PowerPCCPU *cpu,
                                          struct kvmppc_hv_guest_state *hv_state,
                                          CPUPPCState *src)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);
    CPUPPCState *dst = &cpu->env;
    target_ulong lpcr, lpcr_mask;
    lpcr_mask = LPCR_DPFD | LPCR_ILE | LPCR_AIL | LPCR_LD | LPCR_MER;
    if (hv_state) {
        lpcr = (dst->spr[SPR_LPCR] & ~lpcr_mask) | (hv_state->lpcr & lpcr_mask);
    } else if (src) {
        lpcr = (dst->spr[SPR_LPCR] & ~lpcr_mask) |
               (src->spr[SPR_LPCR] & lpcr_mask);
    } else {
        assert(0); /* shall not reach here */
    }
    lpcr |= LPCR_HR | LPCR_UPRT | LPCR_GTSE | LPCR_HVICE | LPCR_HDICE;
    lpcr &= ~LPCR_LPES0;
    dst->spr[SPR_LPCR] = lpcr & pcc->lpcr_mask;
}

static void restore_env_from_ptregs_hvstate(CPUPPCState *env,
                                            struct kvmppc_pt_regs *regs,
                                            struct kvmppc_hv_guest_state *hv_state)
{
    assert(env);
    assert(regs);
    assert(hv_state);
    assert(sizeof(env->gpr) == sizeof(regs->gpr));
    memcpy(env->gpr, regs->gpr, sizeof(env->gpr));
    env->nip = regs->nip;
    env->msr = regs->msr;
    env->lr = regs->link;
    env->ctr = regs->ctr;
    cpu_write_xer(env, regs->xer);
    ppc_store_cr(env, regs->ccr);
    /* hv_state->amor is not used in api v1 */
    env->spr[SPR_HFSCR] = hv_state->hfscr;
    /* TCG does not implement DAWR*, CIABR, PURR, SPURR, IC, VTB, HEIR SPRs*/
    env->cfar = hv_state->cfar;
    env->spr[SPR_PCR]      = hv_state->pcr;
    env->spr[SPR_DPDES]     = hv_state->dpdes;
    env->spr[SPR_SRR0]      = hv_state->srr0;
    env->spr[SPR_SRR1]      = hv_state->srr1;
    env->spr[SPR_SPRG0]     = hv_state->sprg[0];
    env->spr[SPR_SPRG1]     = hv_state->sprg[1];
    env->spr[SPR_SPRG2]     = hv_state->sprg[2];
    env->spr[SPR_SPRG3]     = hv_state->sprg[3];
    env->spr[SPR_BOOKS_PID] = hv_state->pidr;
    env->spr[SPR_PPR]       = hv_state->ppr;
}

static void enter_nested(PowerPCCPU *cpu,
                         uint64_t lpid,
                         struct kvmppc_hv_guest_state *hv_state,
                         struct kvmppc_pt_regs *regs,
                         struct SpaprMachineStateNestedGuestVcpu *vcpu)
{
    SpaprMachineState *spapr = SPAPR_MACHINE(qdev_get_machine());
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);
    target_ulong now = cpu_ppc_load_tbl(env);

    assert(env->spr[SPR_LPIDR] == 0);
    // TODO: we should preallocate this
    spapr_cpu->nested_host_state = g_try_new(CPUPPCState, 1);
    assert(spapr_cpu->nested_host_state);
    memcpy(spapr_cpu->nested_host_state, env, sizeof(CPUPPCState));

    if (spapr->nested.api == NESTED_API_KVM_HV) {
        /* API v1 */
        restore_env_from_ptregs_hvstate(env, regs, hv_state);
        restore_lpcr_from_hvstate_env(cpu, hv_state, NULL);
        restore_hdec_from_hvstate_env(env, hv_state, NULL, now);
        spapr_cpu->nested_tb_offset = hv_state->tb_offset;
    } else {
        /* API v2 */
        assert(vcpu);
        assert(!hv_state);
        assert(!regs);
        assert(sizeof(env->gpr) == sizeof(vcpu->env.gpr));
        restore_common_regs(env, &vcpu->env);
        restore_lpcr_from_hvstate_env(cpu, NULL, &vcpu->env);
        restore_hdec_from_hvstate_env(env, NULL, &vcpu->env, now);
        cpu_ppc_store_decr(env, vcpu->dec_expiry_tb - now);
        spapr_cpu->nested_tb_offset = vcpu->tb_offset;
    }
    env->spr[SPR_LPIDR] = lpid; /* post restore_common_regs */

    /*
     * The hv_state->vcpu_token is not needed. It is used by the KVM
     * implementation to remember which L2 vCPU last ran on which physical
     * CPU so as to invalidate process scope translations if it is moved
     * between physical CPUs. For now TLBs are always flushed on L1<->L2
     * transitions so this is not a problem.
     *
     * Could validate that the same vcpu_token does not attempt to run on
     * different L1 vCPUs at the same time, but that would be a L1 KVM bug
     * and it's not obviously worth a new data structure to do it.
     */

    env->tb_env->tb_offset += spapr_cpu->nested_tb_offset;
    spapr_cpu->in_nested = true;

    hreg_compute_hflags(env);
    ppc_maybe_interrupt(env);
    tlb_flush(cs);
    env->reserve_addr = -1; /* Reset the reservation */

}

/*
 * When this handler returns, the environment is switched to the L2 guest
 * and TCG begins running that. spapr_exit_nested() performs the switch from
 * L2 back to L1 and returns from the H_ENTER_NESTED hcall.
 */
static target_ulong h_enter_nested(PowerPCCPU *cpu,
                                   SpaprMachineState *spapr,
                                   target_ulong opcode,
                                   target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    target_ulong hv_ptr = args[0];
    target_ulong regs_ptr = args[1];
    struct kvmppc_hv_guest_state *hvstate;
    struct kvmppc_hv_guest_state hv_state;
    struct kvmppc_pt_regs *regs;
    hwaddr len;

    if (spapr->nested.ptcr == 0) {
        return H_NOT_AVAILABLE;
    }

    len = sizeof(*hvstate);
    hvstate = address_space_map(CPU(cpu)->as, hv_ptr, &len, false,
                                MEMTXATTRS_UNSPECIFIED);
    if (len != sizeof(*hvstate)) {
        address_space_unmap(CPU(cpu)->as, hvstate, len, 0, false);
        return H_PARAMETER;
    }

    memcpy(&hv_state, hvstate, len);

    address_space_unmap(CPU(cpu)->as, hvstate, len, len, false);

    /*
     * We accept versions 1 and 2. Version 2 fields are unused because TCG
     * does not implement DAWR*.
     */
    if (hv_state.version > HV_GUEST_STATE_VERSION) {
        return H_PARAMETER;
    }


    len = sizeof(*regs);
    regs = address_space_map(CPU(cpu)->as, regs_ptr, &len, false,
                                MEMTXATTRS_UNSPECIFIED);
    if (!regs || len != sizeof(*regs)) {
        address_space_unmap(CPU(cpu)->as, regs, len, 0, false);
        return H_P2;
    }

    enter_nested(cpu, hv_state.lpid, &hv_state, regs, NULL);

    address_space_unmap(CPU(cpu)->as, regs, len, len, false);

    /*
     * The spapr hcall helper sets env->gpr[3] to the return value, but at
     * this point the L1 is not returning from the hcall but rather we
     * start running the L2, so r3 must not be clobbered, so return env->gpr[3]
     * to leave it unchanged.
     */
    return env->gpr[3];
}

#define NESTED_GUEST_MAX 4096
#define NESTED_GUEST_VCPU_MAX 2048

#define VCPU_OUT_BUF_MIN_SZ      0x80ULL
#define H_GUEST_DELETE_ALL_MASK  0x8000000000000000ULL

struct guest_state_element {
    uint16_t id;   /* Big Endian */
    uint16_t size; /* Big Endian */
    uint8_t value[]; /* Big Endian (based on size above) */
} QEMU_PACKED;

struct guest_state_buffer {
    uint32_t num_elements; /* Big Endian */
    struct guest_state_element elements[];
} QEMU_PACKED;

#define GUEST_STATE_REQUEST_GUEST_WIDE      0x1
#define GUEST_STATE_REQUEST_SET             0x2
#define GUEST_STATE_REQUEST_TAKE_OWNERSHIP  0x4

/* Actuall buffer plus some metadata about the request */
struct guest_state_request {
    struct guest_state_buffer *gsb;
    int64_t buf;
    int64_t len;
    uint16_t flags;
};

#define GUEST_STATE_ELEMENT_TYPE_FLAG_GUEST_WIDE 0x1
#define GUEST_STATE_ELEMENT_TYPE_FLAG_READ_ONLY  0x2

struct guest_state_element_type {
    uint16_t id;
    int size;
    uint16_t flags;
    void *(* location)(SpaprMachineStateNestedGuest *, target_ulong);
    size_t offset;
    void (* copy)(void *, void *, bool);
};

SpaprMachineStateNestedGuest *spapr_get_nested_guest(SpaprMachineState *spapr,
                                                     target_ulong lpid)
{
    SpaprMachineStateNestedGuest *guest;
    guest = g_hash_table_lookup(spapr->nested.guests, GINT_TO_POINTER(lpid));
    if (!guest) {
        assert(0);
        return NULL;
    }

    return guest;
}

static bool vcpu_check(SpaprMachineStateNestedGuest *guest,
                       target_ulong vcpuid,
                       bool inoutbuf)
{
    struct SpaprMachineStateNestedGuestVcpu *vcpu;

    if (vcpuid >= NESTED_GUEST_VCPU_MAX) {
        assert(0);
        return false;
    }

    if (!(vcpuid < guest->vcpus)) {
        assert(0);
        return false;
    }

    vcpu = &guest->vcpu[vcpuid];
    if (!vcpu->enabled) {
        assert(0);
        return false;
    }

    if (!inoutbuf)
        return true;

    /* Check to see if the in/out buffers are registered */
    if (vcpu->runbufin.addr && vcpu->runbufout.addr)
        return true;

    assert(0);
    return false;
}

/* set=1 means the L1 is trying to set some state
 * set=0 means the L1 is trying to get some state */
static void copy_state(void *a, void *b, int size, bool set)
{
    /* set takes from the Big endian element_buf and sets internal
     * buffer */

    assert(size == 8);

    if (set)
        *(uint64_t *)a = be64_to_cpu(*(uint64_t *)b);
    else
        *(uint64_t *)b = cpu_to_be64(*(uint64_t *)a);
}

static void copy_state_16to16(void *a, void *b, bool set)
{
    uint64_t *src, *dst;

    if (set) {
        src = b;
        dst = a;

        dst[1]= be64_to_cpu(src[0]);
        dst[0] = be64_to_cpu(src[1]);
    } else {
        src = a;
        dst = b;

        dst[1] = cpu_to_be64(src[0]);
        dst[0] = cpu_to_be64(src[1]);
    }
}

static void copy_state_8to8(void *a, void *b, bool set)
{
    copy_state(a, b, 8, set);
}

static void copy_state_4to8(void *a, void *b, bool set)
{
    if (set)
        *(uint64_t *)a  = (uint64_t) be32_to_cpu(*(uint32_t *)b);
    else
        *(uint32_t *)b = cpu_to_be32((uint32_t) (*((uint64_t *)a)));
}

static void copy_state_pagetbl(void *a, void *b, bool set)
{
    uint64_t *pagetbl;
    uint64_t *buf; /* 3 double words */
    uint64_t rts;

    assert(set);

    pagetbl = a;
    buf = b;

    *pagetbl = be64_to_cpu(buf[0]);
    *pagetbl |= PATE0_HR;

    /* RTS */
    rts = be64_to_cpu(buf[1]);
    assert(rts == 52);
    rts = rts - 31;
    *pagetbl |=  ((rts & 0x7) << 5);
    *pagetbl |=  (((rts >> 3) & 0x3) << 61);

    /* RPDS */
    *pagetbl |= 63 - clz64(be64_to_cpu(buf[2])) - 3;
}

static void copy_state_proctbl(void *a, void *b, bool set)
{
    uint64_t *proctbl;
    uint64_t *buf; /* 2 double words */

    assert(set);

    proctbl = a;
    buf = b;

    *proctbl = be64_to_cpu(buf[0]);

    if (be64_to_cpu(buf[1]) == (1ULL << 12))
            *proctbl |= 0;
    else if (be64_to_cpu(buf[1]) == (1ULL << 24))
            *proctbl |= 12;
    else
        assert(0);
}

static void copy_state_runbuf(void *a, void *b, bool set)
{
    uint64_t *buf; /* 2 double words */
    struct SpaprMachineStateNestedGuestVcpuRunBuf *runbuf;

    assert(set);

    runbuf = a;
    buf = b;

    runbuf->addr = be64_to_cpu(buf[0]);
    assert(runbuf->addr);

    /* per spec */
    assert(be64_to_cpu(buf[1]) <= 16384);

    /* This will also hit in the input buffer but should be fine for
     * now. If not we can split this function.
     */
    assert(be64_to_cpu(buf[1]) >= VCPU_OUT_BUF_MIN_SZ);

    runbuf->size = be64_to_cpu(buf[1]);
}

/* tell the L1 how big we want the output vcpu run buffer */
static void out_buf_min_size(void *a, void *b, bool set)
{
    uint64_t *buf; /* 1 double word */

    assert(!set);

    buf = b;

    buf[0] = cpu_to_be64(VCPU_OUT_BUF_MIN_SZ);
}

static void copy_logical_pvr(void *a, void *b, bool set)
{
    uint32_t *buf; /* 1 word */
    uint32_t *pvr_logical_ptr;
    uint32_t pvr_logical;

    pvr_logical_ptr = a;
    buf = b;

    if (!set) {
        buf[0] = cpu_to_be32(*pvr_logical_ptr);
        return;
    }

    pvr_logical = be32_to_cpu(buf[0]);
    /* don't change the major version */
    if ((pvr_logical & CPU_POWERPC_POWER_SERVER_MASK) !=
        (*pvr_logical_ptr & CPU_POWERPC_POWER_SERVER_MASK))
        assert(0);

    *pvr_logical_ptr = pvr_logical;
}

static void copy_tb_offset(void *a, void *b, bool set)
{
    SpaprMachineStateNestedGuest *guest;
    uint64_t *buf; /* 1 double word */
    uint64_t *tb_offset_ptr;
    uint64_t tb_offset;

    tb_offset_ptr = a;
    buf = b;

    if (!set) {
        buf[0] = cpu_to_be64(*tb_offset_ptr);
        return;
    }

    tb_offset = be64_to_cpu(buf[0]);
    /* need to copy this to the individual tb_offset for each vcpu */
    guest = container_of(tb_offset_ptr, struct SpaprMachineStateNestedGuest, tb_offset);
    for (int i = 0; i < guest->vcpus; i++)
        guest->vcpu[i].tb_offset = tb_offset;
}

static void copy_state_dec_expire_tb(void *a, void *b, bool set)
{
    int64_t *dec_expiry_tb;
    uint64_t *buf; /* 1 double word */

    dec_expiry_tb = a;
    buf = b;

    if (!set) {
        buf[0] = cpu_to_be64(*dec_expiry_tb);
        return;
    }

    *dec_expiry_tb = be64_to_cpu(buf[0]);
}

static void copy_state_hdecr(void *a, void *b, bool set)
{
    uint64_t *buf; /* 1 double word */
    CPUPPCState *env;

    env = a;
    buf = b;

    if (!set) {
        buf[0] = cpu_to_be64(env->tb_env->hdecr_expiry_tb);
        return;
    }

    env->tb_env->hdecr_expiry_tb = be64_to_cpu(buf[0]);
}

static void copy_state_vscr(void *a, void *b, bool set)
{
    uint32_t *buf; /* 1 word */
    CPUPPCState *env;

    env = a;
    buf = b;

    if (!set) {
        buf[0] = cpu_to_be32(ppc_get_vscr(env));
        return;
    }

    ppc_store_vscr(env, be32_to_cpu(buf[0]));
}

static void copy_state_fpscr(void *a, void *b, bool set)
{
    uint64_t *buf; /* 1 double word */
    CPUPPCState *env;

    env = a;
    buf = b;

    if (!set) {
        buf[0] = cpu_to_be64(env->fpscr);
        return;
    }

    ppc_store_fpscr(env, be64_to_cpu(buf[0]));
}

static void copy_state_cr(void *a, void *b, bool set)
{
    uint32_t *buf; /* 1 word */
    CPUPPCState *env;
    uint64_t cr; /* api v1 uses uint64_t but papr acr v2 mentions 4 bytes */
    env = a;
    buf = b;

    if (!set) {
        buf[0] = cpu_to_be32((uint32_t)ppc_get_cr(env));
        return;
    }
    cr = be32_to_cpu(buf[0]);
    ppc_store_cr(env, cr);
}

static void *get_vcpu_env_ptr(SpaprMachineStateNestedGuest *guest,
                              target_ulong vcpuid)
{
    assert(vcpu_check(guest, vcpuid, false));
    return &guest->vcpu[vcpuid].env;
}

static void *get_vcpu_ptr(SpaprMachineStateNestedGuest *guest,
                                   target_ulong vcpuid)
{
    assert(vcpu_check(guest, vcpuid, false));
    return &guest->vcpu[vcpuid];
}

static void *get_guest_ptr(SpaprMachineStateNestedGuest *guest,
                           target_ulong vcpuid)
{
    return guest;
}

#define GUEST_STATE_ELEMENT(i, sz, s, f, ptr, c) { \
    .id = (i),                                     \
    .size = (sz),                                  \
    .location = ptr,                               \
    .offset = offsetof(struct s, f),               \
    .copy = (c)                                    \
}

#define GSBE_NESTED(i, sz, f, c) {                             \
    .id = (i),                                                 \
    .size = (sz),                                              \
    .location = get_guest_ptr,                                 \
    .offset = offsetof(struct SpaprMachineStateNestedGuest, f),\
    .copy = (c)                                                \
}

#define GSBE_NESTED_VCPU(i, sz, f, c) {                            \
    .id = (i),                                                     \
    .size = (sz),                                                  \
    .location = get_vcpu_ptr,                                      \
    .offset = offsetof(struct SpaprMachineStateNestedGuestVcpu, f),\
    .copy = (c)                                                    \
}

#define GUEST_STATE_ELEMENT_NOP(i, sz) { \
    .id = (i),                             \
    .size = (sz),                          \
    .location = NULL,                      \
    .offset = 0,                           \
    .copy = NULL                           \
}
#define GUEST_STATE_ELEMENT_NOP_DW(i)   \
        GUEST_STATE_ELEMENT_NOP(i, 8)
#define GUEST_STATE_ELEMENT_NOP_W(i) \
        GUEST_STATE_ELEMENT_NOP(i, 4)

#define GUEST_STATE_ELEMENT_ENV_BASE(i, s, c) {  \
            .id = (i),                           \
            .size = (s),                         \
            .location = get_vcpu_env_ptr,        \
            .offset = 0,                         \
            .copy = (c)                          \
    }

#define GUEST_STATE_ELEMENT_ENV(i, s, f, c) {    \
            .id = (i),                           \
            .size = (s),                         \
            .location = get_vcpu_env_ptr,        \
            .offset = offsetof(CPUPPCState, f),  \
            .copy = (c)                          \
    }
#define GUEST_STATE_ELEMENT_ENV_DW(i, f) \
    GUEST_STATE_ELEMENT_ENV(i, 8, f, copy_state_8to8)
#define GUEST_STATE_ELEMENT_ENV_W(i, f) \
    GUEST_STATE_ELEMENT_ENV(i, 4, f, copy_state_4to8)

struct guest_state_element_type guest_state_element_types[] = {
    GUEST_STATE_ELEMENT_NOP(GSB_HV_VCPU_IGNORED_ID, 0),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR0,  gpr[0]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR1,  gpr[1]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR2,  gpr[2]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR3,  gpr[3]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR4,  gpr[4]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR5,  gpr[5]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR6,  gpr[6]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR7,  gpr[7]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR8,  gpr[8]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR9,  gpr[9]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR10, gpr[10]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR11, gpr[11]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR12, gpr[12]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR13, gpr[13]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR14, gpr[14]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR15, gpr[15]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR16, gpr[16]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR17, gpr[17]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR18, gpr[18]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR19, gpr[19]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR20, gpr[20]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR21, gpr[21]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR22, gpr[22]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR23, gpr[23]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR24, gpr[24]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR25, gpr[25]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR26, gpr[26]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR27, gpr[27]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR28, gpr[28]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR29, gpr[29]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR30, gpr[30]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_GPR31, gpr[31]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_NIA, nip),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_MSR, msr),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_CTR, ctr),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_LR, lr),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_XER, xer),
    GUEST_STATE_ELEMENT_ENV_BASE(GSB_VCPU_SPR_CR, 4, copy_state_cr),
    GUEST_STATE_ELEMENT_NOP_DW(GSB_VCPU_SPR_MMCR3),
    GUEST_STATE_ELEMENT_NOP_DW(GSB_VCPU_SPR_SIER2),
    GUEST_STATE_ELEMENT_NOP_DW(GSB_VCPU_SPR_SIER3),
    GUEST_STATE_ELEMENT_NOP_W (GSB_VCPU_SPR_WORT),

   /* GUEST_STATE_ELEMENT_HV_REGS_DW(GSB_VCPU_HDEC_LPID, lpid), */
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_LPCR, spr[SPR_LPCR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_AMOR, spr[SPR_AMOR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_HFSCR, spr[SPR_HFSCR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_DAWR0, spr[SPR_DAWR0]),
    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_DAWRX0, spr[SPR_DAWRX0]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_CIABR, spr[SPR_CIABR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_PURR,  spr[SPR_PURR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_SPURR, spr[SPR_SPURR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_IC,    spr[SPR_IC]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_VTB,   spr[SPR_VTB]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_HDAR,  spr[SPR_HDAR]),
    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_HDSISR, spr[SPR_HDSISR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_HEIR,  spr[SPR_HEIR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_ASDR,  spr[SPR_ASDR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_SRR0, spr[SPR_SRR0]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_SRR1, spr[SPR_SRR1]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_SPRG0, spr[SPR_SPRG0]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_SPRG1, spr[SPR_SPRG1]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_SPRG2, spr[SPR_SPRG2]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_SPRG3, spr[SPR_SPRG3]),
    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_PIDR,   spr[SPR_BOOKS_PID]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_CFAR, cfar),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_PPR, spr[SPR_PPR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_DAWR1, spr[SPR_DAWR1]),
    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_DAWRX1, spr[SPR_DAWRX1]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_DEXCR, spr[SPR_DEXCR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_HDEXCR, spr[SPR_HDEXCR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_HASHKEYR,  spr[SPR_HASHKEYR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_HASHPKEYR, spr[SPR_HASHPKEYR]),

    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR0, 16, vsr[0], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR1, 16, vsr[1], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR2, 16, vsr[2], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR3, 16, vsr[3], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR4, 16, vsr[4], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR5, 16, vsr[5], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR6, 16, vsr[6], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR7, 16, vsr[7], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR8, 16, vsr[8], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR9, 16, vsr[9], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR10, 16, vsr[10], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR11, 16, vsr[11], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR12, 16, vsr[12], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR13, 16, vsr[13], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR14, 16, vsr[14], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR15, 16, vsr[15], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR16, 16, vsr[16], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR17, 16, vsr[17], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR18, 16, vsr[18], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR19, 16, vsr[19], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR20, 16, vsr[20], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR21, 16, vsr[21], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR22, 16, vsr[22], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR23, 16, vsr[23], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR24, 16, vsr[24], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR25, 16, vsr[25], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR26, 16, vsr[26], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR27, 16, vsr[27], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR28, 16, vsr[28], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR29, 16, vsr[29], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR30, 16, vsr[30], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR31, 16, vsr[31], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR32, 16, vsr[32], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR33, 16, vsr[33], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR34, 16, vsr[34], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR35, 16, vsr[35], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR36, 16, vsr[36], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR37, 16, vsr[37], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR38, 16, vsr[38], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR39, 16, vsr[39], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR40, 16, vsr[40], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR41, 16, vsr[41], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR42, 16, vsr[42], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR43, 16, vsr[43], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR44, 16, vsr[44], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR45, 16, vsr[45], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR46, 16, vsr[46], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR47, 16, vsr[47], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR48, 16, vsr[48], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR49, 16, vsr[49], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR50, 16, vsr[50], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR51, 16, vsr[51], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR52, 16, vsr[52], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR53, 16, vsr[53], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR54, 16, vsr[54], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR55, 16, vsr[55], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR56, 16, vsr[56], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR57, 16, vsr[57], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR58, 16, vsr[58], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR59, 16, vsr[59], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR60, 16, vsr[60], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR61, 16, vsr[61], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR62, 16, vsr[62], copy_state_16to16),
    GUEST_STATE_ELEMENT_ENV(GSB_VCPU_SPR_VSR63, 16, vsr[63], copy_state_16to16),

    GSBE_NESTED(GSB_PART_SCOPED_PAGETBL, 0x18, parttbl[0],  copy_state_pagetbl),
    GSBE_NESTED(GSB_PROCESS_TBL,         0x10, parttbl[1],  copy_state_proctbl),
    GSBE_NESTED(GSB_VCPU_LPVR,           0x4,  pvr_logical, copy_logical_pvr),
    GSBE_NESTED(GSB_TB_OFFSET,           0x8,  tb_offset,   copy_tb_offset),
    GSBE_NESTED_VCPU(GSB_VCPU_IN_BUFFER, 0x10, runbufin,    copy_state_runbuf),
    GSBE_NESTED_VCPU(GSB_VCPU_OUT_BUFFER,0x10, runbufout,   copy_state_runbuf),
    GSBE_NESTED_VCPU(GSB_VCPU_OUT_BUF_MIN_SZ, 0x8, runbufout, out_buf_min_size),
    GSBE_NESTED_VCPU(GSB_VCPU_DEC_EXPIRE_TB, 0x8, dec_expiry_tb, copy_state_dec_expire_tb),

    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_EBBHR, spr[SPR_EBBHR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_TAR,   spr[SPR_TAR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_EBBRR, spr[SPR_EBBRR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_BESCR, spr[SPR_BESCR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_IAMR , spr[SPR_IAMR ]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_AMR  , spr[SPR_AMR  ]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_UAMOR, spr[SPR_UAMOR]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_DSCR , spr[SPR_DSCR ]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_FSCR , spr[SPR_FSCR ]),
    GUEST_STATE_ELEMENT_ENV_W (GSB_VCPU_SPR_PSPB , spr[SPR_PSPB ]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_CTRL , spr[SPR_CTRL ]),
    GUEST_STATE_ELEMENT_ENV_W (GSB_VCPU_SPR_VRSAVE, spr[SPR_VRSAVE ]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_DAR , spr[SPR_DAR]),
    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_DSISR , spr[SPR_DSISR]),

    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_PMC1, spr[SPR_POWER_PMC1]),
    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_PMC2, spr[SPR_POWER_PMC2]),
    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_PMC3, spr[SPR_POWER_PMC3]),
    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_PMC4, spr[SPR_POWER_PMC4]),
    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_PMC5, spr[SPR_POWER_PMC5]),
    GUEST_STATE_ELEMENT_ENV_W(GSB_VCPU_SPR_PMC6, spr[SPR_POWER_PMC6]),

    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_MMCR0, spr[SPR_POWER_MMCR0]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_MMCR1, spr[SPR_POWER_MMCR1]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_MMCR2, spr[SPR_POWER_MMCR2]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_MMCRA, spr[SPR_POWER_MMCRA]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_SDAR , spr[SPR_POWER_SDAR ]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_SIAR , spr[SPR_POWER_SIAR ]),
    GUEST_STATE_ELEMENT_ENV_DW(GSB_VCPU_SPR_SIER , spr[SPR_POWER_SIER ]),
    GUEST_STATE_ELEMENT_ENV_BASE(GSB_VCPU_HDEC_EXPIRY_TB, 8, copy_state_hdecr),
    GUEST_STATE_ELEMENT_ENV_BASE(GSB_VCPU_SPR_VSCR,  4, copy_state_vscr),
    GUEST_STATE_ELEMENT_ENV_BASE(GSB_VCPU_SPR_FPSCR, 8, copy_state_fpscr)
};

static struct guest_state_element *guest_state_element_next(
    struct guest_state_element *element,
    int64_t *len,
    int64_t *num_elements)
{
    uint16_t size;

    /* size is of element->value[] only. Not whole guest_state_element */
    size = be16_to_cpu(element->size);

    if (len)
        *len -= size + offsetof(struct guest_state_element, value);

    if (num_elements)
        *num_elements -= 1;

    return (struct guest_state_element *)(element->value + size);
}

static void print_element(struct guest_state_element *element,
                          struct guest_state_request *gsr)
{
    printf("id:0x%04x size:0x%04x %s ",
           be16_to_cpu(element->id), be16_to_cpu(element->size),
           gsr->flags & GUEST_STATE_REQUEST_SET ? "set" : "get");
    printf("buf:0x%016lx ...\n", be64_to_cpu(*(uint64_t *)element->value));
}

static struct guest_state_element_type *guest_state_element_type_find(uint16_t id)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(guest_state_element_types); i++)
        if (id == guest_state_element_types[i].id)
            return &guest_state_element_types[i];

    return NULL;
}

static bool guest_state_request_check(struct guest_state_request *gsr)
{
    int64_t num_elements, len = gsr->len;
    struct guest_state_buffer *gsb = gsr->gsb;
    struct guest_state_element *element;
    struct guest_state_element_type *type;
    uint16_t id, size;

    /* gsb->num_elements = 0 == 32 bits long */
    assert(len >= 4);

    num_elements = be32_to_cpu(gsb->num_elements);
    element = gsb->elements;
    len -= sizeof(gsb->num_elements);

    /* Walk the buffer to validate the length */
    while (num_elements) {

        id = be16_to_cpu(element->id);
        size = be16_to_cpu(element->size);

        if (false)
            print_element(element, gsr);
        /* buffer size too small */
        if (len < 0) {
            assert(0);
            return false;
        }

        type = guest_state_element_type_find(id);
        if (!type) {
            printf("%s: Element ID %04x unknown\n", __func__, id);
            print_element(element, gsr);
            assert(0);
            return false;
        }

        if (id == GSB_HV_VCPU_IGNORED_ID) {
            goto next_element;
        }

        if (size != type->size) {
            printf("%s: Size mismatch. Element ID:%04x. Size Wanted:%i Got:%i\n",
                   __func__, id, type->size, size);
            print_element(element, gsr);
            assert(0);
            return false;
        }

        if ((type->flags & GUEST_STATE_ELEMENT_TYPE_FLAG_READ_ONLY) &&
            (gsr->flags & GUEST_STATE_REQUEST_SET)) {
            printf("%s: trying to set a read-only element type. Element ID:%04x.\n",
                   __func__, id);
            assert(0);
            return false;
        }

        if (type->flags & GUEST_STATE_ELEMENT_TYPE_FLAG_GUEST_WIDE) {
            /* guest wide element type */
            if (!(gsr->flags & GUEST_STATE_REQUEST_GUEST_WIDE)) {
                printf("%s: trying to set a guest wide element type. Element ID:%04x.\n",
                       __func__, id);
                assert(0);
                return false;
            }
        } else {
            /* thread wide element type */
            if (gsr->flags & GUEST_STATE_REQUEST_GUEST_WIDE) {
                printf("%s: trying to set a thread wide element type. Element ID:%04x.\n",
                       __func__, id);
                assert(0);
                return false;
            }
        }
next_element:
        element = guest_state_element_next(element, &len, &num_elements);

    }
    return true;
}

static target_ulong getset_state(SpaprMachineStateNestedGuest *guest,
                                 uint64_t vcpuid,
                                 struct guest_state_request *gsr)
{

    void *ptr;
    uint16_t id;
    struct guest_state_element *element;
    struct guest_state_element_type *type;
    int64_t lenleft, num_elements;

    lenleft = gsr->len;

    if (!guest_state_request_check(gsr)) {
        assert(0);
        return H_P3;
    }

    num_elements = be32_to_cpu(gsr->gsb->num_elements);
    element = gsr->gsb->elements;
    /* Process the elements */
    while (num_elements) {
        type = NULL;
        /* Debug print before doing anything */
        if (false)
            print_element(element, gsr);

        id = be16_to_cpu(element->id);
        if (id == GSB_HV_VCPU_IGNORED_ID) {
            goto next_element;
        }

        type = guest_state_element_type_find(id);
        assert(type); /* should have been caught in guest_state_request_check() above */

        /* Get pointer to guest data to get/set */
        if (type->location && type->copy) {
            ptr = type->location(guest, vcpuid);
            assert(ptr);
            type->copy(ptr + type->offset, element->value,
                       gsr->flags & GUEST_STATE_REQUEST_SET? true: false);
        }


next_element:
        element = guest_state_element_next(element, &lenleft, &num_elements);
    }

    return H_SUCCESS;
}

struct run_vcpu_exit_cause {
    uint64_t nia;
    uint64_t count;
    uint16_t ids[10]; /* FIXME make this dynamic */
};

struct run_vcpu_exit_cause run_vcpu_exit_causes[] = {
    { .nia = 0x980,
      .count = 0,
    },
    { .nia = 0xc00,
      .count = 10,
      .ids = {
          GSB_VCPU_GPR3,
          GSB_VCPU_GPR4,
          GSB_VCPU_GPR5,
          GSB_VCPU_GPR6,
          GSB_VCPU_GPR7,
          GSB_VCPU_GPR8,
          GSB_VCPU_GPR9,
          GSB_VCPU_GPR10,
          GSB_VCPU_GPR11,
          GSB_VCPU_GPR12,
      },
    },
    { .nia = 0xe00,
      .count = 5,
      .ids = {
          GSB_VCPU_SPR_HDAR,
          GSB_VCPU_SPR_HDSISR,
          GSB_VCPU_SPR_ASDR,
          GSB_VCPU_SPR_NIA,
          GSB_VCPU_SPR_MSR,
      },
    },
    { .nia = 0xe20,
      .count = 4,
      .ids = {
          GSB_VCPU_SPR_HDAR,
          GSB_VCPU_SPR_ASDR,
          GSB_VCPU_SPR_NIA,
          GSB_VCPU_SPR_MSR,
      },
    },
    { .nia = 0xe40,
      .count = 2, /* 3 */
      .ids = {
          /* GSB_VCPU_SPR_HEIR, */
          GSB_VCPU_SPR_NIA,
          GSB_VCPU_SPR_MSR,
      },
    },
    { .nia = 0xea0,
      .count = 0,
    },
    { .nia = 0xf80,
      .count = 3,
      .ids = {
          GSB_VCPU_SPR_HFSCR,
          GSB_VCPU_SPR_NIA,
          GSB_VCPU_SPR_MSR,
      },
    },
};

static struct run_vcpu_exit_cause *find_exit_cause(uint64_t srr0)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(run_vcpu_exit_causes); i++)
        if (srr0 == run_vcpu_exit_causes[i].nia)
            return &run_vcpu_exit_causes[i];

    printf("%s: srr0:0x%016lx\n", __func__, srr0);
    assert(0);
    return NULL;
}

static void restore_hvstate_from_env(struct kvmppc_hv_guest_state *hvstate,
                                     CPUPPCState *env, int excp)
{
    hvstate->lpcr = env->spr[SPR_LPCR];
    hvstate->hfscr = env->spr[SPR_HFSCR];
    hvstate->cfar = env->cfar;
    hvstate->pcr     = env->spr[SPR_PCR];
    hvstate->dpdes   = env->spr[SPR_DPDES];
    hvstate->srr0    = env->spr[SPR_SRR0];
    hvstate->srr1    = env->spr[SPR_SRR1];
    hvstate->sprg[0] = env->spr[SPR_SPRG0];
    hvstate->sprg[1] = env->spr[SPR_SPRG1];
    hvstate->sprg[2] = env->spr[SPR_SPRG2];
    hvstate->sprg[3] = env->spr[SPR_SPRG3];
    hvstate->pidr    = env->spr[SPR_BOOKS_PID];
    hvstate->ppr     = env->spr[SPR_PPR];

    if (excp == POWERPC_EXCP_HDSI) {
        hvstate->hdar = env->spr[SPR_HDAR];
        hvstate->hdsisr = env->spr[SPR_HDSISR];
        hvstate->asdr = env->spr[SPR_ASDR];
    } else if (excp == POWERPC_EXCP_HISI) {
        hvstate->asdr = env->spr[SPR_ASDR];
    }
}

static int map_and_restore_hvstate(PowerPCCPU *cpu, int excp, target_ulong *r3)
{
    CPUPPCState *env = &cpu->env;
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);
    target_ulong hv_ptr = spapr_cpu->nested_host_state->gpr[4];
    struct kvmppc_hv_guest_state *hvstate;
    hwaddr len = sizeof(*hvstate);

    hvstate = address_space_map(CPU(cpu)->as, hv_ptr, &len, true,
                                MEMTXATTRS_UNSPECIFIED);
    if (len != sizeof(*hvstate)) {
        address_space_unmap(CPU(cpu)->as, hvstate, len, 0, true);
        *r3 = H_PARAMETER;
        return -1;
    }
    restore_hvstate_from_env(hvstate, env, excp);
    /* Is it okay to specify write length larger than actual data written? */
    address_space_unmap(CPU(cpu)->as, hvstate, len, len, true);
    return 0;
}

static void restore_ptregs_from_env(struct kvmppc_pt_regs *regs,
                                    CPUPPCState *env, int excp)
{
    hwaddr len;
    len = sizeof(env->gpr);
    assert(len == sizeof(regs->gpr));
    memcpy(regs->gpr, env->gpr, len);
    if (excp == POWERPC_EXCP_MCHECK ||
        excp == POWERPC_EXCP_RESET ||
        excp == POWERPC_EXCP_SYSCALL) {
        regs->nip = env->spr[SPR_SRR0];
        regs->msr = env->spr[SPR_SRR1] & env->msr_mask;
    } else {
        regs->nip = env->spr[SPR_HSRR0];
        regs->msr = env->spr[SPR_HSRR1] & env->msr_mask;
    }
    regs->link = env->lr;
    regs->ctr  = env->ctr;
    regs->xer  = cpu_read_xer(env);
    regs->ccr  = ppc_get_cr(env);
}

static int map_and_restore_ptregs(PowerPCCPU *cpu, int excp, target_ulong *r3)
{
    CPUPPCState *env = &cpu->env;
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);
    target_ulong regs_ptr = spapr_cpu->nested_host_state->gpr[5];
    hwaddr len;
    struct kvmppc_pt_regs *regs = NULL;

    len = sizeof(*regs);
    regs = address_space_map(CPU(cpu)->as, regs_ptr, &len, true,
                             MEMTXATTRS_UNSPECIFIED);
    if (!regs || len != sizeof(*regs)) {
        address_space_unmap(CPU(cpu)->as, regs, len, 0, true);
        *r3 = H_P2;
        return -1;
    }
    restore_ptregs_from_env(regs, env, excp);
    /* Is it okay to specify write length larger than actual data written? */
    address_space_unmap(CPU(cpu)->as, regs, len, len, true);
    return 0;
}

static void exit_nested_restore_vcpu(PowerPCCPU *cpu, int excp,
                                     SpaprMachineStateNestedGuestVcpu *vcpu)
{
    CPUPPCState *env = &cpu->env;
    target_ulong now, hdar, hdsisr, asdr;

    assert(sizeof(env->gpr) == sizeof(vcpu->env.gpr)); /* sanity check */

    now = cpu_ppc_load_tbl(env); // L2 timebase
    now -= vcpu->tb_offset; // L1 timebase
    vcpu->dec_expiry_tb = now - cpu_ppc_load_decr(env);
    /* backup hdar, hdsisr, asdr if reqd later below */
    hdar   = vcpu->env.spr[SPR_HDAR];
    hdsisr = vcpu->env.spr[SPR_HDSISR];
    asdr   = vcpu->env.spr[SPR_ASDR];

    restore_common_regs(&vcpu->env, env);

    if (excp == POWERPC_EXCP_MCHECK ||
        excp == POWERPC_EXCP_RESET ||
        excp == POWERPC_EXCP_SYSCALL) {
        vcpu->env.nip = env->spr[SPR_SRR0];
        vcpu->env.msr = env->spr[SPR_SRR1] & env->msr_mask;
    } else {
        vcpu->env.nip = env->spr[SPR_HSRR0];
        vcpu->env.msr = env->spr[SPR_HSRR1] & env->msr_mask;
    }

    /* hdar, hdsisr, asdr should be retained unless certain exceptions */
    if ((excp != POWERPC_EXCP_HDSI) && (excp != POWERPC_EXCP_HISI)) {
        vcpu->env.spr[SPR_ASDR] = asdr;
    } else if (excp != POWERPC_EXCP_HDSI) {
        vcpu->env.spr[SPR_HDAR]   = hdar;
        vcpu->env.spr[SPR_HDSISR] = hdsisr;
    }
}

static void exit_process_output_buffer(PowerPCCPU *cpu,
                                      SpaprMachineStateNestedGuest *guest,
                                      target_ulong vcpuid,
                                      target_ulong *r3)
{
    SpaprMachineStateNestedGuestVcpu *vcpu = &guest->vcpu[vcpuid];
    struct guest_state_request gsr;
    struct guest_state_buffer *gsb;
    struct guest_state_element *element;
    struct guest_state_element_type *type;
    struct run_vcpu_exit_cause *exit_cause;
    hwaddr len;
    int i;

    len = vcpu->runbufout.size;
    gsb = address_space_map(CPU(cpu)->as, vcpu->runbufout.addr, &len, true,
                            MEMTXATTRS_UNSPECIFIED);
    if (!gsb || len != vcpu->runbufout.size) {
        assert(0);
        address_space_unmap(CPU(cpu)->as, gsb, len, 0, true);
        *r3 = H_P2;
        return;
    }

    exit_cause = find_exit_cause(*r3);

    /* Create a buffer of elements to send back */
    gsb->num_elements = cpu_to_be32(exit_cause->count);
    element = gsb->elements;
    for (i = 0; i < exit_cause->count; i++) {
        type = guest_state_element_type_find(exit_cause->ids[i]);
        assert(type);
        element->id = cpu_to_be16(exit_cause->ids[i]);
        element->size = cpu_to_be16(type->size);
        element = guest_state_element_next(element, NULL, NULL);
    }
    gsr.gsb = gsb;
    gsr.len = VCPU_OUT_BUF_MIN_SZ;
    gsr.flags = 0; /* get + never guest wide */
    getset_state(guest, vcpuid, &gsr);

    address_space_unmap(CPU(cpu)->as, gsb, len, len, true);
    return;
}

void spapr_exit_nested(PowerPCCPU *cpu, int excp)
{
    SpaprMachineState *spapr = SPAPR_MACHINE(qdev_get_machine());
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;
    SpaprCpuState *spapr_cpu = spapr_cpu_state(cpu);
    target_ulong r3_return = env->excp_vectors[excp]; /* hcall return value */
    target_ulong lpid = 0, vcpuid = 0;
    struct SpaprMachineStateNestedGuestVcpu *vcpu;
    struct SpaprMachineStateNestedGuest *guest = NULL;
    uint32_t tmp_pending_interrupts;

    assert(spapr_cpu->in_nested);

    cpu_ppc_hdecr_exit(env);

    /* TODO: change vhc->deliver_hv_excp rather than do this */
    if (spapr->nested.api == NESTED_API_KVM_HV) {
        if (map_and_restore_hvstate(cpu, excp, &r3_return) ||
            map_and_restore_ptregs (cpu, excp, &r3_return)) {
            goto out_restore_l1;
        }
    } else if (spapr->nested.api == NESTED_API_PAPR) {
        lpid = spapr_cpu->nested_host_state->gpr[5];
        vcpuid = spapr_cpu->nested_host_state->gpr[6];
        guest = spapr_get_nested_guest(spapr, lpid);
        assert(guest);
        vcpu_check(guest, vcpuid, false);
        vcpu = &guest->vcpu[vcpuid];

        exit_nested_restore_vcpu(cpu, excp, vcpu);

        /* do the output buffer for run_vcpu*/
        exit_process_output_buffer(cpu, guest, vcpuid, &r3_return);
    } else
        assert(0);


    out_restore_l1:
    assert(env->spr[SPR_LPIDR] != 0);

    /* Save external and hypervisor virtualization interrupts */
    tmp_pending_interrupts = env->pending_interrupts &
                     (PPC_INTERRUPT_EXT | PPC_INTERRUPT_HVIRT);

    /* copy all the env state */
    if (spapr->nested.api == NESTED_API_KVM_HV) {
        memcpy(env->gpr, spapr_cpu->nested_host_state->gpr, sizeof(env->gpr));
        env->lr = spapr_cpu->nested_host_state->lr;
        env->ctr = spapr_cpu->nested_host_state->ctr;
        memcpy(env->crf, spapr_cpu->nested_host_state->crf, sizeof(env->crf));
        env->cfar = spapr_cpu->nested_host_state->cfar;
        env->xer = spapr_cpu->nested_host_state->xer;
        env->so = spapr_cpu->nested_host_state->so;
        env->ov = spapr_cpu->nested_host_state->ov;
        env->ov32 = spapr_cpu->nested_host_state->ov32;
        env->ca32 = spapr_cpu->nested_host_state->ca32;
        env->msr = spapr_cpu->nested_host_state->msr;
        env->nip = spapr_cpu->nested_host_state->nip;

        assert(env->spr[SPR_LPIDR] != 0);
        env->spr[SPR_LPCR] = spapr_cpu->nested_host_state->spr[SPR_LPCR];
        env->spr[SPR_LPIDR] = spapr_cpu->nested_host_state->spr[SPR_LPIDR];
        env->spr[SPR_PCR] = spapr_cpu->nested_host_state->spr[SPR_PCR];
        env->spr[SPR_DPDES] = 0;
        env->spr[SPR_HFSCR] = spapr_cpu->nested_host_state->spr[SPR_HFSCR];
        env->spr[SPR_SRR0] = spapr_cpu->nested_host_state->spr[SPR_SRR0];
        env->spr[SPR_SRR1] = spapr_cpu->nested_host_state->spr[SPR_SRR1];
        env->spr[SPR_SPRG0] = spapr_cpu->nested_host_state->spr[SPR_SPRG0];
        env->spr[SPR_SPRG1] = spapr_cpu->nested_host_state->spr[SPR_SPRG1];
        env->spr[SPR_SPRG2] = spapr_cpu->nested_host_state->spr[SPR_SPRG2];
        env->spr[SPR_SPRG3] = spapr_cpu->nested_host_state->spr[SPR_SPRG3];
        env->spr[SPR_BOOKS_PID] = spapr_cpu->nested_host_state->spr[SPR_BOOKS_PID];
        env->spr[SPR_PPR] = spapr_cpu->nested_host_state->spr[SPR_PPR];
    } else {

        /* API v2 */
        restore_common_regs(env, spapr_cpu->nested_host_state);
    }

    /*
     * OR the external and hypervisor virtualization interrupts
     * in the cpu env. This will result in L1 calling its do_IRQ
     * generic interrupt handling routine. This is important for
     * responsiveness in L1 and consequently also L2.
     */
    env->pending_interrupts |= tmp_pending_interrupts;

    if (spapr->nested.api == NESTED_API_PAPR) {
        env->gpr[3] = H_SUCCESS;
        env->gpr[4] = r3_return;
    } else {
        /*
         * Return the interrupt vector address from H_ENTER_NESTED to the L1
         * (or error code).
         */
        env->gpr[3] = r3_return;
    }

    env->tb_env->tb_offset -= spapr_cpu->nested_tb_offset;
    spapr_cpu->in_nested = false;

    hreg_compute_hflags(env);
    ppc_maybe_interrupt(env);
    tlb_flush(cs);
    env->reserve_addr = -1; /* Reset the reservation */

    g_free(spapr_cpu->nested_host_state);
    spapr_cpu->nested_host_state = NULL;
}

static void init_nested(void)
{
    struct guest_state_element_type *type;
    int i;

    /* Fill in the table. Could do this statically, but easier here */
    for (i = 0; i < ARRAY_SIZE(guest_state_element_types); i++) {
        type = &guest_state_element_types[i];

        if (type->id > GSB_LAST)
            assert(0);
        else if (type->id >= GSB_VCPU_SPR_HDAR)
            /* 0xf000 - 0xf005 Thread + RO */
            type->flags = GUEST_STATE_ELEMENT_TYPE_FLAG_READ_ONLY;
        else if (type->id >= GSB_VCPU_IN_BUFFER)
            /* 0x0c00 - 0xf000 Thread + RW */
            type->flags = 0;
        else if (type->id >= GSB_VCPU_LPVR)
            /* 0x0003 - 0x0bff Guest + RW */
            type->flags = GUEST_STATE_ELEMENT_TYPE_FLAG_GUEST_WIDE;
        else if (type->id >= GSB_HV_VCPU_STATE_SIZE)
            /* 0x0001 - 0x0002 Guest + RO */
            type->flags = GUEST_STATE_ELEMENT_TYPE_FLAG_READ_ONLY |
                          GUEST_STATE_ELEMENT_TYPE_FLAG_GUEST_WIDE;
    }
}

#define H_GUEST_CAPABILITIES_COPY_MEM 0x8000000000000000
#define H_GUEST_CAPABILITIES_P9_MODE  0x4000000000000000
#define H_GUEST_CAPABILITIES_P10_MODE 0x2000000000000000

static target_ulong h_guest_get_capabilities(PowerPCCPU *cpu,
                                             SpaprMachineState *spapr,
                                             target_ulong opcode,
                                             target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    target_ulong flags = args[0];

    if (!tcg_enabled())
        return H_FUNCTION;

    if (flags) { /* don't handle any flags capabilities for now */
        assert(0);
        return H_UNSUPPORTED_FLAG;
    }

    if ((env->spr[SPR_PVR] & CPU_POWERPC_POWER_SERVER_MASK) ==
        (CPU_POWERPC_POWER9_BASE))
        env->gpr[4] = H_GUEST_CAPABILITIES_P9_MODE;

    if ((env->spr[SPR_PVR] & CPU_POWERPC_POWER_SERVER_MASK) ==
        (CPU_POWERPC_POWER10_BASE))
        env->gpr[4] = H_GUEST_CAPABILITIES_P10_MODE;

    return H_SUCCESS;
}

static target_ulong h_guest_set_capabilities(PowerPCCPU *cpu,
                                             SpaprMachineState *spapr,
                                             target_ulong opcode,
                                              target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    target_ulong flags = args[0];
    target_ulong capabilities = args[1];

    if (!tcg_enabled())
        return H_FUNCTION;

    if (flags) { /* don't handle any flags capabilities for now */
        assert(0);
        return H_UNSUPPORTED_FLAG;
    }


    /* isn't supported */
    if (capabilities & H_GUEST_CAPABILITIES_COPY_MEM) {
        env->gpr[4] = 0;
        assert(0);
        return H_P2;
    }

    if ((env->spr[SPR_PVR] & CPU_POWERPC_POWER_SERVER_MASK) ==
        (CPU_POWERPC_POWER9_BASE)) {
        /* We are a P9 */
        if (!(capabilities & H_GUEST_CAPABILITIES_P9_MODE)) {
            env->gpr[4] = 1;
            assert(0);
            return H_P2;
        }
    }

    if ((env->spr[SPR_PVR] & CPU_POWERPC_POWER_SERVER_MASK) ==
        (CPU_POWERPC_POWER10_BASE)) {
        /* We are a P10 */
        if (!(capabilities & H_GUEST_CAPABILITIES_P10_MODE)) {
            env->gpr[4] = 2;
            assert(0);
            return H_P2;
        }
    }

    spapr->nested.capabilities_set = true;

    spapr->nested.pvr_base = env->spr[SPR_PVR];

    return H_SUCCESS;
}

static void
destroy_guest_helper(gpointer value)
{
    struct SpaprMachineStateNestedGuest *guest = value;
    int i = 0;
    for (i=0; i < guest->vcpus; i++) {
        cpu_ppc_tb_free(&guest->vcpu[i].env);
    }
    g_free(guest->vcpu);
    g_free(guest);
}

static target_ulong h_guest_create(PowerPCCPU *cpu,
                                   SpaprMachineState *spapr,
                                   target_ulong opcode,
                                   target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    target_ulong flags = args[0];
    target_ulong continue_token = args[1];
    uint64_t lpid;
    int nguests = 0;
    struct SpaprMachineStateNestedGuest *guest;

    if (!tcg_enabled())
        return H_FUNCTION;

    if (flags) /* don't handle any flags for now */
        return H_UNSUPPORTED_FLAG;

    if (continue_token != -1)
        return H_P2;

    if (!spapr_get_cap(spapr, SPAPR_CAP_NESTED_PAPR)) {
        return H_FUNCTION;
    }

    if (!spapr->nested.capabilities_set) {
        assert(0);
        return H_STATE;
    }

    if (!spapr->nested.guests) {
        spapr->nested.lpid_max = NESTED_GUEST_MAX;
        spapr->nested.guests = g_hash_table_new_full(NULL,
                                                     NULL,
                                                     NULL,
                                                     destroy_guest_helper);
    }

    nguests = g_hash_table_size(spapr->nested.guests);

    if (nguests == spapr->nested.lpid_max)
        return H_NO_MEM;

    /* Allocate lpids linearly. FIXME: make faster */
    for (lpid = 1; lpid < spapr->nested.lpid_max; lpid++)
        if (!(g_hash_table_lookup(spapr->nested.guests, GINT_TO_POINTER(lpid))))
            break;
    if (lpid == spapr->nested.lpid_max)
        return H_NO_MEM;

    guest = g_try_new0(struct SpaprMachineStateNestedGuest, 1);
    if (!guest)
        return H_NO_MEM;

    guest->pvr_logical = spapr->nested.pvr_base;

    g_hash_table_insert(spapr->nested.guests, GINT_TO_POINTER(lpid), guest);
    printf("%s: lpid: %lu (MAX: %i)\n", __func__, lpid, spapr->nested.lpid_max);

    env->gpr[4] = lpid;
    return H_SUCCESS;
}

static target_ulong h_guest_delete(PowerPCCPU *cpu,
                                   SpaprMachineState *spapr,
                                   target_ulong opcode,
                                   target_ulong *args)
{
    target_ulong flags = args[0];
    target_ulong lpid = args[1];
    struct SpaprMachineStateNestedGuest *guest;

    if (!tcg_enabled())
        return H_FUNCTION;

    /* handle flag deleteAllGuests, remaining bits reserved */
    if (flags & ~H_GUEST_DELETE_ALL_MASK) {
        return H_UNSUPPORTED_FLAG;
    } else if (flags & H_GUEST_DELETE_ALL_MASK) {
        g_hash_table_destroy(spapr->nested.guests);
        return H_SUCCESS;
    }

    /* FIXME: check to see if any vcpus are running */

    if (!spapr_get_cap(spapr, SPAPR_CAP_NESTED_PAPR))
        return H_FUNCTION;

    guest = g_hash_table_lookup(spapr->nested.guests, GINT_TO_POINTER(lpid));
    if (!guest)
        return H_P2;

    g_hash_table_remove(spapr->nested.guests, GINT_TO_POINTER(lpid));

    return H_SUCCESS;
}

static target_ulong h_guest_create_vcpu(PowerPCCPU *cpu,
                                        SpaprMachineState *spapr,
                                        target_ulong opcode,
                                        target_ulong *args)
{
    CPUPPCState *env = &cpu->env, *l2env;
    target_ulong flags = args[0];
    target_ulong lpid = args[1];
    target_ulong vcpuid = args[2];
    SpaprMachineStateNestedGuest *guest;

    if (!tcg_enabled())
        return H_FUNCTION;

    if (flags) /* don't handle any flags for now */
        return H_UNSUPPORTED_FLAG;

    guest = spapr_get_nested_guest(spapr, lpid);
    if (!guest)
        return H_PARAMETER;

    if (guest->vcpus == NESTED_GUEST_VCPU_MAX)
        return H_P3;

    if (guest->vcpus) {
        struct SpaprMachineStateNestedGuestVcpu *vcpus;
        vcpus = g_try_renew(struct SpaprMachineStateNestedGuestVcpu, guest->vcpu,
                            guest->vcpus + 1);
        if (!vcpus)
            return H_NO_MEM;
        memset(&vcpus[guest->vcpus], 0, sizeof(struct SpaprMachineStateNestedGuestVcpu));
        guest->vcpu = vcpus;
        l2env = &vcpus[guest->vcpus].env;
    } else {
        guest->vcpu = g_try_new0(struct SpaprMachineStateNestedGuestVcpu, 1);
        if (guest->vcpu == NULL)
            return H_NO_MEM;
        l2env = &guest->vcpu->env;
    }
    /* need to memset to zero otherwise we leak L1 state to L2 */
    memset(l2env, 0, sizeof(CPUPPCState));
    /* Copy L1 PVR to L2 */
    l2env->spr[SPR_PVR] = env->spr[SPR_PVR];
    cpu_ppc_tb_init(l2env, SPAPR_TIMEBASE_FREQ);

    guest->vcpus++;
    assert(vcpuid < guest->vcpus);
    guest->vcpu[vcpuid].enabled = true;

    /* double check we didn't screw up */
    if (!vcpu_check(guest, vcpuid, false))
        return H_PARAMETER;

    return H_SUCCESS;
}

static target_ulong map_and_getset_state(PowerPCCPU *cpu,
                                         SpaprMachineStateNestedGuest *guest,
                                         uint64_t vcpuid,
                                         struct guest_state_request *gsr)
{
    target_ulong rc;
    int64_t lenleft, len;

    assert(gsr->len < (1024*1024)); /* sanity check */

    lenleft = len = gsr->len;
    gsr->gsb = address_space_map(CPU(cpu)->as, gsr->buf, (uint64_t *)&len,
                                 false, MEMTXATTRS_UNSPECIFIED);
    if (!gsr->gsb) {
        assert(0);
        rc = H_P3;
        goto out1;
    }

    if (len != lenleft) {
        assert(0);
        rc = H_P3;
        goto out1;
    }

    getset_state(guest, vcpuid, gsr);

    address_space_unmap(CPU(cpu)->as, gsr->gsb, len, len, false);
    return H_SUCCESS;

out1:
    address_space_unmap(CPU(cpu)->as, gsr->gsb, len, 0, false);
    return rc;
}

#define H_GUEST_GETSET_STATE_FLAG_GUEST_WIDE 0x8000000000000000

static target_ulong h_guest_getset_state(PowerPCCPU *cpu,
                                         SpaprMachineState *spapr,
                                         target_ulong *args,
                                         bool set)
{
    target_ulong flags = args[0];
    target_ulong lpid = args[1];
    target_ulong vcpuid = args[2];
    target_ulong buf = args[3];
    target_ulong buflen = args[4];
    struct guest_state_request gsr;
    SpaprMachineStateNestedGuest *guest;

    if (!tcg_enabled())
        return H_FUNCTION;

    guest = spapr_get_nested_guest(spapr, lpid);
    if (!guest){
        assert(0);
        return H_NOT_AVAILABLE;
    }
    gsr.buf = buf;
    gsr.len = buflen;
    gsr.flags = 0;
    if (flags & H_GUEST_GETSET_STATE_FLAG_GUEST_WIDE)
        gsr.flags |= GUEST_STATE_REQUEST_GUEST_WIDE;
    if (flags & !H_GUEST_GETSET_STATE_FLAG_GUEST_WIDE)
        assert(0);

    if (set)
        gsr.flags |= GUEST_STATE_REQUEST_SET;
    return map_and_getset_state(cpu, guest, vcpuid, &gsr);
}

static target_ulong h_guest_set_state(PowerPCCPU *cpu,
                                      SpaprMachineState *spapr,
                                      target_ulong opcode,
                                      target_ulong *args)
{
    return h_guest_getset_state(cpu, spapr, args, true);
}

static target_ulong h_guest_get_state(PowerPCCPU *cpu,
                                      SpaprMachineState *spapr,
                                      target_ulong opcode,
                                      target_ulong *args)
{
    return h_guest_getset_state(cpu, spapr, args, false);
}

static target_ulong h_guest_run_vcpu(PowerPCCPU *cpu,
                                     SpaprMachineState *spapr,
                                     target_ulong opcode,
                                     target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    target_ulong flags = args[0];
    target_ulong lpid = args[1];
    target_ulong vcpuid = args[2];
    struct SpaprMachineStateNestedGuestVcpu *vcpu;
    struct guest_state_request gsr;
    SpaprMachineStateNestedGuest *guest;

    if (!tcg_enabled())
        return H_FUNCTION;

    if (flags) /* don't handle any flags for now */
        return H_UNSUPPORTED_FLAG;

    guest = spapr_get_nested_guest(spapr, lpid);
    if (!guest)
        return H_NOT_AVAILABLE;
    if (!vcpu_check(guest, vcpuid, true))
        return H_NOT_AVAILABLE;

    if (guest->parttbl[0] == 0) {
        /* At least need a partition scoped radix tree */
        assert(0);
        return H_NOT_AVAILABLE;
    }

    vcpu = &guest->vcpu[vcpuid];

    /* Read run_vcpu input buffer to update state */
    gsr.buf = vcpu->runbufin.addr;
    gsr.len = vcpu->runbufin.size;
    gsr.flags = GUEST_STATE_REQUEST_SET; /* Thread wide + writing */
    map_and_getset_state(cpu, guest, vcpuid, &gsr);

    enter_nested(cpu, lpid, NULL, NULL, vcpu);

    return env->gpr[3];
}

static void hypercall_register_nested(void)
{
    spapr_register_hypercall(KVMPPC_H_SET_PARTITION_TABLE, h_set_ptbl);
    spapr_register_hypercall(KVMPPC_H_ENTER_NESTED,        h_enter_nested);
    spapr_register_hypercall(KVMPPC_H_TLB_INVALIDATE,      h_tlb_invalidate);
    spapr_register_hypercall(KVMPPC_H_COPY_TOFROM_GUEST,   h_copy_tofrom_guest);
}

void hypercall_register_nested_phyp(void)
{
    spapr_register_hypercall(H_GUEST_GET_CAPABILITIES, h_guest_get_capabilities);
    spapr_register_hypercall(H_GUEST_SET_CAPABILITIES, h_guest_set_capabilities);
    spapr_register_hypercall(H_GUEST_CREATE          , h_guest_create);
    spapr_register_hypercall(H_GUEST_CREATE_VCPU     , h_guest_create_vcpu);
    spapr_register_hypercall(H_GUEST_SET_STATE       , h_guest_set_state);
    spapr_register_hypercall(H_GUEST_GET_STATE       , h_guest_get_state);
    spapr_register_hypercall(H_GUEST_RUN_VCPU        , h_guest_run_vcpu);
    spapr_register_hypercall(H_GUEST_DELETE          , h_guest_delete);
}

static void hypercall_register_softmmu(void)
{
    /* DO NOTHING */
}
#else
void spapr_exit_nested(PowerPCCPU *cpu, int excp)
{
    g_assert_not_reached();
}

static target_ulong h_softmmu(PowerPCCPU *cpu, SpaprMachineState *spapr,
                            target_ulong opcode, target_ulong *args)
{
    g_assert_not_reached();
}

static void hypercall_register_nested(void)
{
    /* DO NOTHING */
}

void hypercall_register_nested_phyp(void)
{
    /* DO NOTHING */
}

static void hypercall_register_softmmu(void)
{
    /* hcall-pft */
    spapr_register_hypercall(H_ENTER, h_softmmu);
    spapr_register_hypercall(H_REMOVE, h_softmmu);
    spapr_register_hypercall(H_PROTECT, h_softmmu);
    spapr_register_hypercall(H_READ, h_softmmu);

    /* hcall-bulk */
    spapr_register_hypercall(H_BULK_REMOVE, h_softmmu);
}

static void init_nested(void)
{
    /* DO NOTHING */
}
#endif

static void hypercall_register_types(void)
{
    hypercall_register_softmmu();

    /* hcall-hpt-resize */
    spapr_register_hypercall(H_RESIZE_HPT_PREPARE, h_resize_hpt_prepare);
    spapr_register_hypercall(H_RESIZE_HPT_COMMIT, h_resize_hpt_commit);

    /* hcall-splpar */
    spapr_register_hypercall(H_REGISTER_VPA, h_register_vpa);
    spapr_register_hypercall(H_CEDE, h_cede);
    spapr_register_hypercall(H_CONFER, h_confer);
    spapr_register_hypercall(H_PROD, h_prod);

    /* hcall-join */
    spapr_register_hypercall(H_JOIN, h_join);

    spapr_register_hypercall(H_SIGNAL_SYS_RESET, h_signal_sys_reset);

    /* processor register resource access h-calls */
    spapr_register_hypercall(H_SET_SPRG0, h_set_sprg0);
    spapr_register_hypercall(H_SET_DABR, h_set_dabr);
    spapr_register_hypercall(H_SET_XDABR, h_set_xdabr);
    spapr_register_hypercall(H_PAGE_INIT, h_page_init);
    spapr_register_hypercall(H_SET_MODE, h_set_mode);

    /* In Memory Table MMU h-calls */
    spapr_register_hypercall(H_CLEAN_SLB, h_clean_slb);
    spapr_register_hypercall(H_INVALIDATE_PID, h_invalidate_pid);
    spapr_register_hypercall(H_REGISTER_PROC_TBL, h_register_process_table);

    /* hcall-get-cpu-characteristics */
    spapr_register_hypercall(H_GET_CPU_CHARACTERISTICS,
                             h_get_cpu_characteristics);

    /* "debugger" hcalls (also used by SLOF). Note: We do -not- differenciate
     * here between the "CI" and the "CACHE" variants, they will use whatever
     * mapping attributes qemu is using. When using KVM, the kernel will
     * enforce the attributes more strongly
     */
    spapr_register_hypercall(H_LOGICAL_CI_LOAD, h_logical_load);
    spapr_register_hypercall(H_LOGICAL_CI_STORE, h_logical_store);
    spapr_register_hypercall(H_LOGICAL_CACHE_LOAD, h_logical_load);
    spapr_register_hypercall(H_LOGICAL_CACHE_STORE, h_logical_store);
    spapr_register_hypercall(H_LOGICAL_ICBI, h_logical_icbi);
    spapr_register_hypercall(H_LOGICAL_DCBF, h_logical_dcbf);
    spapr_register_hypercall(KVMPPC_H_LOGICAL_MEMOP, h_logical_memop);

    /* qemu/KVM-PPC specific hcalls */
    spapr_register_hypercall(KVMPPC_H_RTAS, h_rtas);

    /* ibm,client-architecture-support support */
    spapr_register_hypercall(KVMPPC_H_CAS, h_client_architecture_support);

    spapr_register_hypercall(KVMPPC_H_UPDATE_DT, h_update_dt);

    hypercall_register_nested();

    init_nested();
}

type_init(hypercall_register_types)
