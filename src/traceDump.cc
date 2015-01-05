#include "trace.container.hpp"

#include <udis86.h>

void print_operand (const operand_info & op_info, bool pre) {
    if (pre)
        printf("  pre  [");
    else
        printf("  post [");

    if (op_info.operand_usage().read())
        printf("r");
    else
        printf(" ");

    if (op_info.operand_usage().written())
        printf("w");
    else
        printf(" ");

    if (op_info.operand_usage().index())
        printf("i");
    else
        printf(" ");

    if (op_info.operand_usage().base())
        printf("b");
    else
        printf(" ");

    printf("]  %02d  ", op_info.bit_length());

    if (op_info.operand_info_specific().has_mem_operand()) {
        const mem_operand & mem_op = op_info.operand_info_specific().mem_operand();
        printf("mem=%08llx  ", mem_op.address());
    }
    else if (op_info.operand_info_specific().has_reg_operand()) {
        const reg_operand & reg_op = op_info.operand_info_specific().reg_operand();
        printf("reg=%-08s  ", reg_op.name().c_str());
    }

    if (op_info.taint_info().has_taint_id())
        printf("taint=%08x  ", op_info.taint_info().taint_id());
    else if (    (op_info.taint_info().has_taint_multiple())
              && (op_info.taint_info().taint_multiple()))
        printf("taint=multiple  ");
    else
        printf("taint=none      ");


    printf("\n");
}

int main (int argc, char * argv[]) {
    SerializedTrace::TraceContainerReader t(argv[1]);

    uint64_t std_frames         = 0;
    uint64_t syscall_frames     = 0;
    uint64_t taint_intro_frames = 0;
    uint64_t modload_frames     = 0;
    uint64_t key_frames         = 0;

    while (! t.end_of_trace()) {
        const std::auto_ptr<frame> & f = t.get_frame();

        unsigned int frames = 0;
        if (f->has_std_frame())
            frames++;
        if (f->has_syscall_frame())
            frames++;
        if (f->has_exception_frame())
            frames++;
        if (f->has_taint_intro_frame())
            frames++;
        if (f->has_modload_frame())
            frames++;
        if (f->has_key_frame())
            frames++;

        if (frames != 1) {
            fprintf(stderr, "frames != 1, frames is %d\n", frames);
            return -1;
        }

        if (f->has_std_frame()) {
            std_frames++;

            const std_frame & std_f = f->std_frame();

            ud_t ud_obj;

            ud_init(&ud_obj);
            ud_set_input_buffer(&ud_obj,
                                (const uint8_t *) std_f.rawbytes().c_str(),
                                std_f.rawbytes().size());
            ud_set_syntax(&ud_obj, UD_SYN_INTEL);
            ud_set_mode(&ud_obj, 32);

            if (ud_disassemble(&ud_obj)) {
                printf("std_frame [%08llx] %s\n",
                       std_f.address(),
                       ud_insn_asm(&ud_obj));
            }
            else {
                fprintf(stderr, "std_frame [%08llx] could not disassemble\n");
                return -1;
            }

            const operand_value_list & pre_list = std_f.operand_pre_list();
            for (int i = 0; i < pre_list.elem_size(); i++) {
                const operand_info & op_info = pre_list.elem(i);
                print_operand(op_info, true);
            }

            const operand_value_list & post_list = std_f.operand_post_list();
            for (int i = 0; i < pre_list.elem_size(); i++) {
                const operand_info & op_info = pre_list.elem(i);
                print_operand(op_info, false);
            }
        }

        else if (f->has_syscall_frame()) {
            syscall_frames++;

            const syscall_frame & syscall_f = f->syscall_frame();
            printf("syscall [%08llx] 0x%llx\n",
                   syscall_f.address(),
                   syscall_f.number());
        }

        else if (f->has_taint_intro_frame()) {
            taint_intro_frames++;

            const taint_intro_frame & taint_intro_f = f->taint_intro_frame();

            const taint_intro_list & taint_intro_list = taint_intro_f.taint_intro_list();

            for (int i = 0; i < taint_intro_list.elem_size(); i++) {
                const taint_intro & taint_i = taint_intro_list.elem(i);

                printf("taint_intro [%08llx]  id=%llx, size=%d, offset=%llx, %s\n",
                       taint_i.addr(),
                       taint_i.taint_id(),
                       taint_i.value().size(),
                       taint_i.offset(),
                       taint_i.source_name().c_str());
            }
        }

        else if (f->has_modload_frame()) {
            modload_frames++;

            const modload_frame & modload_f = f->modload_frame();

            printf("modload [%08llx .. %08llx] %s\n",
                   modload_f.low_address(),
                   modload_f.high_address(),
                   modload_f.module_name().c_str());
        }

        else if (f->has_key_frame()) {
            key_frames++;
        }

    }

    printf("        std_frames: %lld\n", std_frames);
    printf("    syscall_frames: %lld\n", syscall_frames);
    printf("taint_intro_frames: %lld\n", taint_intro_frames);
    printf("    modload_frames: %lld\n", modload_frames);
    printf("        key_frames: %lld\n", key_frames);

    return 0;
}