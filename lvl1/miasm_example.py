#!/usr/bin/python2
from miasm2.analysis.machine import Machine
from miasm2.analysis import binary

bi = binary.Container("crackmips")
machine = Machine('mips32l')
mn, dis_engine_cls, ira_cls = machine.mn, machine.dis_engine, machine.ira

BB_BEGIN = 0x00402290
BB_END = 0x004022BC

# Disassemble
dis_engine = dis_engine_cls(bs=bi.bs)
dis_engine.dont_dis = [BB_END]
bloc = dis_engine.dis_bloc(BB_BEGIN)
print '\n'.join(map(str, bloc.lines))

# Transform to IR
ira = ira_cls()
irabloc = ira.add_bloc(bloc)[0]
print '\n'.join(map(lambda b: str(b[0]), irabloc.irs))


from miasm2.expression.expression import *
from miasm2.ir.symbexec import symbexec
from miasm2.expression.simplifications import expr_simp

# Prepare symbolic execution
symbols_init = {}
for i, r in enumerate(mn.regs.all_regs_ids):
    symbols_init[r] = mn.regs.all_regs_ids_init[i]

# Perform symbolic exec
sb = symbexec(ira, symbols_init)
sb.emulbloc(irabloc)

mem, exprs = sb.symbols.symbols_mem.items()[0]
print "Memory changed at %s :" % mem
print "  before:", exprs[0]
print "  after:", exprs[1]

# Simplifications
fp_init = ExprId('FP_init', 32)
zero_init = ExprId('ZERO_init', 32)
e_i_pattern = expr_simp(ExprMem(fp_init + ExprInt32(0x38), 32))
e_i = ExprId('i', 32)
e_pass_i_pattern = expr_simp(ExprMem(fp_init + (e_i << ExprInt32(2)) + ExprInt32(0x20), 32))
e_pass_i = ExprId("pwd[i]", 32)

simplifications = {e_i_pattern      : e_i,
                   e_pass_i_pattern : e_pass_i,
                   zero_init        : ExprInt32(0) }

def my_simplify(expr):
    expr2 = expr.replace_expr(simplifications)
    return expr2

print "%s = %s" % (my_simplify(exprs[0]) ,my_simplify(exprs[1]))
