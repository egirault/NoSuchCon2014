#!/usr/bin/python2

from miasm2.analysis.machine import Machine
from miasm2.analysis import binary
from miasm2.expression.expression import *
from miasm2.ir.symbexec import symbexec
from miasm2.expression.simplifications import expr_simp

# Open file and setup the machine
bi = binary.Container("crackmips")
machine = Machine('mips32l')
mn, dis_engine_cls, ira_cls = machine.mn, machine.dis_engine, machine.ira

# Prepare symbolic execution
symbols_init = {}
for i, r in enumerate(mn.regs.all_regs_ids):
    symbols_init[r] = mn.regs.all_regs_ids_init[i]


fp_init = ExprId('FP_init', 32)
zero_init = ExprId('ZERO_init', 32)
e_i_pattern = expr_simp(ExprMem(fp_init + ExprInt32(0x38), 32))
e_i = ExprId('i', 32)
e_pass_i_pattern = expr_simp(ExprMem(fp_init + (e_i << ExprInt32(2)) + ExprInt32(0x20), 32))
e_pass_i = ExprId("pwd[i]", 32)

simplifications = {e_i_pattern          : e_i,
                   e_pass_i_pattern     : e_pass_i,
                   zero_init            : ExprInt32(0) }

def my_simplify(expr):
    expr2 = expr.replace_expr(simplifications)
    return expr2

def exprs2str(exprs):
    return ' = '.join(str(e) for e in exprs)

def analyse_bb(begin, end):

    # Disassemble
    dis_engine = dis_engine_cls(bs=bi.bs)
    dis_engine.dont_dis = [end]
    bloc = dis_engine.dis_bloc(begin)
    
    # Transform to IR
    ira = ira_cls()
    irabloc = ira.add_bloc(bloc)[0]

    # Perform symbolic exec
    sb = symbexec(ira, symbols_init)
    sb.emulbloc(irabloc)

    # Find out what has been modified during symbolic execution
    # only 1 iteration here
    assert len(sb.symbols.symbols_mem) == 1
    expr_res = []
    for mem, vals in sb.symbols.symbols_mem.iteritems(): 
        exprs = [my_simplify(e) for e in vals]
        expr_res.append(exprs)

    assert len(expr_res) == 1

    return expr_res[0]

def load_trace(filename):
    return [int(x.strip(), 16) for x in open(filename).readlines()]

def boundaries_from_trace(trace):
    bb_starts = sorted(set(trace))
    boundaries = [(bb_starts[i], bb_starts[i+1]-4) for i in range(len(bb_starts)-1)]
    boundaries.append((0x4039DC, 0x04039E8)) # last basic bloc, added by hand
    return boundaries

trace = load_trace("gdb_trace.txt")
boundaries = boundaries_from_trace(trace)

print "# Building IR blocs & expressions for all basic blocks"
bb_exprs = []
for zone in boundaries:
    bb_exprs.append(analyse_bb(*zone))

print "# Reconstructing the whole algorithm based on GDB trace"
bb_starts = [x[0] for x in boundaries]
for bb_ea in trace:
    bb_index = bb_starts.index(bb_ea)
    #print "%x : %s" % (bb_ea, exprs2str(bb_exprs[bb_index]))
    print exprs2str(bb_exprs[bb_index])
    
