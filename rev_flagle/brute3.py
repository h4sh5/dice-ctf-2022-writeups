#!/usr/bin/env python3
import angr #the main framework
import claripy #the solver engine

proj = angr.Project("index3")

main = 0x80491d6

'''
BVS(name, size, min=None, max=None, stride=None, uninitialized=False, explicit_name=None, discrete_set=False, discrete_set_max_card=None, **kwargs)
'''
# 8 bit because its a char
flag_len = 5
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(flag_len)] 

# a new line at the end
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

# lighter state , with flag as init. above
state = proj.factory.blank_state(addr=main, stdin=flag)


# Constrain all bytes to be non-null and non-newline:
for k in flag_chars:
    state.solver.add(k != 0)
    state.solver.add(k != 10)
    state.solver.add(k > 31) # ascii range


# try until SUCCESS is printed
target = lambda s: b"OK" in s.posix.dumps(1) 

# not much to avoid
avoid = [0x080492e7]

# specify state in the manager
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=target,avoid=avoid)

found = simgr.found[0]

print("found! :", found)

print(found.posix.dumps(0))