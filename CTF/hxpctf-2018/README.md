# angrme [Rev 50 points]

### Chall's description
```
Difficulty: easy
I hope you do not need more than [three lines of python](https://angr.io) to solve this.

```

#### File given for the chall
* [angrme](./angrme)

## Solution

```
$ file angrme
angrme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

first download this:
	$ mkvirtualenv angr
	$ pip install angr

otherwise run in docker.


then read this:
https://docs.angr.io/core-concepts/toplevel

after read this cheat sheet:
https://github.com/angr/angr-doc/blob/master/CHEATSHEET.md

this is what we want:

	1) execute the basic block starting on offset 0x2370
	2) avoid the basic block starting on offset 0x2390


```
>>> import angr #the main framework
>>> import claripy #the solver engine

>>> proj = angr.Project("./angrme", auto_load_libs=False)
>>> base_address=proj.loader.main_object.min_addr
>>> state = proj.factory.entry_state()
>>> simgr = proj.factory.simulation_manager(state)
>>> simgr.use_technique(angr.exploration_techniques.DFS())

>>> avoid_addr= base_address + 0x2390
>>> find_addr= base_address + 0x2370

>>> simgr.explore(find=find_addr, avoid=avoid_addr)
>>> found = simgr.found[0]
>>> arg_offset = 0x30
>>> [ found.solver.eval( found.mem[found.regs.rsp + arg_offset + x ].long.resolved ) for x in range(0, 0x30, 8) ]

[0x5f646e347b707868,
 0x5f7230665f77306e,
 0x6133725f336d3073,
 0x336c6c3468635f6c,
 0x7d33676e,
 0x7b]
```

# The Flag:
    hxp{4nd_n0w_f0r_s0m3_r3al_ch4ll3ng3}
