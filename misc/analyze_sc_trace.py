import os
import sys

from dataclasses import dataclass

jumpers = [59] #execve
ignores = [15] # sigreturn - signal handler interrupted prior syscall
exits = [231, 60] # exit

'''
sigreturn goes between a syscall and a sysret and doesn't return:
    syscall (callno, asid, pc, rsp)
    syscall (15, asid, pc, rsp) <-- no return, asid is still really in original callno
    sysret (asid, pc, rsp) <- return from callno

execve (and clone) jump to a new PC
    syscall (callno, asid, pc, rsp) <-- noreturn
    syscall (callno, asid, NEW pc, NEW rsp) <-- new process
    sysret (asid, new pc, new rsp)

exit (and friends) never return and asid/fs can be reused in a call
    syscall (callno, asid, pc, rsp) <- noreturn
    syscall (callno asid, NEW pc, NEW rsp) <-- new process
    sysret (asid, new pc, new rsp) <-- return from 2nd syscall
'''


@dataclass
class SyscallRet:
    """Class for storing a syscall / sysret with cpu state"""
    is_syscall: bool
    cpu: int
    callno: int
    asid: int
    pc: int
    sp: int
    fs: int

    def __str__(self):
        if self.is_syscall:
            return f"syscall[{self.cpu:<01}]({self.callno:>03}, {self.asid:x}, {self.pc:x}, {self.sp:x}, {self.fs:x})"
        else:
            return f"sysret[{self.cpu}](___, {self.asid:x}, {self.pc:x}, {self.sp:x}, {self.fs:x})"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        # Direct equality
        return self.is_syscall == other.is_syscall and self.cpu == other.cpu and self.asid == other.asid and self.callno == other.callno and self.pc == other.pc and self.sp == other.sp and self.fs == other.fs
    
    def could_match(self, other):
        """is there any way this sysret could be from that syscall?"""
        assert(not self.is_syscall and other.is_syscall)
        return self.asid == other.asid and self.cpu == other.cpu

    def match(self, other, without=None):
        # Trying to match a sysret to a syscall
        if not without:
            without = []
        fields = ['asid', 'pc', 'sp', 'fs']

        for x in (without if isinstance(without, list) else [without]):
            try:
                fields.remove(x)
            except ValueError:
                print("Error no field: ", x)
                raise
        
        for field in fields:
            if getattr(self, field) != getattr(other, field):
                return False
        return True

    def __hash__(self):
        return hash((self.is_syscall, self.cpu, self.callno, self.asid, self.pc, self.sp, self.fs))

@dataclass
class Entry:
    """Class for storing an entry in our log file. line, cpu, and syscall object"""
    line: int
    syscallret: SyscallRet

    def __str__(self):
        return f"Line {self.line}: {self.syscallret}"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.line == other.line and self.syscall == other.syscall

    def __hash__(self):
        return hash((self.syscallret, self.line))

class SyscallState:
    def __init__(self):
        self.syscalls = [] # Entry objects
        self.active = set() # Syscall objects


    def handle(self, entry: Entry):
        '''
        return false to bail early
        '''
        if entry.syscallret.is_syscall:
            return self.push_syscall(entry)
        return self.pop_syscall(entry)

        
    def push_syscall(self, entry: Entry):
        assert(entry.syscallret.is_syscall)
        if entry.syscallret.callno == 15: # Ignore sigreturn
            print(f"Ignoring sigreturn: {entry}")
            return True
        
        # Raise an error on double sysret, unless the last entry was a no-return
        if entry.syscallret in self.active:
            abort = True
            match = None

            print("We have a total of ", len(self.syscalls), " syscalls active")

            # Find the most recent match, there has to be one!
            for i in range(len(self.syscalls)-1, -1, -1): # Start from len()-1, run including 0
                print("Checking ", self.syscalls[i].syscallret)
                if entry.syscallret == self.syscalls[i].syscallret:
                    match = i
                    break

            assert(match is not None)

            if match:
                # Found a match - analyze and potentially skip our abort
                last_callno = self.syscalls[match].syscallret.callno
                print("Last syscall:", self.syscalls[match].syscallret)
                if last_callno in [59, 60, 231]: # execve, exit, exit_group
                    # It's a duplicate, except the last entry was something that wouldn't return so just drop it now
                    self.syscalls.pop(match)
                    abort = False

            if abort:
                print("ERROR: double syscall without sysret")
                print(f"Prev syscall: {self.syscalls[i]}")
                print(f"Curr syscall: {entry}")
                raise RuntimeError

        self.active.add(entry.syscallret)
        self.syscalls.append(entry)

        return True

    def pop_syscall(self, entry: Entry):
        assert(not entry.syscallret.is_syscall)
        # Find the most recent, unpopped syscalls that could be
        # the origin of this sysret using (asid,sp,fs), (asid,pc,fs), (asid,pc,sp) and (asid,fs)
        # Then analyze the potential prior syscalls and, based off their callno, identify which we came from.
        # This works because we know how the prior callno would alter things i.e., arch_getprctl changes fs.

        withouts = {
            'pc': None,
            'sp': None,
            'fs': None,
            'pc_sp': None
        }

        for idx, other in reversed(list(enumerate(self.syscalls))):
            if not entry.syscallret.could_match(other.syscallret):
                continue

            for y in ['pc', 'sp', 'fs', ['pc', 'sp']]:
                name = ('_'.join(y) if isinstance(y, list) else y)

                if withouts[name] is not None:
                    continue

                if entry.syscallret.match(other.syscallret, without=y):
                    withouts[name] = idx

            if not any([x is None for x in withouts.values()]):
                break
        
        if all([x == None for x in withouts.values()]):
            raise ValueError(f"All matches are none for {entry}")

        last_sc = None # It's an entry
        if (withouts['pc'] == withouts['fs'] and withouts['fs'] == withouts['sp'] and withouts['sp'] == withouts['pc_sp']):
            # All the same, easy case
            last_sc = self.syscalls.pop(withouts['pc']) # Grab any, they're all the same
        else:
            # Need to decide which one to believe
            # We can examine the callno from each and decide if it's worth taking or not

            if withouts['pc'] is not None and withouts['pc'] == withouts['fs'] and withouts['fs'] == withouts['sp']:
                # We saw something when we searched on just asid,fs but it wasn't an execve so let's use what we got ??
                last_sc = self.syscalls.pop(withouts['pc'])

            elif withouts['fs'] is not None and self.syscalls[withouts['fs']].syscallret.callno in [158, 95]:
                # FS changed because of arch_prctl or umask
                last_sc = self.syscalls.pop(withouts['fs'])
            else:
                print(f"ERROR: failed to map {entry} back to a syscall")
                for name, val in withouts.items():
                    if val is None:
                        print("No value for ", name)
                    else:
                        print(name, self.syscalls[val])

                print("Potential syscalls we could have come from (asid, cpu)")
                for x in self.syscalls:
                    if x.syscallret.could_match(entry.syscallret):
                        print(x)

        if last_sc:
            print(f"{entry} -> {last_sc}")
            assert(last_sc.syscallret in self.active)
            self.active.remove(last_sc.syscallret)

        return last_sc is not None # Return false to bail early

def parse(file_name, outfile):
    with open (outfile, "w") as out:
        out.write(f"lineno, syscall, cpu, callno, asid, pc, rsp, fs\n")

        with open(file_name, 'r') as file:
            for idx, line in enumerate(file):
                if not line.startswith("sys"):
                    #raise ValueError(f"Bad line {idx+1}: {line}")
                    if "sys" in line:
                        line = line[line.index("sys"):]
                    else:
                        continue

                if "syscall" not in line and "sysret" not in line:
                    continue

                if "fs" not in line:
                    print("ERROR:", line)
                assert("fs" in line)

                parts = line.strip().split(' ')
                is_syscall = parts[0] == 'syscall'

                try:
                    asid = int(parts[1], 16)
                    cpu = int(parts[3], 16)
                    if is_syscall:
                        callno = int(parts[5][:-1])
                        pc_idx = 7
                        rsp_idx = 9
                        fs_idx = 11
                    else:
                        callno = 0
                        pc_idx = 6
                        rsp_idx = 8
                        fs_idx = 10

                    if parts[pc_idx].endswith(","):
                        parts[pc_idx] = parts[pc_idx][:-1]
                    pc = int(parts[pc_idx], 16)
                    rsp= int(parts[rsp_idx], 16)
                    fs=  int(parts[fs_idx], 16)

                except ValueError:
                    print(idx+1, line)
                    raise

                key = (asid, fs, rsp)
                no_sp_key = (asid, fs)

                if parts[0] == 'syscall':
                    callno = int(parts[5][:-1])
                else:
                    callno = 0

                out.write(f"{idx+1},{is_syscall},{cpu},{callno},{asid:x},{pc:x},{rsp:x},{fs:x}\n")

def analyze_file(file_name):
    asid_map = {} # (asid, fs, rsp)
    seen_first = set()
    active_jumps = {} # (asid, fs) => old rsp. On every return try looking up in here, if we find one, use old rsp to drop from asid_map
    
    # New stuff
    seen = set()

    S = SyscallState()

    with open(file_name, 'r') as file:
        # skip header
        file.readline()

        for line in file:
            parts = line.strip().split(',')

            line = int(parts[0])
            is_syscall = parts[1] == 'True'
            cpu = int(parts[2])
            callno = int(parts[3])

            asid = int(parts[4], 16)
            pc = int(parts[5], 16)
            sp = int(parts[6], 16)
            fs = int(parts[7], 16)

            record = Entry(line, SyscallRet(is_syscall, cpu, callno, asid, pc, sp, fs))

            if not S.handle(record):
                print(f"Bailing early for failure with {record}")
                break # Debugging, quit early sometimes

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 analyze_file.py <file_name> [out.csv]')
    else:
        if len(sys.argv) > 2:
            out = sys.argv[2]
        else:
            out = "out.csv"

        #if not os.path.isfile(out):
        #    parse(sys.argv[1], out)
        analyze_file(out)