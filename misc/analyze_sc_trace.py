import os
import sys

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
class SyscallState:
    def __init__(self):
        self.syscalls = [] # Front is oldest. (cpu, asid, pc, sp, fs, enter_line, enter_callno)
        self.active = set() # (cpu, asid, pc, sp, fs)
        
    def push_syscall(self, line, callno, cpu, asid, pc, sp, fs):
        if callno == 15: # Ignore sigreturn
            return
        
        #print(f"\nStore {cpu} {asid:x} {pc:x} {sp:x} {fs:x} {callno}")
        #print(self.active)

        if (cpu, asid, pc, sp, fs) in self.active:
            print(f"Error: double sysenter at {line}: {cpu} {asid:x} {pc:x} {sp:x} {fs:x} {callno}")
            raise RuntimeError

        if callno in [231, 60]: # exit
            # Do not record - we won't see a sysret for this
            return

        if callno in [59]: # execve and friends
            # Do not record - we won't see a sysret for this
            # Note, if these fail, we *do* see a sysret. We could record this and then, on the next
            # syscall in the same asid/fs, cleanup, otherwise cleanup on return (in the rare case of errors)
            return

        self.active.add((cpu, asid, pc, sp, fs))

        self.syscalls.append((cpu, asid, pc, sp, fs, line, callno))

    def pop_syscall(self, line, cpu, asid, pc, sp, fs):
        # Find the most recent, unpopped syscalls that could be
        # the origin of this sysret using (asid,sp,fs), (asid,pc,fs), (asid,pc,sp) and (asid,fs)
        # Then analyze the potential prior syscalls and, based off their callno, identify which we came from.
        # This works because we know how the prior callno would alter things i.e., arch_getprctl changes fs.

        without_pc = None
        without_sp = None
        without_fs = None
        without_pc_sp = None
        for i in range(len(self.syscalls)-1, -1, -1): # Start from len()-1, run including 0
            #print(f"Comparing cpu ({cpu} vs {self.syscalls[i][0]}) and asid ({asid:x} vs {self.syscalls[i][1]:x}) and pc ({pc:x} vs {self.syscalls[i][2]:x}) and ({sp:x} vs {self.syscalls[i][3]:x}) and ({fs:x} vs {self.syscalls[i][4]:x})")
            if self.syscalls[i][0] != cpu or self.syscalls[i][1] != asid:
                # Definitely wrong, different CPU or different ASID
                continue

            if self.syscalls[i][2] == pc and self.syscalls[i][3] == sp and without_fs is None:
                without_fs = i

            if self.syscalls[i][2] == pc and self.syscalls[i][4] == fs and without_sp is None:
                without_sp = i

            if self.syscalls[i][3] == sp and self.syscalls[i][4] == fs and without_pc is None:
                without_pc = i

            # Just asid+FS matches
            if self.syscalls[i][4] == fs and without_pc_sp is None:
                without_pc_sp = i

            if not any([x is None for x in [without_pc, without_sp, without_fs, without_pc_sp]]):
                break
        
        if all([x is None for x in [without_pc, without_sp, without_fs, without_pc_sp]]):
            # Didn't find any - yikes. early?
            print(f"Found nothing for {asid:x} on line {line}")
            return None

        last_sc = None
        if (without_pc == without_fs and without_fs == without_sp and without_sp == without_pc_sp):
            # All the same, easy case
            last_sc = self.syscalls.pop(without_pc) # Grab any, they're all the same
        else:
            # Need to decide which one to believe
            # We can examine the callno from each and decide if it's worth taking or not

            # Maybe we shouldn't ever hit this case - we shouldn't record the execve since it's a noreturn
            if without_pc_sp and self.syscalls[without_pc_sp][-1] in [59]:
                # PC changed because of execve - this syscall seems right
                last_sc = self.syscalls.pop(without_pc_sp)

            elif without_pc == without_fs and without_fs == without_sp:
                # We saw something when we searched on just asid,fs but it wasn't an execve so let's use what we got
                last_sc = self.syscalls.pop(without_pc)

            elif without_fs and self.syscalls[without_fs][-1] in [158]:
                # FS changed because of arch_prctl
                last_sc = self.syscalls.pop(without_fs)
            else:
                print(f"TODO: {line}")
                for x in [without_pc, without_fs, without_sp, without_pc_sp]:
                    print(x, "callno:", self.syscalls[x][-1], "line:", self.syscalls[x][-2], "asid:", hex(self.syscalls[x][1]))

        if last_sc:
            assert(last_sc[0:5] in self.active)
            self.active.remove((last_sc[0:5]))
            print(f"Syscall from line {line} seems to be return from line {last_sc[-2]} which was callno {last_sc[-1]}")

        return last_sc is None

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
            key = (asid, fs, sp)
            no_sp_key = (asid, fs)

            '''
            if key not in seen:
                seen.add(key)
                if not is_syscall:
                    print(f"{line}: first time seeing {key} and it's on return - allow")
                    continue # We didn't see the enter, so we don't care about the exit
            '''

            if is_syscall:
                S.push_syscall(line, callno, cpu, asid, pc, sp, fs)
            else:
                if S.pop_syscall(line, cpu, asid, pc, sp, fs):
                    break # Got an error if it returns True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 analyze_file.py <file_name> [out.csv]')
    else:
        if len(sys.argv) > 2:
            out = sys.argv[2]
        else:
            out = "out.csv"

        if not os.path.isfile(out):
            parse(sys.argv[1], out)
        analyze_file(out)