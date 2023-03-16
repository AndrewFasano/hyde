# HyDE Capabilities


Whereas a HyDE implementation and its programs are bug-free so they only cause the intended state changes to guest sytems, they may be described as the following.

`HP = HyDE program` and `GP = guest program`

## Active or Passive
Does HP modify the behavior of the guest system?

## Coordinated or Uncoordinated with Guest Program(s)
Does the HP require GP to behave in a certain way in order to have a desired outcome?

Two cases for coordinated programs:
1) GP only functions properly in conjunction with HP - i.e., GP is developed such that it depends on HP.
2) GP does not depend on HP, but HP provides guardrails on execution on one or more GP - i.e., HP is designed to limit behavior of GP to expected execution.

## Omnipresent or Loadable
Must the HP be running from the start of guest boot or can it be loaded on demand?

## On-Demand or Long-lived
Is the HyDE program something that runs briefly or persistently during guest execution?

# Problems in Virtualized Environments
* Identifying unexpected behavior - buggy code, misconfiguration, or malicious actors lead system to take unexpected actions
* Understanding system behavior - enumerating processes and interactively debugging them requires accessing the guest and installing new software
* Lost access to guest system - password forgotten, ssh server or RDP is stopped, crashes, or is misconfigured
* Cannot safely modify guest filesystem while guest is running
* Guest programs may be unaware of host features that could be used to optimize performance
* Difficult to enforce security policies - malicious actors in guest can disable and reconfigure security policies post-exploitation
* Malicious root users in guest have unlimited access to system

# List of HyDE Programs and Applications

* Whole-system strace or subset of syscalls (i.e., execves) - understanding system behavior, validation of correct execution
* HyDE-ps - list running processes
* HyDE-debugger - attach a debugger to a running process and interactively debug it
* File creation or modification in guest - reset password, share data with guest
* Program launcher - start shell, ssh/RDP server
* Socket reconfiguration - modify guest-created AF_INET sockets to instead use AF_VSOCK to skip the need for running emulated hardware
* Execution filter - only allow programs with specific hash to execute
* Execution addition - add argument or environment variable when condition is met (i.e., API key)
* Pseudofile addition - when conditions are met, allow process to read a host-managed file.
* Kernel module filter - prevent kernel modules from being loaded unless they are in a specified list
* Seccomp detection - identify which processes have enabled syscall filtering with seccomp
* No-encrypt - identify when a process is rewriting files to increase entropy and kill it (anti-ransomware)

# HyDE Program Taxonomy

| Program Type | Summary | **A**ctive / **P**assive | **Un**/**Co**ordinated | **Om**nipresent / **Lo**adable | On-Demand (**OD**) / Long-Lived (**LL**) |
| :---         | :---     | :---:           | :---:          | :---:                  | :----:                 |
| Tracing | record log of executions or system calls | P | UN | L | LL |
| Introspection | collect information about system and running programs  | P | UN | L | OD |
| Debugger | start debugging a selected process | A| UN| L| OD |
| File manager | add, delete, or modify a guest file | A| UN| L| OD |
| Program launcher | spawn a guest program | A| UN| L| OD |
| Execution filter | ensure only known binaries can run with known libraries | A| UN| L| LL |
| Execution addition | conditionally provide information to launched programs | A| CO| L| LL |
| Pseudofile addition | conditionally allow reads of a file | A| CO| L| LL |
| Kernel module filter | restrict which kernel modules can be run | A| UN| L/OM| LL |
| Seccomp detection | identify which processes have seccomp enabled | P| UN| L/OM| LL |
| Optimization | transparently change how programs interact with hardware | A| UN| OM| LL |

And more!


# Example programs
| Program Name | Program Type | Summary | Implemented | SLoC | Test status |
| :----        | :---         | :---    | :---:       | :--- | :---:       |
| PwReset      | File manager | Change password hashes  | Yes | 165 | works on ubuntu 18.04
| EnvMgr       | Execution addition | Add environment variable | Yes | 91 | works on ubuntu 18.04
| SecretFile   | Pseudofile addition | Conditionally allow reads of a (host-managed) pseudofile | Yes |  139 | works on ubuntu 18.04
| PS           | Introspection | List currently running processes | Yes |  144 | works on ubuntu 18.04
| Attest       | Execution filter | Checksum binaries before they're allowed to run (TODO: and libraries) | Yes |  105 | works on ubuntu 18.04
| LaunchSSH    | Program launcher | Restart the ssh daemon | Yes | 106 | works on ubuntu 18.04
| SBOM         | Introspection | Report hashes of binaries that are run and files mapped into memory | Yes |  202 | works on ubuntu 18.04