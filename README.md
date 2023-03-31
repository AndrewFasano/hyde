# HyDE Programs

Cloud computing, a type of infrastructure-as-service, enables users to run software on hardware owned by a cloud provider.
Typically, the provider manages their hardware and uses a virtualization layer so a user-managed operating system
and software can operate independently from any other users who are co-located on the same hardware.

This split in management responsabilities has both benefits and disadvantages for users. Users may
run any software they want, so long as it supports the deployed virtualization software. However,
if users misconfigure their system, there are few features their provider can offer to assist.

Typically providers give users a web interface where guest VMs can be powered on/off,
hardware utilization can be viewed (e.g., CPU usage),
hardware settings adjusted (e.g., disk size, memory available),
and a virtual serial console can be accessed.

Both users and providers would benefit if providers were able to provide additional ways for users to
examine and control their systems. For example, consider the following problems that users may encounter:

## Problems for users of virtualized systems
* Diagnosing unexpected system behavior  - buggy code, misconfiguration, or malicious actors lead system to take ggunexpected actions. Enumerating processes and interactively debugging them requires accessing the guest and installing new software
* Lost access to guest system - password forgotten, ssh server or RDP is stopped, crashes, or is misconfigured
* Programs may be unaware of optimiziations available due to the nature of the virtualized environment
* Malicious actors can erase logs or disable and reconfugre security policies post-exploitation
* Users may want out-of-band filesystem access to simplify management of guest system
* Users may wish to enable out-of-band restrictions on guest behavior

## How these problems are solved today:
* Diagnosting unexpected system behavior - install debugging/profiling tools inside guest system, enumerate running processes, use installed tools to analyze suspicious processes
* Lost access - virtualized console access to restart services, shutdown and modify (unencrypted) filesystem to reset password
* Unaware of optimizations - programs generally cannot take advantage of virtualization-based features that they were not designed to support, unless the kernel enables this
* Malicious acotrs in guest - logs can be stored remotely which should capture compromise itself, but log forwarding may be disabled post-exploitation
* Out-of-band filesystem access - providers can build interfaces atop guest-enabled services (i.e., ssh) but users must provide authentication credentials to this interface
* Out-of-band behavior restrictions - users may limit hardware features (i.e., disable networking), but such restrictions cannot easily be done in software.

These problems, and more, can be solved using our technique, Hypervisor Dissociative Execution which provides a stable interface
atop which portable programs can be designed that run at the virtualization layer, without the need for guest cooperation.
Programs can be built atop this interface, that provide information about a guest system's current state, make a one-time modification to the state, collect
information in perpetuity, or modify system behaviour forever.

These programs can run across guest OSes and OS versions, only needing modifications when the target system's system call interface changes. While these programs are running,
a modest, 30% slowdown in guest behavior is introduced, but for many users, this may be a worthy trade off.

----

## Problem classes
* Monitoring or Modification: Does this problem require passively monitoring system or changing its behavior?
* Must guest run bespoke programs 

----

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
* No root network listening processes - if a process has an EUID of 0, it cannot listen for network traffic on a public IP

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
