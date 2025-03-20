# Hypervisor Dissociative Execution (HyDE)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Project Status: Active](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

HyDE (Hypervisor Dissociative Execution) is an innovative, modified virtualization environment that empowers the host system to inject system calls into a guest virtual machine, enabling advanced control and monitoring of guest behavior. This repository contains the HyDE software development kit (SDK), examples, and documentation.

## Table of Contents
- [Abstract](#abstract)
- [Key Features](#key-features)
- [HyDE Repositories](#hyde-repositories)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Building HyDE Programs](#building-hyde-programs)
- [Running a HyDE Program](#running-a-hyde-program)
- [Contributing](#contributing)
- [License](#license)
- [Citation](#citation)
- [Support](#support)

## Abstract

To understand the HyDE system, we recommend reading [our full paper](https://github.com/AndrewFasano/hyde/blob/main/paper.pdf), the abstract of which is below:

> Both cloud providers and users wish to manage, monitor, and secure virtualized guest systems. Traditionally, this has been accomplished with custom agent programs that run inside a guest or complex virtual machine introspection (VMI) systems that operate outside a guest. Agents are limited by the need to install and maintain them in each guest, while VMI systems are limited by the need to understand guest kernel internals. We introduce Hypervisor Dissociative Execution, or HyDE, a new approach that operates between these extremes to avoid their limitations and provide a robust and flexible mechanism to examine and modify a guest from the outside. In the HyDE model, developers assemble programs that mix out-of-guest logic with in-guest system calls. These programs are launched from outside a guest where they are able to coopt the execution of guest processes. We present a prototype HyDE implementation paired with 10 HyDE programs that address a wide range of user needs from password resets and guest process enumeration to dynamically generating a software bill of materials. We evaluate the utility, robustness, and performance of HyDE by executing these example programs while concurrently running standard benchmarks within multiple guest systems. Our results show that HyDE maintains system stability and incurs negligible overhead for one-off analyses or modifications. In persistent operation, HyDE incurs overhead as low as 7% in a multi-node cloud application benchmark.

## Key Features
- Inject system calls into guest VMs from the host system
- Flexible guest monitoring and control without in-guest agents
- Minimal performance overhead
- Wide range of applications from password resets to software bill of materials generation

## HyDE Repositories
- [HyDE Core](https://github.com/AndrewFasano/hyde): HyDE SDK, examples, and documentation (this repo).
- [HyDE KVM](https://github.com/AndrewFasano/hyde-kvm): Customized Linux KVM logic for HyDE.
- [HyDE QEMU](https://github.com/AndrewFasano/hyde-qemu) Customized QEMU for HyDE.

## Getting Started

### Prerequisites
- Linux environment
- clang-15++
- Git

### Installation
1. Clone this repository:
   ```
   git clone https://github.com/AndrewFasano/hyde-capabilities.git
   cd hyde-capabilities
   ```
2. Set up dependencies:
   - Build and install a Linux kernel with support for HyDE's KVM (follow instructions in the [HyDE KVM repo](https://github.com/AndrewFasano/hyde-kvm)).
   - Build and install the HyDE QEMU fork (follow instructions in the [HyDE QEMU repo](https://github.com/AndrewFasano/hyde-qemu)).
   - Build one or more HyDE programs (instructions below).
   - Run an emulated guest and load a HyDE program (instructions below).

## Building HyDE Programs

After cloning this repo, simply run `make` to build the programs in `hyde_programs` into `.so` shared objects. The build process requires you to have clang-15++ and to have cloned the `hyde-qemu` repo in the parent directory of this repo. The generated shared objects will be produced in the `hyde_programs` directory.

## Running a HyDE Program

To run a HyDE program, you can either:

1. Launch QEMU with the `-hyde-enable` argument:
   ```sh
   qemu-system-x86_64 -enable-kvm your_image.qcow2 -m 8G -smp 8,sockets=2,cores=4 -hyde-enable /path/to/your/hyde/program.so
   ```

2. Load a HyDE program from the QEMU monitor after guest startup:
   - Launch QEMU without the `-hyde-enable` argument
   - Press `control-a` then `c` to access the `(QEMU)` prompt
   - Type: `hyde_enable /path/to/your/hyde/program.so`

## Contributing
We welcome contributions to HyDE! We would be excited by additional HyDE programs, bug fixes, and other improvements. Please open an issue or pull request in this repository to contribute.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Citation
To cite our work, please use the following BibTeX entry:

```bibtex
@inproceedings{fasano2024hypervisor,
  title={Hypervisor Dissociative Execution: Programming Guests for Monitoring, Management, and Security},
  author={Fasano, Andrew and Estrada, Zak and Leek, Tim and Robertson, William},
  booktitle={Proceedings of the Annual Computer Security Applications Conference},
  series={ACSAC '24},
  year={2024},
  month={Dec},
  address={Waikiki, Hawaii, USA},
  publisher={Association for Computing Machinery},
  location={Waikiki, Hawaii, USA},
  dates={9-13}
}
```

## Support
For questions, issues, or feature requests, please open an issue in this repository!
