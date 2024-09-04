# Hypervisor Dissociative Execution (HyDE)

HyDE (Hypervisor Dissociative Execution) is an innovative, modified virtualization environment that empowers the host system to inject system calls into a guest virtual machine, enabling advanced control and monitoring of guest behavior. This repository contains the HyDE software development kit (SDK), examples, and documentation.

## Repositories
- [HyDE Core](https://github.com/AndrewFasano/hyde-capabilities): HyDE SDK, examples, and documentation.
- [HyDE KVM](https://github.com/AndrewFasano/hyde-kvm): Customized Linux KVM logic for HyDE.
- [HyDE QEMU](https://github.com/AndrewFasano/hyde-qemu) Customized QEMU for HyDE.

## License
As described in the LICENSE file, this repository is licensed under the MIT License.

## Citation
To cite our work, please use the following BibTeX entry:

```
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