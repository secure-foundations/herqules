# HerQules: Securing Programs via Hardware-Enforced Message Queues

Many computer programs directly manipulate memory using unsafe pointers, which may introduce memory safety bugs. In response, past work has developed various runtime defenses, including memory safety checks, as well as mitigations like no-execute memory, shadow stacks, and control-flow integrity (CFI), which aim to prevent attackers from obtaining program control. However, software-based designs often need to update in-process runtime metadata to maximize accuracy, which is difficult to do precisely, efficiently, and securely. Hardware-based fine-grained instruction monitoring avoids this problem by maintaining metadata in special-purpose hardware, but suffers from high design complexity and requires significant microarchitectural changes.

In this project, we present an alternative solution by adding a fast hardware-based append-only inter-process communication (IPC) primitive, named AppendWrite, which allows a monitored program to transmit a log of execution events to an external verifier, relying on inter-process memory protections for isolation. We build low-cost implementations of AppendWrite for both an FPGA-based accelerator and in microarchitecture. Using this primitive, we design HerQules (HQ), a framework for automatically enforcing integrity-based execution policies through compiler instrumentation, which reduces overhead on the critical path by decoupling program execution from policy checking via concurrency, without affecting security. We perform a case study on control-flow integrity against multiple benchmark suites, and demonstrate that HQ-CFI achieves a significant improvement in correctness, effectiveness, and performance compared to prior work.

# Publication Information

Daming D. Chen, Wen Shih Lim, Mohammad Bakhshalipour, Phillip B. Gibbons, James C. Hoe, Bryan Parno. [*HerQules: Securing Programs via Hardware-Enforced Message Queues*](papers/2021_asplos_herqules.pdf). In **Proceedings of the Twenty-Sixth International Conference on Architectural Support for Programming Languages and Operating Systems** (ASPLOS '21). Association for Computing Machinery, New York, NY, USA. April 2021.

# Repository Information

This repository contains the code for HerQules, which includes our AppendWrite implementations for FPGA and microarchitecture, as well as our HQ-CFI policy that enforces our pointer integrity-based control-flow integrity design. See [BUILDING.md](BUILDING.md) for configuration and build instructions.
