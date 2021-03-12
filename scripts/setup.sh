#!/bin/sh

set -e

DPDK=0
OPAE=0

# packages
apt-get update
apt-get install -y build-essential binutils-dev cmake ccache ninja-build linux-headers-$(uname -r) clang-11 clang-format-11 llvm-11-dev linux-tools-$(uname -r) libcap-dev libssl-dev wget

if [ $DPDK -ne 0 ]; then
    apt-get install -y dpdk libdpdk-dev
    sed -i "s/^GRUB_CMDLINE_LINUX=\"/&intel_iommu=on /" /etc/default/grub
    update-grub
    # echo "options vfio enable_unsafe_noiommu_mode=1" | tee /etc/modprobe.d/vfio-iommu.conf
fi

if [ $OPAE -ne 0 ] ; then
    apt-get install -y alien uuid-dev libjson-c-dev
    dpkg -i "$(dirname $0)"/libjson0_0.12.1.deb
    wget https://github.com/OPAE/opae-sdk/releases/download/1.3.0-2/opae-libs-1.3.0-2.x86_64.deb
    dpkg -i opae-libs-1.3.0-2.x86_64.deb
    wget https://github.com/OPAE/opae-sdk/releases/download/1.3.0-2/opae-devel-1.3.0-2.x86_64.deb
    dpkg -i opae-devel-1.3.0-2.x86_64.deb

    wget https://github.com/OPAE/opae-sdk/releases/download/1.4.0-1/opae-intel-fpga-driver-2.0.4-2.x86_64.rpm
    alien opae-intel-fpga-driver-2.0.4-2.x86_64.rpm
fi

# perf
echo "kernel.perf_event_paranoid = -1\nkernel.kptr_restrict = 0" | tee -a /etc/sysctl.conf
sysctl -f

# kernel interface
echo "\ndebugfs\t/sys/kernel/debug\tdebugfs\tdefaults,mode=755\t0\t0\ntracefs\t/sys/kernel/debug/tracing\ttracefs\tdefaults,mode=755\t0\t0" | tee -a /etc/fstab

# hugepages
sed -i "s/^GRUB_CMDLINE_LINUX=\"/&default_hugepagesz=1G hugepagesz=1G hugepages=1 hugepagesz=2MB hugepages=1024 /" /etc/default/grub
update-grub
mkdir /mnt/huge_1GB
chmod a+rw -R /mnt/huge_1GB
mkdir /mnt/huge_2MB
chmod a+rw -R /mnt/huge_2MB
echo "\nnodev\t/mnt/huge_1GB\thugetlbfs\tpagesize=1GB\t0\t0\nnodev\t/mnt/huge_2MB\thugetlbfs\tpagesize=2MB\t0\t0" | tee -a /etc/fstab
