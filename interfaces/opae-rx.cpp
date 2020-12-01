#include <vector>

#include <opae/cxx/core/properties.h>
#include <opae/cxx/core/token.h>

#include "opae-rx.h"

namespace HQ::OPAE {

fpga_t RX::open_device() {
    // Create a filter with desired properties for enumerating devices
    auto filter = opae::fpga::types::properties::get();
    filter->guid = const_cast<std::decay<fpga_guid>::type>(FPGA_GUID);
    filter->type = FPGA_ACCELERATOR;

    // Enumerate the devices using the filter
    std::vector<opae::fpga::types::token::ptr_t> tokens =
        opae::fpga::types::token::enumerate({filter});
    if (!tokens.size()) {
        std::cerr << "Cannot find a matching FPGA device!" << std::endl;
        return nullptr;
    }

    // Open the first matching device
    fpga_t fpga = opae::fpga::types::handle::open(tokens[0], FPGA_OPEN_SHARED);
    if (!fpga) {
        std::cerr << "FPGA device is busy!" << std::endl;
        return nullptr;
    }

    return fpga;
}

bool RX::open() {
    fpga = open_device();
    if (!fpga)
        return false;

    // Map registers
    if (!(mmio = fpga->mmio_ptr(0, DEFAULT_CSR_SPACE)))
        return false;

    static_assert(sizeof(struct fpga_msg) == 64,
                  "Messages from FPGA must be cacheline size!");
    // Prepare buffer
    buffer = opae::fpga::types::shared_buffer::allocate(
        fpga, HQ_INTERFACE_APPLICATION_SIZE);
    if (!buffer)
        return false;

    // Configure host buffer, in cacheline units
#ifdef HQ_INTERFACE_OPAE_SIMULATE
    fpga->write_csr64(REG_HOST_BUF_ADDR,
                      buffer->io_address() / sizeof(struct fpga_msg));
    fpga->write_csr64(REG_HOST_BUF_SZ, BUFFER_SIZE);
#else
    write64(mmio, REG_HOST_BUF_ADDR,
            buffer->io_address() / sizeof(struct fpga_msg));
    write64(mmio, REG_HOST_BUF_SZ, BUFFER_SIZE);
#endif /* HQ_INTERFACE_OPAE_SIMULATE */
    return true;
}

RX::const_iterator RX::get_msgs() {
#ifndef NDEBUG
    if (__builtin_expect(!*this, 0))
        return nullptr;
#endif /* !NDEBUG */

    const volatile auto *buf =
        reinterpret_cast<volatile struct fpga_msg *>(buffer->c_type());
    const auto *ptr = &buf[read % BUFFER_SIZE];
    const auto counter = ptr->counter;
    if (__builtin_expect(counter > read + 1, 0)) {
        // Message was missed, return error
        return nullptr;
    }
    // Return begin/end iterator depending on whether message has arrived
    // yet
    return const_iterator(counter < read + 1 ? ptr : &buf[BUFFER_SIZE], buf,
                          &read);
}

bool RX::reset() {
#ifndef NDEBUG
    if (__builtin_expect(!*this, 0))
        return false;
#endif /* !NDEBUG */

    const volatile auto *buf =
        reinterpret_cast<volatile struct fpga_msg *>(buffer->c_type());
    const auto *ptr = &buf[read % BUFFER_SIZE];
    if (ptr->counter > read + 1) {
        read = ptr->counter - 1;
        return true;
    }

    return false;
}

ssize_t RX::get_drops() const {
#ifndef NDEBUG
    if (__builtin_expect(!*this, 0))
        return -1;
#endif /* !NDEBUG */

#ifdef HQ_INTERFACE_OPAE_SIMULATE
    return fpga->read_csr64(REG_MSG_DROPS);
#else
    return read64(mmio, REG_MSG_DROPS);
#endif /* HQ_INTERFACE_OPAE_SIMULATE */
}

std::ostream &operator<<(std::ostream &os, const RX &rx) {
    return os << "OPAE::RX = FPGA: " << rx.fpga << ", Buffer: " << rx.buffer
              << ", Read: " << rx.read << ", MMIO: "
              << static_cast<const void *>(const_cast<const uint8_t *>(rx.mmio))
              << ", Drops: " << rx.get_drops();
}

} // namespace HQ::OPAE
