#include <unistd.h>

#include "model_sim.h"

namespace HQ::MODEL_SIM {

bool RX::open() { return true; }

std::ostream &operator<<(std::ostream &os, const RX &rx) {
    return os << "MODEL_SIM::RX";
}

} // namespace HQ::MODEL_SIM
