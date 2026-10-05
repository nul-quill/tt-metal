// SPDX-FileCopyrightText: © 2026 Tenstorrent USA, Inc.
//
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <tt-metalium/core_coord.hpp>

#include "hostdev/streaming_profiler_common.h"

namespace tt {
class Cluster;
}
namespace tt::llrt {
class RunTimeOptions;
}
namespace tt::tt_fabric {
class ControlPlane;
class FabricContext;
class FabricNodeId;
}  // namespace tt::tt_fabric

namespace tt::tt_metal {

class Hal;

// Without fabric, the profiler runs the link ends as resident kernels. With fabric, the routers on the chosen links run
// them, under LINK_SYNC_ROLE in fabric_erisc_router.cpp.
namespace streaming_profiler::link_sync {

struct Link {
    CoreCoord eth_a, eth_b;  // eth_a is on the lower chip id, whose end is the transmitter
};
// Returns every connected eth pair between the two chips. With fabric on (`control_plane` non-null), returns only the
// pairs on its active channels.
std::vector<Link> links_between(
    const tt::Cluster& cluster, const tt_fabric::ControlPlane* control_plane, uint32_t chip_x, uint32_t chip_y);

// Returns the address of the link end's kernel_profiler::LinkSyncL1 on every active eth core. It is at the top of
// ACTIVE_ETH UNRESERVED, whether a resident kernel or a router runs the end.
uint32_t l1_addr(const Hal& hal);
// Returns the top of the L1 a fabric router may load into. That is the start of the link end's LinkSyncL1 whenever the
// profiler captures, and `router_limit` otherwise.
uint32_t router_l1_limit(const Hal& hal, const llrt::RunTimeOptions& rtoptions, uint32_t router_limit);
// Returns the named compile-time args that kernels/link_sync.hpp reads. LINK_SYNC_ROLE is the role of the link end,
// LINK_SYNC_L1_ADDR is the address of its LinkSyncL1, and LINK_SYNC_CHECK is whether the sync check runs.
std::unordered_map<std::string, uint32_t> compile_args(
    kernel_profiler::LinkSyncRole role, uint32_t link_l1, bool sync_check);
// Adds compile_args() to the named compile-time args that fabric_erisc_router.cpp reads whenever the JIT defines
// PROFILE_STREAMING on Blackhole. Only ERISC0's router runs a link end, and only when this process captures.
void add_router_compile_args(
    const tt_fabric::FabricContext& fabric,
    uint32_t risc_id,
    const tt_fabric::FabricNodeId& node,
    const CoreCoord& eth_logical,
    std::unordered_map<std::string, uint32_t>& named_args);
// Zeroes the link-end slots, control word and done word of the LinkSyncL1 at `link_l1` on the eth core at `virt`.
void zero_link_end(tt::Cluster& cluster, uint32_t chip, const CoreCoord& virt, uint32_t link_l1);

}  // namespace streaming_profiler::link_sync
}  // namespace tt::tt_metal
