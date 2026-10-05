// SPDX-FileCopyrightText: © 2026 Tenstorrent USA, Inc.
//
// SPDX-License-Identifier: Apache-2.0

#include "impl/streaming_profiler/sync/link_sync.hpp"

#include <algorithm>
#include <cstddef>
#include <ranges>
#include <tuple>
#include <vector>

#include <tt-metalium/experimental/fabric/control_plane.hpp>
#include <tt-metalium/experimental/fabric/fabric_types.hpp>
#include <umd/device/types/core_coordinates.hpp>

#include "fabric/fabric_context.hpp"
#include "hostdev/streaming_profiler_common.h"
#include "impl/streaming_profiler/device_programs.hpp"
#include "llrt/hal.hpp"
#include "llrt/metal_soc_descriptor.hpp"
#include "llrt/tt_cluster.hpp"

namespace tt::tt_metal::streaming_profiler::link_sync {

namespace {

bool on_synced_channel(
    const tt::Cluster& cluster,
    const tt_fabric::ControlPlane* control_plane,
    uint32_t chip,
    const CoreCoord& eth_logical) {
    if (control_plane == nullptr) {
        return true;
    }
    const auto& soc = cluster.get_soc_desc(static_cast<ChipId>(chip));
    const auto channels = control_plane->get_active_fabric_eth_channels(
        control_plane->get_fabric_node_id_from_physical_chip_id(static_cast<ChipId>(chip)));
    return std::ranges::any_of(channels | std::views::keys, [&](const auto channel) {
        return soc.get_eth_core_for_channel(channel, CoordSystem::LOGICAL) == eth_logical;
    });
}

// Returns the role of this eth core's end on the link the profiler syncs through it, or None if it syncs no link.
kernel_profiler::LinkSyncRole role_of(
    const tt::Cluster& cluster,
    const tt_fabric::ControlPlane& control_plane,
    ChipId chip,
    const CoreCoord& eth_logical) {
    const auto& connections = cluster.get_ethernet_connections();
    const auto on_chip = connections.find(chip);
    if (on_chip == connections.end() ||
        !on_chip->second.contains(cluster.get_soc_desc(chip).logical_eth_core_to_chan_map.at(eth_logical))) {
        return kernel_profiler::LinkSyncRole::None;
    }
    const auto [peer, peer_eth] = cluster.get_connected_ethernet_core(std::make_tuple(chip, eth_logical));
    if (!on_synced_channel(cluster, &control_plane, static_cast<uint32_t>(chip), eth_logical) ||
        !on_synced_channel(cluster, &control_plane, static_cast<uint32_t>(peer), peer_eth)) {
        return kernel_profiler::LinkSyncRole::None;
    }
    return chip < peer ? kernel_profiler::LinkSyncRole::Transmitter : kernel_profiler::LinkSyncRole::Receiver;
}

}  // namespace

std::vector<Link> links_between(
    const tt::Cluster& cluster, const tt_fabric::ControlPlane* control_plane, uint32_t chip_x, uint32_t chip_y) {
    std::vector<Link> out;
    const uint32_t lo = std::min(chip_x, chip_y), hi = std::max(chip_x, chip_y);
    const auto by_peer = cluster.get_ethernet_cores_grouped_by_connected_chips(static_cast<ChipId>(lo));
    const auto it = by_peer.find(static_cast<ChipId>(hi));
    if (it == by_peer.end()) {
        return out;
    }
    for (const CoreCoord& eth_a : it->second) {
        const CoreCoord eth_b =
            std::get<1>(cluster.get_connected_ethernet_core(std::make_tuple(static_cast<ChipId>(lo), eth_a)));
        if (on_synced_channel(cluster, control_plane, lo, eth_a) &&
            on_synced_channel(cluster, control_plane, hi, eth_b)) {
            out.push_back(Link{.eth_a = eth_a, .eth_b = eth_b});
        }
    }
    return out;
}

uint32_t l1_addr(const Hal& hal) {
    return hal.get_dev_addr(HalProgrammableCoreType::ACTIVE_ETH, HalL1MemAddrType::UNRESERVED) +
           hal.get_dev_size(HalProgrammableCoreType::ACTIVE_ETH, HalL1MemAddrType::UNRESERVED) -
           sizeof(kernel_profiler::LinkSyncL1);
}

uint32_t router_l1_limit(const Hal& hal, const llrt::RunTimeOptions& rtoptions, uint32_t router_limit) {
    return can_capture(hal, rtoptions) ? l1_addr(hal) : router_limit;
}

std::unordered_map<std::string, uint32_t> compile_args(
    kernel_profiler::LinkSyncRole role, uint32_t link_l1, bool sync_check) {
    return {
        {"LINK_SYNC_ROLE", static_cast<uint32_t>(role)},
        {"LINK_SYNC_L1_ADDR", link_l1},
        {"LINK_SYNC_CHECK", sync_check ? 1u : 0u}};
}

void add_router_compile_args(
    const tt_fabric::FabricContext& fabric,
    uint32_t risc_id,
    const tt_fabric::FabricNodeId& node,
    const CoreCoord& eth_logical,
    std::unordered_map<std::string, uint32_t>& named_args) {
    const Hal& hal = fabric.get_hal();
    if (hal.get_arch() != tt::ARCH::BLACKHOLE) {
        return;
    }
    auto role = kernel_profiler::LinkSyncRole::None;
    if (risc_id == 0 && can_capture(hal, fabric.get_rtoptions())) {
        const tt_fabric::ControlPlane& control_plane = fabric.get_control_plane();
        role = role_of(
            fabric.get_cluster(),
            control_plane,
            control_plane.get_physical_chip_id_from_fabric_node_id(node),
            eth_logical);
    }
    named_args.merge(
        compile_args(role, l1_addr(hal), fabric.get_rtoptions().get_streaming_profiler_sync_check_enabled()));
}

void zero_link_end(tt::Cluster& cluster, uint32_t chip, const CoreCoord& virt, uint32_t link_l1) {
    zero_l1(cluster, chip, virt, link_l1, offsetof(kernel_profiler::LinkSyncL1, ring));
}

}  // namespace tt::tt_metal::streaming_profiler::link_sync
