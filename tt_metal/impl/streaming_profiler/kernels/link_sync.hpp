// SPDX-FileCopyrightText: © 2026 Tenstorrent USA, Inc.
//
// SPDX-License-Identifier: Apache-2.0

// One end of a link's clock sync. Each round, the two ends exchange bursts of stamped frames, and the host solves the
// link's clock offset from their stamps. RouterEnd runs an end inside a fabric router's main loop.

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "hostdev/dev_msgs.h"
#include "hostdev/streaming_profiler_common.h"
#include "internal/ethernet/dataflow_api.h"
#include "internal/ethernet/eth_ptp.hpp"
#include "tt_metal/impl/streaming_profiler/kernels/eth_clock.hpp"

namespace link_sync {

static_assert(
    kernel_profiler::kEthRefclkHz == eth_ptp::kRefclkHz &&
    kernel_profiler::kRefclkTicksPerUpdate == eth_ptp::kRefclkTicksPerUpdate);

// A link's stamped frames use a TX queue and header row that nothing else uses. The firmware uses header rows 0 to 2
// (see eth_ptp.hpp). The fabric routers send on TX queue 0, and when a router runs on two ERISCs, its receiver uses
// queue 1.
constexpr uint32_t kLinkTxq = 2;
constexpr uint32_t kLinkHeaderRow = 3;
// The TCAM row and label are arbitrary.
constexpr uint32_t kLinkTcamRow = 63;
constexpr uint32_t kLinkLabel = 0x15;
// The rule matches this address's middle four bytes, which no firmware frame has (see eth_ptp.hpp).
constexpr uint64_t kStampFrameDestination = 0x02A5'A5A5'A5A5ull;
constexpr eth_ptp::RxTcamNonIpMatch kStampMatch =
    eth_ptp::rx_tcam_match_destination(kStampFrameDestination, 0x00FF'FFFF'FF00ull);
constexpr bool kSyncCheck = get_named_compile_time_arg_val("LINK_SYNC_CHECK") != 0;

constexpr uint32_t kTripsPerRound = 128;
constexpr uint32_t kBurstFrames = 4;
constexpr uint32_t kBurstsPerRound = kTripsPerRound / kBurstFrames;
constexpr uint32_t kFrameBytes = 32;
static_assert(kTripsPerRound % kBurstFrames == 0);

// The transmitter sends a frame with awaiting_echo set, and the receiver clears it and echoes the frame back.
// awaiting_echo is the frame's last word, so once it changes in L1, the rest of the frame has landed.
struct LinkFrame {
    eth_ptp::FrameStampSlot stamp;
    uint32_t round;
    uint32_t pad[2];
    uint32_t awaiting_echo;
};
static_assert(sizeof(LinkFrame) == kFrameBytes && kFrameBytes % 16 == 0);
static_assert(
    offsetof(kernel_profiler::LinkSyncL1, slots) == 0 &&
    kBurstFrames * kFrameBytes == sizeof(kernel_profiler::LinkSyncL1::slots));

// The sum is 64-bit because a round's 128 offsets from its first stamp can add up to more than 2^32 ns once the round
// spans about 34 ms, and on a loaded router a round can spread over tens of milliseconds.
struct StampSum {
    uint32_t count = 0;
    uint64_t first = 0;
    uint64_t sum_from_first = 0;
    FORCE_INLINE void reset() {
        count = 0;
        sum_from_first = 0;
    }
    FORCE_INLINE void add(uint64_t stamp) {
        if (count == 0) {
            first = stamp;
        }
        sum_from_first += stamp - first;
        count++;
    }
};

// Tracks the number of AICLK cycles per refclk update (four ticks), rounded to the nearest cycle, by re-reading the
// refclk every kRemeasureCycles. reference_wall is 64-bit because a link end's first frame can come minutes after
// start(), long enough for a 32-bit wall-clock difference to wrap.
struct UpdatePeriod {
    static constexpr uint32_t kRemeasureCycles = 1u << 20;
    static constexpr uint32_t kStartMeasureTicks = 1000;
    // remeasure() skips a longer span, so measure() never sees more than 32 bits of cycles. The router can go that long
    // without stepping during a fabric pause, and the period keeps its old value until the next remeasure.
    static constexpr uint32_t kMaxMeasureCycles = 1u << 31;
    uint64_t reference_wall = 0;
    uint32_t cycles_per_update = 0, reference_refclk = 0;
    void start() {
        const eth_ptp::ClocksLo first = eth_ptp::await_refclk_update();
        while (eth_ptp::kRefclkLo.read() - first.refclk < kStartMeasureTicks) {
        }
        const eth_ptp::ClocksLo edge = eth_ptp::await_refclk_update();
        cycles_per_update = measure(edge.wall - first.wall, edge.refclk - first.refclk);
        take_reference();
    }
    FORCE_INLINE void remeasure_if_due() {
        if (eth_ptp::kWallClockLo.read() - static_cast<uint32_t>(reference_wall) >= kRemeasureCycles) {
            remeasure();
        }
    }

private:
    static FORCE_INLINE uint32_t measure(uint32_t cycles, uint32_t refclk_ticks) {
        const uint32_t updates = refclk_ticks / eth_ptp::kRefclkTicksPerUpdate;
        return (cycles + updates / 2) / updates;
    }
    FORCE_INLINE void take_reference() {
        const eth_ptp::Instant now = eth_ptp::read_instant();
        reference_wall = now.wall;
        reference_refclk = static_cast<uint32_t>(now.refclk);
    }
    __attribute__((noinline)) void remeasure() {
        const uint64_t prev_wall = reference_wall;
        const uint32_t prev_refclk = reference_refclk;
        take_reference();
        if (reference_wall - prev_wall < kMaxMeasureCycles) {
            cycles_per_update = measure(reference_wall - prev_wall, reference_refclk - prev_refclk);
        }
    }
};

// Every member starts at zero, so an end has no .data for the firmware to copy. start() sets the nonzero ones.
struct EndBase {
    eth_ptp::TxHeaderRow<kLinkTxq, kLinkHeaderRow> header;
    eth_ptp::RxStampRule<kLinkTcamRow, kLinkLabel> rule;
    volatile kernel_profiler::LinkSyncL1* l1 = nullptr;
    uint32_t round = 0;
    UpdatePeriod period;
    uint32_t random_state = 0;
    StampSum egress, ingress;
    uint32_t ring_tail = 0;
    bool stopped = false;

    // The host zeroes the slots, ctl and done before the end starts, because a stale awaiting_echo would stall the link
    // for good.
    void start() {
        l1 = reinterpret_cast<volatile kernel_profiler::LinkSyncL1*>(
            get_named_compile_time_arg_val("LINK_SYNC_L1_ADDR"));
        // When the eth relay launches, it starts reading this end's ring at the tail it finds in this word.
        control_vector()[kernel_profiler::SPSC_LINK_SYNC_TAIL] = ring_tail;
        eth_ptp::restart_ptp_timer();
        rule.install(kStampMatch);
        header.install(kStampFrameDestination);
        // The queue stays armed until stop(), so the MAC stamps every frame and no stamp slot needs clearing.
        eth_ptp::txq_arm_in_frame(kLinkTxq);
        period.start();
        random_state = eth_ptp::kWallClockLo.read() | 1u;
    }
    void stop() {
        eth_ptp::txq_disarm(kLinkTxq);
        header.restore();
        rule.remove();
        l1->done = kernel_profiler::kResidentDoneWord;
        stopped = true;
    }

protected:
    // A burst's frame i uses slot i, at the same L1 address on both ends, so an echo lands on the frame it answers.
    FORCE_INLINE volatile LinkFrame& frame(uint32_t slot) const {
        return reinterpret_cast<volatile LinkFrame*>(l1->slots)[slot];
    }
    // Adds the burst's egress stamps, which its frames carry, and its ingress stamps, which are in the RX stamp FIFO.
    // The FIFO doesn't say which frame a stamp belongs to, so the two ends take turns. The transmitter only sends a
    // burst once the previous one has been fully echoed, and the receiver only takes a burst's stamps once all its
    // frames have arrived. A frame's stamp is in the FIFO before the frame itself is visible, and only the link's rule
    // records stamps. The FIFO therefore holds exactly this burst's stamps, in order, unless a frame was resent and
    // stamped twice, in which case the burst is dropped.
    __attribute__((noinline)) void take_burst() {
        if (!eth_ptp::rx_stamp_fifo::holds_exactly<kBurstFrames>()) {
            eth_ptp::rx_stamp_fifo::flush();
            return;
        }
#pragma GCC unroll 1
        for (uint32_t i = 0; i < kBurstFrames; i++) {
            egress.add(eth_ptp::frame_stamp_ns(frame(i).stamp));
            ingress.add(eth_ptp::rx_stamp_fifo::pop());
        }
    }
    // Waits a uniformly random number of cycles, up to one refclk update period, then sends the slot's frame, and
    // returns the number of frames sent. A stamp is its time rounded down to a whole tick. The random delay spans a
    // whole number of ticks, so the amount rounded off is uniform over a tick whatever the code's timing, and over a
    // round's frames it averages to half a tick at both ends, which cancels in the offset between them.
    __attribute__((noinline)) uint32_t send_dithered(uint32_t slot) {
        period.remeasure_if_due();
        const uint32_t cycles = eth_clock::draw(random_state, period.cycles_per_update);
        const uint32_t start = eth_ptp::kWallClockLo.read();
        while (eth_ptp::kWallClockLo.read() - start < cycles) {
        }
        // If the queue is busy, leave the frame for a later step. Waiting on a queue that a link-level resend keeps
        // busy would stop the router serving the fabric.
        if (internal_::eth_txq_is_busy(kLinkTxq)) {
            return 0;
        }
        const uint32_t word_addr = reinterpret_cast<uintptr_t>(&frame(slot)) >> 4;
        internal_::eth_send_packet_unsafe(kLinkTxq, word_addr, word_addr, kFrameBytes >> 4);
        return 1;
    }
    static FORCE_INLINE volatile uint32_t* control_vector() {
        return reinterpret_cast<volatile uint32_t*>(GET_MAILBOX_ADDRESS_DEV(profiler.control_vector));
    }
    // The host computes the average, because a 64-bit divide would pull a library routine into the router's code.
    __attribute__((noinline)) void record(const StampSum& sum, kernel_profiler::SyncRole role) {
        auto& slot = const_cast<kernel_profiler::SyncLinkRecord&>(
            l1->ring[ring_tail % kernel_profiler::kLinkSyncRingRecords].link);
        slot.meta = kernel_profiler::SyncMeta{.role = role, .kind = kernel_profiler::SyncKind::Link};
        slot.round = round;
        slot.first_ns = sum.first;
        slot.sum_from_first_ns = sum.sum_from_first;
        slot.count = sum.count;
        std::atomic_thread_fence(std::memory_order_release);
        control_vector()[kernel_profiler::SPSC_LINK_SYNC_TAIL] = ++ring_tail;
    }
    // A round with no stamps is not recorded. Neither is a round the ring has no room for, because an end never waits
    // for the eth relay to make room.
    __attribute__((noinline)) void close_round(
        kernel_profiler::SyncRole egress_role, kernel_profiler::SyncRole ingress_role) {
        if (egress.count != 0 &&
            ring_tail - control_vector()[kernel_profiler::SPSC_LINK_SYNC_HEAD] <=
                kernel_profiler::kLinkSyncRingRecords - kernel_profiler::kLinkSyncRecordsPerRound) {
            record(egress, egress_role);
            record(ingress, ingress_role);
        }
    }
    FORCE_INLINE void open_round(
        uint32_t next, kernel_profiler::SyncRole egress_role, kernel_profiler::SyncRole ingress_role) {
        close_round(egress_role, ingress_role);
        round = next;
        egress.reset();
        ingress.reset();
    }
};

struct TransmitterLink : EndBase {
    static constexpr uint32_t kBurstTicks =
        (kSyncCheck ? kernel_profiler::kLinkSyncCheckRoundTicks : kernel_profiler::kLinkSyncRoundTicks) /
        kBurstsPerRound;
    // next_burst_refclk keeps only the low word, since a burst is never scheduled more than kMaxLeadTicks ahead.
    static constexpr uint32_t kMaxLeadTicks = 1u << 20;
    static_assert(kBurstTicks < kMaxLeadTicks);
    uint32_t next_burst_refclk = 0;
    uint32_t frames_to_send = 0, round_bursts_sent = 0;

    void start() {
        EndBase::start();
        resync();
    }
    // next_burst_refclk is never more than kMaxLeadTicks ahead, so a burst that appears further ahead is overdue. After
    // a pause of any length this holds a burst back by at most kMaxLeadTicks, whereas testing the sign of the
    // difference could hold it back 2^31 ticks.
    FORCE_INLINE bool due() const {
        return frames_to_send != 0 || next_burst_refclk - eth_ptp::kRefclkLo.read() > kMaxLeadTicks;
    }
    FORCE_INLINE void serve() {
        if (frames_to_send != 0) {
            send_next();
            return;
        }
        invalidate_l1_cache();
        if (l1->ctl != kernel_profiler::LinkSyncCtl::Run) {
            round_bursts_sent = 0;
            resync();
            return;
        }
        if (!echoed()) {
            return;
        }
        burst();
    }

private:
    FORCE_INLINE void resync() { next_burst_refclk = eth_ptp::kRefclkLo.read() + kBurstTicks; }
    FORCE_INLINE bool echoed() const {
        for (uint32_t i = 0; i < kBurstFrames; i++) {
            if (frame(i).awaiting_echo) {
                return false;
            }
        }
        return true;
    }
    __attribute__((noinline)) void send_next() { frames_to_send -= send_dithered(kBurstFrames - frames_to_send); }
    __attribute__((noinline)) void burst() {
        const uint32_t now = eth_ptp::kRefclkLo.read();
        take_burst();
        if (round_bursts_sent == 0) {
            open_round(round + 1, kernel_profiler::SyncRole::ReturnEgress, kernel_profiler::SyncRole::ReturnIngress);
        }
        if (++round_bursts_sent == kBurstsPerRound) {
            round_bursts_sent = 0;
        }
#pragma GCC unroll 1
        for (uint32_t i = 0; i < kBurstFrames; i++) {
            volatile LinkFrame& sent = frame(i);
            sent.round = round;
            sent.awaiting_echo = 1;
        }
        frames_to_send = kBurstFrames;
        next_burst_refclk += kBurstTicks;
        if (next_burst_refclk - now > kMaxLeadTicks) {
            next_burst_refclk = now;
        }
    }
};

struct ReceiverLink : EndBase {
    uint32_t frames_taken = 0, frames_echoed = 0;

    FORCE_INLINE bool due() const {
        invalidate_l1_cache();
        return frames_echoed != frames_taken || frame(frames_taken).awaiting_echo != 0;
    }
    FORCE_INLINE void serve() {
        if (frames_echoed == frames_taken) {
            take();
        }
        echo();
    }

private:
    // Takes each frame as it arrives, and the burst's stamps with its last frame, before echoing it. The earlier
    // frames' slots still hold the transmitter's egress stamps, because the MAC writes an echo's stamp only on the wire
    // and the transmitter sends nothing more until every echo is in.
    __attribute__((noinline)) void take() {
        volatile LinkFrame& taken = frame(frames_taken);
        if (frames_taken == 0 && taken.round != round) {
            open_round(
                taken.round, kernel_profiler::SyncRole::ForwardEgress, kernel_profiler::SyncRole::ForwardIngress);
        }
        if (frames_taken == kBurstFrames - 1) {
            take_burst();
        }
        taken.awaiting_echo = 0;
        frames_taken++;
    }
    __attribute__((noinline)) void echo() {
        frames_echoed += send_dithered(frames_echoed);
        if (frames_echoed == kBurstFrames) {
            frames_taken = 0;
            frames_echoed = 0;
        }
    }
};

template <bool Transmitter>
using LinkEnd = std::conditional_t<Transmitter, TransmitterLink, ReceiverLink>;

// The router's only call into its link end is step(), from its main loop. Any call before or after that loop makes the
// compiler keep the loop's state in callee-saved registers, costing about 1% of fabric bandwidth, so the end starts in
// its first serve() and stops when the host writes Stop, like the standalone kernel. due() makes no calls and serve()
// is cold, because the router's bandwidth depends on how the compiler allocates registers around them in its main loop.
// Inlining either one, or letting due() start the end, costs up to 1% on some fabrics.
template <bool Transmitter>
struct RouterEnd {
    static inline LinkEnd<Transmitter> end;
    __attribute__((noinline)) static bool due() {
        if (end.l1 == nullptr) {
            return true;
        }
        return !end.stopped && (end.due() || end.l1->ctl == kernel_profiler::LinkSyncCtl::Stop);
    }
    __attribute__((noinline, cold)) static void serve() {
        if (end.l1 == nullptr) {
            end.start();
            return;
        }
        invalidate_l1_cache();
        if (end.l1->ctl == kernel_profiler::LinkSyncCtl::Stop) {
            end.stop();
            return;
        }
        end.serve();
    }
    // Calling due() only every 16th loop keeps the link's cost to the router small. The sync check runs rounds 10 times
    // as often, and at every 16th loop its bursts take longer than the time each one is given, so too few rounds
    // complete for the check. With the sync check the router steps every loop.
    static constexpr uint32_t kRouterStepLoops = kSyncCheck ? 1 : 16;
    static_assert((kRouterStepLoops & (kRouterStepLoops - 1)) == 0);
    static FORCE_INLINE void step(uint32_t iter) {
        if ((iter & (kRouterStepLoops - 1)) == 0 && due()) {
            serve();
        }
    }
};

struct NoLinkEnd {
    static void step(uint32_t) {}
};

constexpr auto kRouterRole =
    static_cast<kernel_profiler::LinkSyncRole>(get_named_compile_time_arg_val("LINK_SYNC_ROLE"));
using RouterHook = std::conditional_t<
    kRouterRole == kernel_profiler::LinkSyncRole::None,
    NoLinkEnd,
    RouterEnd<kRouterRole == kernel_profiler::LinkSyncRole::Transmitter>>;

}  // namespace link_sync
