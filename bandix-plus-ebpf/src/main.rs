#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_SHOT, TC_ACT_UNSPEC},
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use bandix_plus_common::{
    DeviceGlobalLimitKey, DeviceIfaceLimitKey, DeviceTrafficKey, IfaceLimitKey, InterfaceTrafficKey, Ipv4TrafficKey,
    Ipv6TrafficKey, IpVersion, RateBucketValue, RateLimitValue, TrafficDirection, TrafficValue,
};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_PPP_SES: u16 = 0x8864;
const PPP_PROTO_IP: u16 = 0x0021;
const PPP_PROTO_IPV6: u16 = 0x0057;
const MAX_ENTRIES: u32 = 65536;
const BPS_DENOM_NS: u64 = 1_000_000_000;
const BURST_WINDOW_NS: u64 = 100_000_000; // 100ms burst cap
const INIT_WINDOW_NS: u64 = 50_000_000; // 50ms initial tokens
const RATE_SAFETY_PERCENT: u64 = 95; // reduce observed overshoot

fn sat_mul_u64(a: u64, b: u64) -> u64 {
    if a == 0 || b == 0 {
        return 0;
    }
    if a > u64::MAX / b { u64::MAX } else { a * b }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PppoeSessionHdr {
    ver_type: u8,
    code: u8,
    session_id: u16,
    length: u16,
    ppp_proto: u16,
}

#[derive(Clone, Copy)]
struct PacketMeta {
    ip_version: u8,
    mac: Option<[u8; 6]>,
    src_ip: Option<[u8; 16]>,
    dst_ip: Option<[u8; 16]>,
}

#[classifier]
pub fn bandix_plus_ingress(ctx: TcContext) -> i32 {
    match try_bandix_plus(ctx, TrafficDirection::Ingress as u8) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[classifier]
pub fn bandix_plus_egress(ctx: TcContext) -> i32 {
    match try_bandix_plus(ctx, TrafficDirection::Egress as u8) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map]
static IFACE_TRAFFIC_STATS: HashMap<InterfaceTrafficKey, TrafficValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static DEVICE_TRAFFIC_STATS: HashMap<DeviceTrafficKey, TrafficValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static IPV4_TRAFFIC_STATS: HashMap<Ipv4TrafficKey, TrafficValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static IPV6_TRAFFIC_STATS: HashMap<Ipv6TrafficKey, TrafficValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static DEVICE_LIMIT_GLOBAL: HashMap<DeviceGlobalLimitKey, RateLimitValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static DEVICE_LIMIT_IFACE: HashMap<DeviceIfaceLimitKey, RateLimitValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static DEVICE_RATE_BUCKETS: HashMap<DeviceIfaceLimitKey, RateBucketValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static IFACE_LIMIT: HashMap<IfaceLimitKey, RateLimitValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static IFACE_RATE_BUCKETS: HashMap<InterfaceTrafficKey, RateBucketValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);

fn try_bandix_plus(ctx: TcContext, direction: u8) -> Result<i32, i32> {
    let meta = match resolve_packet_meta(&ctx, direction) {
        Some(v) => v,
        None => return Ok(TC_ACT_UNSPEC),
    };

    let ifindex = unsafe { (*ctx.skb.skb).ifindex } as u32;
    let pkt_len = unsafe { (*ctx.skb.skb).len } as u64;

    let iface_key = InterfaceTrafficKey {
        ifindex,
        ip_version: meta.ip_version,
        direction,
        _pad: [0; 2],
    };
    bump_iface_counter(&iface_key, pkt_len);

    if let Some(mac) = meta.mac {
        let device_key = DeviceTrafficKey {
            ifindex,
            mac,
            ip_version: meta.ip_version,
            direction,
        };
        bump_device_counter(&device_key, pkt_len);
    }

    if let Some(src_ip) = meta.src_ip {
        if meta.ip_version == IpVersion::V4 as u8 {
            let key = Ipv4TrafficKey {
                ifindex,
                ip: [src_ip[0], src_ip[1], src_ip[2], src_ip[3]],
                ip_version: meta.ip_version,
                direction,
                _pad: [0; 2],
            };
            bump_ipv4_counter(&key, pkt_len);
        } else {
            let key = Ipv6TrafficKey {
                ifindex,
                ip: src_ip,
                ip_version: meta.ip_version,
                direction,
            };
            bump_ipv6_counter(&key, pkt_len);
        }
    }

    if let Some(dst_ip) = meta.dst_ip {
        if meta.ip_version == IpVersion::V4 as u8 {
            let key = Ipv4TrafficKey {
                ifindex,
                ip: [dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]],
                ip_version: meta.ip_version,
                direction,
                _pad: [0; 2],
            };
            bump_ipv4_counter(&key, pkt_len);
        } else {
            let key = Ipv6TrafficKey {
                ifindex,
                ip: dst_ip,
                ip_version: meta.ip_version,
                direction,
            };
            bump_ipv6_counter(&key, pkt_len);
        }
    }

    if should_drop_by_rate_limit(ifindex, meta.mac, meta.ip_version, direction, pkt_len) {
        return Ok(TC_ACT_SHOT);
    }

    Ok(TC_ACT_UNSPEC)
}

fn resolve_packet_meta(ctx: &TcContext, direction: u8) -> Option<PacketMeta> {
    let eth_proto = ctx.load::<u16>(12).ok()?;
    let eth_proto = u16::from_be(eth_proto);
    if let Some(ip_version) = resolve_ip_version_from_eth(ctx, eth_proto) {
        let mac = match direction {
            x if x == TrafficDirection::Ingress as u8 => ctx.load::<[u8; 6]>(6).ok(),
            _ => ctx.load::<[u8; 6]>(0).ok(),
        };
        let src_ip = if eth_proto == ETH_P_IP {
            resolve_ipv4_only(ctx, 14 + 12)
        } else if eth_proto == ETH_P_IPV6 {
            resolve_ipv6_only(ctx, 14 + 8)
        } else {
            None
        };
        let dst_ip = if eth_proto == ETH_P_IP {
            resolve_ipv4_only(ctx, 14 + 16)
        } else if eth_proto == ETH_P_IPV6 {
            resolve_ipv6_only(ctx, 14 + 24)
        } else {
            None
        };
        return Some(PacketMeta { ip_version, mac, src_ip, dst_ip });
    }

    // L3-style interfaces (e.g. ppp/tun/wireguard) may have no Ethernet header.
    if let Some(ip_version) = resolve_ip_version_from_l3(ctx, 0) {
        let src_ip = if ip_version == IpVersion::V4 as u8 {
            resolve_ipv4_only(ctx, 12)
        } else {
            resolve_ipv6_only(ctx, 8)
        };
        let dst_ip = if ip_version == IpVersion::V4 as u8 {
            resolve_ipv4_only(ctx, 16)
        } else {
            resolve_ipv6_only(ctx, 24)
        };
        return Some(PacketMeta { ip_version, mac: None, src_ip, dst_ip });
    }
    if let Some(ip_version) = resolve_ip_version_from_ppp(ctx) {
        let src_ip = if ip_version == IpVersion::V4 as u8 {
            resolve_ipv4_only(ctx, 2 + 12)
        } else {
            resolve_ipv6_only(ctx, 2 + 8)
        };
        let dst_ip = if ip_version == IpVersion::V4 as u8 {
            resolve_ipv4_only(ctx, 2 + 16)
        } else {
            resolve_ipv6_only(ctx, 2 + 24)
        };
        return Some(PacketMeta { ip_version, mac: None, src_ip, dst_ip });
    }
    None
}

fn resolve_ip_version_from_eth(ctx: &TcContext, eth_proto: u16) -> Option<u8> {
    match eth_proto {
        ETH_P_IP => Some(IpVersion::V4 as u8),
        ETH_P_IPV6 => Some(IpVersion::V6 as u8),
        ETH_P_PPP_SES => {
            let ppp_proto = ctx.load::<u16>(14 + 4).ok()?;
            let ppp_proto = u16::from_be(ppp_proto);
            match ppp_proto {
                PPP_PROTO_IP => Some(IpVersion::V4 as u8),
                PPP_PROTO_IPV6 => Some(IpVersion::V6 as u8),
                _ => None,
            }
        }
        _ => None,
    }
}

fn resolve_ip_version_from_l3(ctx: &TcContext, offset: usize) -> Option<u8> {
    let first2 = ctx.load::<u16>(offset).ok()?;
    let first2 = u16::from_be(first2);
    let version = (first2 >> 12) as u8;
    match version {
        4 => Some(IpVersion::V4 as u8),
        6 => Some(IpVersion::V6 as u8),
        _ => None,
    }
}

fn resolve_ip_version_from_ppp(ctx: &TcContext) -> Option<u8> {
    let proto = ctx.load::<u16>(0).ok()?;
    let proto = u16::from_be(proto);
    match proto {
        PPP_PROTO_IP => return Some(IpVersion::V4 as u8),
        PPP_PROTO_IPV6 => return Some(IpVersion::V6 as u8),
        _ => {}
    }
    // Protocol field + L3 payload.
    resolve_ip_version_from_l3(ctx, 2)
}

fn bump_iface_counter(key: &InterfaceTrafficKey, bytes: u64) {
    unsafe {
        if let Some(value) = IFACE_TRAFFIC_STATS.get_ptr_mut(key) {
            (*value).packets = (*value).packets.saturating_add(1);
            (*value).bytes = (*value).bytes.saturating_add(bytes);
            return;
        }

        let value = TrafficValue { packets: 1, bytes };
        let _ = IFACE_TRAFFIC_STATS.insert(key, &value, 0);
    }
}

fn bump_device_counter(key: &DeviceTrafficKey, bytes: u64) {
    unsafe {
        if let Some(value) = DEVICE_TRAFFIC_STATS.get_ptr_mut(key) {
            (*value).packets = (*value).packets.saturating_add(1);
            (*value).bytes = (*value).bytes.saturating_add(bytes);
            return;
        }

        let value = TrafficValue { packets: 1, bytes };
        let _ = DEVICE_TRAFFIC_STATS.insert(key, &value, 0);
    }
}

fn bump_ipv4_counter(key: &Ipv4TrafficKey, bytes: u64) {
    unsafe {
        if let Some(value) = IPV4_TRAFFIC_STATS.get_ptr_mut(key) {
            (*value).packets = (*value).packets.saturating_add(1);
            (*value).bytes = (*value).bytes.saturating_add(bytes);
            return;
        }

        let value = TrafficValue { packets: 1, bytes };
        let _ = IPV4_TRAFFIC_STATS.insert(key, &value, 0);
    }
}

fn bump_ipv6_counter(key: &Ipv6TrafficKey, bytes: u64) {
    unsafe {
        if let Some(value) = IPV6_TRAFFIC_STATS.get_ptr_mut(key) {
            (*value).packets = (*value).packets.saturating_add(1);
            (*value).bytes = (*value).bytes.saturating_add(bytes);
            return;
        }

        let value = TrafficValue { packets: 1, bytes };
        let _ = IPV6_TRAFFIC_STATS.insert(key, &value, 0);
    }
}

fn resolve_ipv4_only(ctx: &TcContext, offset: usize) -> Option<[u8; 16]> {
    let bytes = ctx.load::<[u8; 4]>(offset).ok()?;
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&bytes);
    Some(out)
}

fn resolve_ipv6_only(ctx: &TcContext, offset: usize) -> Option<[u8; 16]> {
    ctx.load::<[u8; 16]>(offset).ok()
}

fn should_drop_by_rate_limit(ifindex: u32, mac: Option<[u8; 6]>, ip_version: u8, direction: u8, pkt_len: u64) -> bool {
    let iface_only_key = IfaceLimitKey { ifindex };

    if let Some(limit) = unsafe { IFACE_LIMIT.get(&iface_only_key) } {
        let raw_budget = project_budget(limit, ip_version, direction);
        if raw_budget > 0 && consume_iface_bucket(ifindex, ip_version, direction, raw_budget, pkt_len) {
            return true;
        }
    }

    let Some(mac) = mac else {
        return false;
    };
    let iface_key = DeviceIfaceLimitKey {
        ifindex,
        mac,
        _pad: [0; 2],
    };
    let global_key = DeviceGlobalLimitKey { mac, _pad: [0; 2] };

    let mut device_limit: Option<RateLimitValue> = None;
    unsafe {
        if let Some(v) = DEVICE_LIMIT_GLOBAL.get(&global_key) {
            device_limit = Some(*v);
        }
        if let Some(v) = DEVICE_LIMIT_IFACE.get(&iface_key) {
            device_limit = Some(match device_limit {
                Some(current) => stricter_limit_value(current, *v),
                None => *v,
            });
        }
    }

    let Some(limit) = device_limit else {
        return false;
    };
    let raw_budget = project_budget(&limit, ip_version, direction);
    if raw_budget == 0 {
        return false;
    }
    consume_device_bucket(iface_key, limit, ip_version, direction, raw_budget, pkt_len)
}

fn project_budget(limit: &RateLimitValue, ip_version: u8, direction: u8) -> u64 {
    match (ip_version, direction) {
        (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Ingress as u8 => limit.up_v4_bps,
        (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Ingress as u8 => limit.up_v6_bps,
        (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Egress as u8 => limit.down_v4_bps,
        (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Egress as u8 => limit.down_v6_bps,
        _ => 0,
    }
}

fn stricter_limit_value(a: RateLimitValue, b: RateLimitValue) -> RateLimitValue {
    RateLimitValue {
        down_v4_bps: stricter_field(a.down_v4_bps, b.down_v4_bps),
        down_v6_bps: stricter_field(a.down_v6_bps, b.down_v6_bps),
        up_v4_bps: stricter_field(a.up_v4_bps, b.up_v4_bps),
        up_v6_bps: stricter_field(a.up_v6_bps, b.up_v6_bps),
    }
}

fn stricter_field(a: u64, b: u64) -> u64 {
    if a == 0 {
        return b;
    }
    if b == 0 {
        return a;
    }
    if a < b { a } else { b }
}

fn consume_iface_bucket(ifindex: u32, ip_version: u8, direction: u8, raw_budget: u64, pkt_len: u64) -> bool {
    let key = InterfaceTrafficKey {
        ifindex,
        ip_version,
        direction,
        _pad: [0; 2],
    };
    let budget = effective_budget(raw_budget);
    let now = unsafe { bpf_ktime_get_ns() as u64 };
    unsafe {
        if let Some(bucket) = IFACE_RATE_BUCKETS.get_ptr_mut(&key) {
            let (tokens, last_refill_ns) = match (ip_version, direction) {
                (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Ingress as u8 => {
                    (&mut (*bucket).up_v4_tokens, &mut (*bucket).up_v4_last_refill_ns)
                }
                (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Ingress as u8 => {
                    (&mut (*bucket).up_v6_tokens, &mut (*bucket).up_v6_last_refill_ns)
                }
                (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Egress as u8 => {
                    (&mut (*bucket).down_v4_tokens, &mut (*bucket).down_v4_last_refill_ns)
                }
                _ => (&mut (*bucket).down_v6_tokens, &mut (*bucket).down_v6_last_refill_ns),
            };
            refill_bucket(tokens, last_refill_ns, budget, now, pkt_len);
            if *tokens >= pkt_len {
                *tokens = tokens.saturating_sub(pkt_len);
                false
            } else {
                true
            }
        } else {
            let mut bucket = RateBucketValue {
                down_v4_tokens: 0,
                down_v6_tokens: 0,
                up_v4_tokens: 0,
                up_v6_tokens: 0,
                down_v4_last_refill_ns: now,
                down_v6_last_refill_ns: now,
                up_v4_last_refill_ns: now,
                up_v6_last_refill_ns: now,
            };
            let tokens = match (ip_version, direction) {
                (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Ingress as u8 => &mut bucket.up_v4_tokens,
                (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Ingress as u8 => &mut bucket.up_v6_tokens,
                (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Egress as u8 => &mut bucket.down_v4_tokens,
                _ => &mut bucket.down_v6_tokens,
            };
            *tokens = tokens_for_window(budget, INIT_WINDOW_NS);
            if *tokens >= pkt_len {
                *tokens = tokens.saturating_sub(pkt_len);
                let _ = IFACE_RATE_BUCKETS.insert(&key, &bucket, 0);
                false
            } else {
                let _ = IFACE_RATE_BUCKETS.insert(&key, &bucket, 0);
                true
            }
        }
    }
}

fn consume_device_bucket(
    iface_key: DeviceIfaceLimitKey,
    limit: RateLimitValue,
    ip_version: u8,
    direction: u8,
    raw_budget: u64,
    pkt_len: u64,
) -> bool {
    let budget = effective_budget(raw_budget);
    let now = unsafe { bpf_ktime_get_ns() as u64 };
    unsafe {
        if let Some(bucket) = DEVICE_RATE_BUCKETS.get_ptr_mut(&iface_key) {
            let (tokens, last_refill_ns) = match (ip_version, direction) {
                (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Ingress as u8 => {
                    (&mut (*bucket).up_v4_tokens, &mut (*bucket).up_v4_last_refill_ns)
                }
                (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Ingress as u8 => {
                    (&mut (*bucket).up_v6_tokens, &mut (*bucket).up_v6_last_refill_ns)
                }
                (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Egress as u8 => {
                    (&mut (*bucket).down_v4_tokens, &mut (*bucket).down_v4_last_refill_ns)
                }
                _ => (&mut (*bucket).down_v6_tokens, &mut (*bucket).down_v6_last_refill_ns),
            };
            refill_bucket(tokens, last_refill_ns, budget, now, pkt_len);
            if *tokens >= pkt_len {
                *tokens = tokens.saturating_sub(pkt_len);
                false
            } else {
                true
            }
        } else {
            let mut bucket = RateBucketValue {
                down_v4_tokens: tokens_for_window(effective_budget(limit.down_v4_bps), INIT_WINDOW_NS),
                down_v6_tokens: tokens_for_window(effective_budget(limit.down_v6_bps), INIT_WINDOW_NS),
                up_v4_tokens: tokens_for_window(effective_budget(limit.up_v4_bps), INIT_WINDOW_NS),
                up_v6_tokens: tokens_for_window(effective_budget(limit.up_v6_bps), INIT_WINDOW_NS),
                down_v4_last_refill_ns: now,
                down_v6_last_refill_ns: now,
                up_v4_last_refill_ns: now,
                up_v6_last_refill_ns: now,
            };
            let tokens = match (ip_version, direction) {
                (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Ingress as u8 => &mut bucket.up_v4_tokens,
                (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Ingress as u8 => &mut bucket.up_v6_tokens,
                (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Egress as u8 => &mut bucket.down_v4_tokens,
                _ => &mut bucket.down_v6_tokens,
            };
            if *tokens >= pkt_len {
                *tokens = tokens.saturating_sub(pkt_len);
                let _ = DEVICE_RATE_BUCKETS.insert(&iface_key, &bucket, 0);
                false
            } else {
                let _ = DEVICE_RATE_BUCKETS.insert(&iface_key, &bucket, 0);
                true
            }
        }
    }
}

fn refill_bucket(tokens: *mut u64, last_refill_ns: *mut u64, budget_bps: u64, now_ns: u64, pkt_len: u64) {
    unsafe {
        let last = *last_refill_ns;
        if now_ns <= last {
            return;
        }

        let elapsed_ns = now_ns - last;
        let capped_elapsed_ns = if elapsed_ns > BPS_DENOM_NS { BPS_DENOM_NS } else { elapsed_ns };
        if capped_elapsed_ns == 0 {
            return;
        }

        // Avoid u128 ops in eBPF (will emit unsupported helper builtins).
        let whole = budget_bps / BPS_DENOM_NS;
        let frac = budget_bps % BPS_DENOM_NS;
        let part1 = sat_mul_u64(whole, capped_elapsed_ns);
        let part2 = sat_mul_u64(frac, capped_elapsed_ns) / BPS_DENOM_NS;
        let refill = part1.saturating_add(part2);
        if refill == 0 {
            return;
        }

        let mut cap = tokens_for_window(budget_bps, BURST_WINDOW_NS);
        if cap < pkt_len {
            cap = pkt_len;
        }
        let next_tokens = (*tokens).saturating_add(refill);
        *tokens = if next_tokens > cap { cap } else { next_tokens };
        *last_refill_ns = now_ns;
    }
}

fn effective_budget(raw_budget: u64) -> u64 {
    if raw_budget == 0 {
        return 0;
    }
    let scaled = sat_mul_u64(raw_budget, RATE_SAFETY_PERCENT) / 100;
    if scaled == 0 { 1 } else { scaled }
}

fn tokens_for_window(budget_bps: u64, window_ns: u64) -> u64 {
    if budget_bps == 0 || window_ns == 0 {
        return 0;
    }
    let whole = budget_bps / BPS_DENOM_NS;
    let frac = budget_bps % BPS_DENOM_NS;
    sat_mul_u64(whole, window_ns).saturating_add(sat_mul_u64(frac, window_ns) / BPS_DENOM_NS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
