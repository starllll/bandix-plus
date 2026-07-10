use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Duration;

use aya::Ebpf;
use aya::maps::HashMap as AyaHashMap;
use bandix_plus_common::{DeviceTrafficKey, InterfaceTrafficKey, IpTrafficKey, IpVersion, TrafficDirection, TrafficValue};
use chrono::{Local, TimeZone, Timelike};
use serde::{Deserialize, Serialize};

use crate::topology::TopologySnapshot;
use crate::utils::mac_utils;
use crate::utils::system_utils;
use crate::utils::time_utils;

// 定义聚合桶类型枚举
#[derive(Debug, Clone, Copy)]
pub enum AggregateBucket {
    Hourly,
    Daily,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterQuad {
    pub up_v4_bps: u64,
    pub down_v4_bps: u64,
    pub up_v6_bps: u64,
    pub down_v6_bps: u64,
    pub up_v4_bytes: u64,
    pub down_v4_bytes: u64,
    pub up_v6_bytes: u64,
    pub down_v6_bytes: u64,
}

impl Default for CounterQuad {
    fn default() -> Self {
        Self {
            up_v4_bps: 0,
            down_v4_bps: 0,
            up_v6_bps: 0,
            down_v6_bps: 0,
            up_v4_bytes: 0,
            down_v4_bytes: 0,
            up_v6_bytes: 0,
            down_v6_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedBucket {
    pub start_ts_ms: u64,
    pub end_ts_ms: u64,
    pub up_v4_bytes: u64,
    pub down_v4_bytes: u64,
    pub up_v6_bytes: u64,
    pub down_v6_bytes: u64,
    pub up_v4_bps_avg: u64,
    pub up_v4_bps_min: u64,
    pub up_v4_bps_max: u64,
    pub up_v4_bps_p95: u64,
    pub down_v4_bps_avg: u64,
    pub down_v4_bps_min: u64,
    pub down_v4_bps_max: u64,
    pub down_v4_bps_p95: u64,
    pub up_v6_bps_avg: u64,
    pub up_v6_bps_min: u64,
    pub up_v6_bps_max: u64,
    pub up_v6_bps_p95: u64,
    pub down_v6_bps_avg: u64,
    pub down_v6_bps_min: u64,
    pub down_v6_bps_max: u64,
    pub down_v6_bps_p95: u64,
}

impl Default for AggregatedBucket {
    fn default() -> Self {
        Self {
            start_ts_ms: 0,
            end_ts_ms: 0,
            up_v4_bytes: 0,
            down_v4_bytes: 0,
            up_v6_bytes: 0,
            down_v6_bytes: 0,
            up_v4_bps_avg: 0,
            up_v4_bps_min: 0,
            up_v4_bps_max: 0,
            up_v4_bps_p95: 0,
            down_v4_bps_avg: 0,
            down_v4_bps_min: 0,
            down_v4_bps_max: 0,
            down_v4_bps_p95: 0,
            up_v6_bps_avg: 0,
            up_v6_bps_min: 0,
            up_v6_bps_max: 0,
            up_v6_bps_p95: 0,
            down_v6_bps_avg: 0,
            down_v6_bps_min: 0,
            down_v6_bps_max: 0,
            down_v6_bps_p95: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryPoint {
    pub ts_ms: u64,
    pub metrics: CounterQuad,
    pub cumulative: CounterQuad,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySample {
    pub ts_ms: u64,
    pub up_v4_bps: u64,
    pub up_v6_bps: u64,
    pub down_v4_bps: u64,
    pub down_v6_bps: u64,
    pub up_v4_bytes: u64,
    pub up_v6_bytes: u64,
    pub down_v4_bytes: u64,
    pub down_v6_bytes: u64,
    pub up_v4_bytes_cumulative: u64,
    pub up_v6_bytes_cumulative: u64,
    pub down_v4_bytes_cumulative: u64,
    pub down_v6_bytes_cumulative: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceOverviewItem {
    pub ifindex: u32,
    pub ifname: String,
    pub zone: String,
    pub metrics: CounterQuad,
    pub cumulative: CounterQuad,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceListItem {
    pub ifindex: u32,
    pub logical_iface: String,
    pub subnet: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub mac: String,
    pub hostname: String,
    pub metrics: CounterQuad,
    pub cumulative: CounterQuad,
    pub online: bool,
    pub last_seen_ms: u64,
    pub neighbor_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpListItem {
    pub ifindex: u32,
    pub ifname: String,
    pub ip_addr: String,
    pub ip_version: u8,
    pub metrics: CounterQuad,
    pub cumulative: CounterQuad,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotData {
    pub timestamp_ms: u64,
    pub interfaces: Vec<InterfaceOverviewItem>,
    pub devices: Vec<DeviceListItem>,
    pub ips: Vec<IpListItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSeriesKey {
    pub ifindex: u32,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpSeriesKey {
    pub ifindex: u32,
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentHourPointState {
    pub ts_ms: u64,
    pub metrics: CounterQuad,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorRuntime {
    pub prev_iface_bytes: HashMap<InterfaceTrafficKey, u64>,
    pub prev_device_bytes: HashMap<DeviceTrafficKey, u64>,
    pub prev_ip_bytes: HashMap<IpTrafficKey, u64>,
    pub cumulative_iface: HashMap<u32, CounterQuad>,
    pub cumulative_device: HashMap<(u32, [u8; 6]), CounterQuad>,
    pub cumulative_ip: HashMap<(u32, String), CounterQuad>,
    pub last_snapshot_ms: Option<u64>,
    pub device_registry: DeviceRegistry,
    pub last_snapshot_histogram_state: HistogramHistory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistry {
    pub entries: HashMap<(u32, [u8; 6]), DeviceRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistryEntry {
    pub logical_iface: String,
    pub subnet: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub hostname: String,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramHistory {
    completed_iface: HashMap<u32, Vec<AggregatedBucket>>,
    current_hour_iface: HashMap<u32, (u64, Vec<CurrentHourPointState>)>,
    completed_device: HashMap<DeviceSeriesKey, Vec<AggregatedBucket>>,
    current_hour_device: HashMap<DeviceSeriesKey, (u64, Vec<CurrentHourPointState>)>,
    completed_ip: HashMap<IpSeriesKey, Vec<AggregatedBucket>>,
    current_hour_ip: HashMap<IpSeriesKey, (u64, Vec<CurrentHourPointState>)>,
}

impl HistogramHistory {
    pub fn query_aggregate(&self, ifindex: u32, mac_or_ip: Option<&str>, start_ms: u64, end_ms: u64, bucket: AggregateBucket) -> Vec<AggregatedBucket> {
        if let Some(mac_or_ip) = mac_or_ip {
            // 如果提供了MAC或IP，则查询设备或IP的统计数据
            if mac_or_ip.contains('.') || mac_or_ip.contains(':') {
                // 这是一个IP地址
                let key = IpSeriesKey { ifindex, ip: mac_or_ip.to_string() };
                match bucket {
                    AggregateBucket::Hourly => self.query_ip_hourly(&key, start_ms, end_ms),
                    AggregateBucket::Daily => self.query_ip_daily(&key, start_ms, end_ms),
                }
            } else {
                // 这是一个MAC地址
                let key = DeviceSeriesKey { ifindex, mac: mac_or_ip.to_string() };
                match bucket {
                    AggregateBucket::Hourly => self.query_device_hourly(&key, start_ms, end_ms),
                    AggregateBucket::Daily => self.query_device_daily(&key, start_ms, end_ms),
                }
            }
        } else {
            // 查询接口级别的统计数据
            match bucket {
                AggregateBucket::Hourly => self.query_iface_hourly(ifindex, start_ms, end_ms),
                AggregateBucket::Daily => self.query_iface_daily(ifindex, start_ms, end_ms),
            }
        }
    }

    fn query_iface_hourly(&self, ifindex: u32, start_ms: u64, end_ms: u64) -> Vec<AggregatedBucket> {
        let mut result = Vec::new();
        if let Some(completed) = self.completed_iface.get(&ifindex) {
            for b in completed {
                if b.start_ts_ms <= end_ms && b.end_ts_ms >= start_ms {
                    result.push(b.clone());
                }
            }
        }
        if let Some((cur_start, points)) = self.current_hour_iface.get(&ifindex) {
            let (start, end) = hourly_bucket_local(*cur_start);
            if start <= end_ms && end >= start_ms && !points.is_empty() {
                result.push(points_to_bucket(start, points));
            }
        }
        result.sort_by_key(|b| b.start_ts_ms);
        result
    }

    fn query_device_hourly(&self, key: &DeviceSeriesKey, start_ms: u64, end_ms: u64) -> Vec<AggregatedBucket> {
        let mut result = Vec::new();
        if let Some(completed) = self.completed_device.get(&key) {
            for b in completed {
                if b.start_ts_ms <= end_ms && b.end_ts_ms >= start_ms {
                    result.push(b.clone());
                }
            }
        }
        if let Some((cur_start, points)) = self.current_hour_device.get(&key) {
            let (start, end) = hourly_bucket_local(*cur_start);
            if start <= end_ms && end >= start_ms && !points.is_empty() {
                result.push(points_to_bucket(start, points));
            }
        }
        result.sort_by_key(|b| b.start_ts_ms);
        result
    }

    // 新增：查询IP小时数据
    fn query_ip_hourly(&self, key: &IpSeriesKey, start_ms: u64, end_ms: u64) -> Vec<AggregatedBucket> {
        let mut result = Vec::new();
        if let Some(completed) = self.completed_ip.get(&key) {
            for b in completed {
                if b.start_ts_ms <= end_ms && b.end_ts_ms >= start_ms {
                    result.push(b.clone());
                }
            }
        }
        if let Some((cur_start, points)) = self.current_hour_ip.get(&key) {
            let (start, end) = hourly_bucket_local(*cur_start);
            if start <= end_ms && end >= start_ms && !points.is_empty() {
                result.push(points_to_bucket(start, points));
            }
        }
        result.sort_by_key(|b| b.start_ts_ms);
        result
    }

    fn query_iface_daily(&self, ifindex: u32, start_ms: u64, end_ms: u64) -> Vec<AggregatedBucket> {
        let mut result = self.query_iface_hourly(ifindex, start_ms, end_ms);
        result = merge_buckets_to_daily(result);
        result.retain(|b| b.start_ts_ms <= end_ms && b.end_ts_ms >= start_ms);
        result
    }

    fn query_device_daily(&self, key: &DeviceSeriesKey, start_ms: u64, end_ms: u64) -> Vec<AggregatedBucket> {
        let mut result = self.query_device_hourly(key, start_ms, end_ms);
        result = merge_buckets_to_daily(result);
        result.retain(|b| b.start_ts_ms <= end_ms && b.end_ts_ms >= start_ms);
        result
    }

    // 新增：查询IP每日数据
    fn query_ip_daily(&self, key: &IpSeriesKey, start_ms: u64, end_ms: u64) -> Vec<AggregatedBucket> {
        let mut result = self.query_ip_hourly(key, start_ms, end_ms);
        result = merge_buckets_to_daily(result);
        result.retain(|b| b.start_ts_ms <= end_ms && b.end_ts_ms >= start_ms);
        result
    }

    pub fn cumulative_from_all(&self) -> (HashMap<u32, CounterQuad>, HashMap<(u32, [u8; 6]), CounterQuad>, HashMap<(u32, String), CounterQuad>) {
        let (iface, device, ip) = self.cumulative_from_completed();
        let mut all_iface = iface;
        let mut all_device = device;
        let mut all_ip = ip;

        // 收集当前小时的所有接口数据
        for (ifindex, (_hour_start, points)) in &self.current_hour_iface {
            let mut total = CounterQuad::default();
            for p in points {
                add_quad(&mut total, &p.cumulative);
            }
            *all_iface.entry(*ifindex).or_default() = total;
        }

        // 收集当前小时的所有设备数据
        for (key, (_hour_start, points)) in &self.current_hour_device {
            let mut total = CounterQuad::default();
            for p in points {
                add_quad(&mut total, &p.cumulative);
            }
            *all_device.entry((key.ifindex, mac_utils::from_str(&key.mac).unwrap_or([0; 6]))).or_default() = total;
        }

        // 新增：收集当前小时的所有IP数据
        for (key, (_hour_start, points)) in &self.current_hour_ip {
            let mut total = CounterQuad::default();
            for p in points {
                add_quad(&mut total, &p.cumulative);
            }
            *all_ip.entry((key.ifindex, key.ip.clone())).or_default() = total;
        }

        (all_iface, all_device, all_ip)
    }

    pub fn cumulative_from_completed(&self) -> (HashMap<u32, CounterQuad>, HashMap<(u32, [u8; 6]), CounterQuad>, HashMap<(u32, String), CounterQuad>) {
        let mut iface = HashMap::new();
        let mut device = HashMap::new();
        let mut ip = HashMap::new();

        for (ifindex, buckets) in &self.completed_iface {
            let mut total = CounterQuad::default();
            for bucket in buckets {
                add_bucket_bytes(&mut total, bucket);
            }
            iface.insert(*ifindex, total);
        }

        for (key, buckets) in &self.completed_device {
            let mut total = CounterQuad::default();
            for bucket in buckets {
                add_bucket_bytes(&mut total, bucket);
            }
            device.insert((key.ifindex, mac_utils::from_str(&key.mac).unwrap_or([0; 6])), total);
        }

        // 新增：从已完成的IP桶中累积数据
        for (key, buckets) in &self.completed_ip {
            let mut total = CounterQuad::default();
            for bucket in buckets {
                add_bucket_bytes(&mut total, bucket);
            }
            ip.insert((key.ifindex, key.ip.clone()), total);
        }

        (iface, device, ip)
    }

    pub fn restore_iface_bucket(&mut self, ifindex: u32, bucket: AggregatedBucket) {
        self.completed_iface.entry(ifindex).or_default().push(bucket);
    }

    pub fn restore_device_bucket(&mut self, ifindex: u32, mac: String, bucket: AggregatedBucket) {
        let key = DeviceSeriesKey { ifindex, mac };
        self.completed_device.entry(key).or_default().push(bucket);
    }

    // 新增：恢复IP桶数据
    pub fn restore_ip_bucket(&mut self, ifindex: u32, ip: String, bucket: AggregatedBucket) {
        let key = IpSeriesKey { ifindex, ip };
        self.completed_ip.entry(key).or_default().push(bucket);
    }

    pub fn restore_current_hour_iface_state(
        &mut self,
        ifindex: u32,
        hour_start_ts_ms: u64,
        points: Vec<CurrentHourPointState>,
        now_ms: u64,
    ) {
        let (expected_start, expected_end) = hourly_bucket_local(now_ms);
        if hour_start_ts_ms == expected_start {
            self.current_hour_iface.insert(ifindex, (hour_start_ts_ms, points));
        }
    }

    pub fn restore_current_hour_device_state(
        &mut self,
        ifindex: u32,
        mac: String,
        hour_start_ts_ms: u64,
        points: Vec<CurrentHourPointState>,
        now_ms: u64,
    ) {
        let (expected_start, expected_end) = hourly_bucket_local(now_ms);
        let key = DeviceSeriesKey { ifindex, mac };
        if hour_start_ts_ms == expected_start {
            self.current_hour_device.insert(key, (hour_start_ts_ms, points));
        }
    }

    // 新增：恢复IP当前小时状态
    pub fn restore_current_hour_ip_state(
        &mut self,
        ifindex: u32,
        ip: String,
        hour_start_ts_ms: u64,
        points: Vec<CurrentHourPointState>,
        now_ms: u64,
    ) {
        let (expected_start, expected_end) = hourly_bucket_local(now_ms);
        let key = IpSeriesKey { ifindex, ip };
        if hour_start_ts_ms == expected_start {
            self.current_hour_ip.insert(key, (hour_start_ts_ms, points));
        }
    }

    pub fn export_current_hour_state(&self) -> ExportedCurrentHourState {
        ExportedCurrentHourState {
            iface: self
                .current_hour_iface
                .iter()
                .map(|(ifindex, (hour_start, points))| ExportedCurrentHourIfaceState {
                    ifindex: *ifindex,
                    hour_start_ts_ms: *hour_start,
                    points: points.clone(),
                })
                .collect(),
            device: self
                .current_hour_device
                .iter()
                .map(|(key, (hour_start, points))| ExportedCurrentHourDeviceState {
                    ifindex: key.ifindex,
                    mac: key.mac.clone(),
                    hour_start_ts_ms: *hour_start,
                    points: points.clone(),
                })
                .collect(),
            // 新增：导出IP当前小时状态
            ip: self
                .current_hour_ip
                .iter()
                .map(|(key, (hour_start, points))| ExportedCurrentHourIpState {
                    ifindex: key.ifindex,
                    ip: key.ip.clone(),
                    hour_start_ts_ms: *hour_start,
                    points: points.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Default)]
struct BucketAccum {
    start_ts_ms: u64,
    end_ts_ms: u64,
    up_v4_bytes: u64,
    down_v4_bytes: u64,
    up_v6_bytes: u64,
    down_v6_bytes: u64,
    up_v4_bps: Vec<u64>,
    down_v4_bps: Vec<u64>,
    up_v6_bps: Vec<u64>,
    down_v6_bps: Vec<u64>,
}

fn merge_buckets_to_daily(buckets: Vec<AggregatedBucket>) -> Vec<AggregatedBucket> {
    if buckets.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut current_day_buckets: Vec<AggregatedBucket> = Vec::new();
    let mut current_day_start = daily_bucket_local(buckets[0].start_ts_ms).0;

    for bucket in buckets {
        let (day_start, _) = daily_bucket_local(bucket.start_ts_ms);
        if day_start == current_day_start {
            current_day_buckets.push(bucket);
        } else {
            if !current_day_buckets.is_empty() {
                result.push(merge_buckets_same_day(&current_day_buckets));
            }
            current_day_buckets.clear();
            current_day_buckets.push(bucket);
            current_day_start = day_start;
        }
    }

    if !current_day_buckets.is_empty() {
        result.push(merge_buckets_same_day(&current_day_buckets));
    }

    result
}

fn merge_buckets_same_day(buckets: &[AggregatedBucket]) -> AggregatedBucket {
    if buckets.is_empty() {
        return AggregatedBucket::default();
    }

    let start_ts_ms = daily_bucket_local(buckets[0].start_ts_ms).0;
    let end_ts_ms = daily_bucket_local(buckets[0].start_ts_ms).1;

    let mut accum = BucketAccum::default();
    accum.start_ts_ms = start_ts_ms;
    accum.end_ts_ms = end_ts_ms;

    for bucket in buckets {
        accum.up_v4_bytes = accum.up_v4_bytes.saturating_add(bucket.up_v4_bytes);
        accum.down_v4_bytes = accum.down_v4_bytes.saturating_add(bucket.down_v4_bytes);
        accum.up_v6_bytes = accum.up_v6_bytes.saturating_add(bucket.up_v6_bytes);
        accum.down_v6_bytes = accum.down_v6_bytes.saturating_add(bucket.down_v6_bytes);
        accum.up_v4_bps.extend(&bucket.up_v4_bps);
        accum.down_v4_bps.extend(&bucket.down_v4_bps);
        accum.up_v6_bps.extend(&bucket.up_v6_bps);
        accum.down_v6_bps.extend(&bucket.down_v6_bps);
    }

    bucket_accum_to_aggregated(accum)
}

fn points_to_bucket(start_ms: u64, points: &[HistoryPoint]) -> AggregatedBucket {
    let (_, end_ms) = hourly_bucket_local(start_ms);
    let mut accum = BucketAccum {
        start_ts_ms: start_ms,
        end_ts_ms: end_ms,
        ..Default::default()
    };
    for p in points {
        let m = &p.metrics;
        accum.up_v4_bytes = accum.up_v4_bytes.saturating_add(m.up_v4_bytes);
        accum.down_v4_bytes = accum.down_v4_bytes.saturating_add(m.down_v4_bytes);
        accum.up_v6_bytes = accum.up_v6_bytes.saturating_add(m.up_v6_bytes);
        accum.down_v6_bytes = accum.down_v6_bytes.saturating_add(m.down_v6_bytes);
        accum.up_v4_bps.push(m.up_v4_bps);
        accum.down_v4_bps.push(m.down_v4_bps);
        accum.up_v6_bps.push(m.up_v6_bps);
        accum.down_v6_bps.push(m.down_v6_bps);
    }
    bucket_accum_to_aggregated(accum)
}

fn normalize_current_hour_points(
    hour_start_ts_ms: u64,
    points: Vec<CurrentHourPointState>,
    now_ms: u64,
) -> Option<(u64, Vec<HistoryPoint>)> {
    let (expected_start, expected_end) = hourly_bucket_local(now_ms);
    if hour_start_ts_ms != expected_start {
        return None;
    }

    let mut restored: Vec<HistoryPoint> = points
        .into_iter()
        .filter(|p| p.ts_ms >= expected_start && p.ts_ms <= expected_end)
        .map(|p| HistoryPoint {
            ts_ms: p.ts_ms,
            metrics: p.metrics,
            cumulative: CounterQuad::default(),
        })
        .collect();
    restored.sort_by_key(|p| p.ts_ms);
    restored.dedup_by_key(|p| p.ts_ms);

    if restored.is_empty() {
        return None;
    }

    Some((hour_start_ts_ms, restored))
}

fn delta_bytes(current: u64, previous: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        // Counter may reset after map/program reload.
        current
    }
}

/// 从 eBPF map 读取接口级流量统计
fn read_iface_stats(ebpf: &mut Ebpf) -> anyhow::Result<HashMap<InterfaceTrafficKey, TrafficValue>> {
    let map = ebpf
        .map_mut("IFACE_TRAFFIC_STATS")
        .ok_or_else(|| anyhow::anyhow!("IFACE_TRAFFIC_STATS map not found"))?;
    let map: AyaHashMap<_, InterfaceTrafficKey, TrafficValue> = AyaHashMap::try_from(map)?;
    let mut result = HashMap::new();
    for entry in map.iter() {
        let (k, v) = entry?;
        result.insert(k, v);
    }
    Ok(result)
}

/// 从 eBPF map 读取设备级流量统计
fn read_device_stats(ebpf: &mut Ebpf) -> anyhow::Result<HashMap<DeviceTrafficKey, TrafficValue>> {
    let map = ebpf
        .map_mut("DEVICE_TRAFFIC_STATS")
        .ok_or_else(|| anyhow::anyhow!("DEVICE_TRAFFIC_STATS map not found"))?;
    let map: AyaHashMap<_, DeviceTrafficKey, TrafficValue> = AyaHashMap::try_from(map)?;
    let mut result = HashMap::new();
    for entry in map.iter() {
        let (k, v) = entry?;
        result.insert(k, v);
    }
    Ok(result)
}

// 新增：从 eBPF map 读取IP级流量统计
fn read_ip_stats(ebpf: &mut Ebpf) -> anyhow::Result<HashMap<IpTrafficKey, TrafficValue>> {
    use aya::maps::HashMap as AyaHashMap;
    use bandix_plus_common::{IpTrafficKey, TrafficValue};

    let mut ip_stats: HashMap<IpTrafficKey, TrafficValue> = HashMap::new();
    
    // 获取IP_TRAFFIC_STATS映射
    if let Ok(mut map) = AyaHashMap::<&mut aya::Ebpf, IpTrafficKey, TrafficValue>::try_from(ebpf.map_mut("IP_TRAFFIC_STATS")?) {
        for result in map.iter() {
            let (key, value) = result?;
            ip_stats.insert(key, value);
        }
    }
    
    Ok(ip_stats)
}

/// 根据 IP 版本和方向填充四元组，bytes 存增量
fn fill_quad(ip_version: u8, direction: u8, quad: &mut CounterQuad, delta_bytes: u64, sec: f64) {
    let delta_bps = ((delta_bytes as f64) * 8.0 / sec).round() as u64;
    match (ip_version, direction) {
        (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Ingress as u8 => {
            quad.up_v4_bps = quad.up_v4_bps.saturating_add(delta_bps);
            quad.up_v4_bytes = quad.up_v4_bytes.saturating_add(delta_bytes);
        }
        (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Egress as u8 => {
            quad.down_v4_bps = quad.down_v4_bps.saturating_add(delta_bps);
            quad.down_v4_bytes = quad.down_v4_bytes.saturating_add(delta_bytes);
        }
        (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Ingress as u8 => {
            quad.up_v6_bps = quad.up_v6_bps.saturating_add(delta_bps);
            quad.up_v6_bytes = quad.up_v6_bytes.saturating_add(delta_bytes);
        }
        (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Egress as u8 => {
            quad.down_v6_bps = quad.down_v6_bps.saturating_add(delta_bps);
            quad.down_v6_bytes = quad.down_v6_bytes.saturating_add(delta_bytes);
        }
        _ => {}
    }
}

// 新增：根据IP版本和方向填充四元组用于IP统计
fn fill_quad_for_ip(ip_version: u8, direction: u8, quad: &mut CounterQuad, delta_bytes: u64, sec: f64) {
    let delta_bps = ((delta_bytes as f64) * 8.0 / sec).round() as u64;
    match (ip_version, direction) {
        (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Ingress as u8 => {
            quad.up_v4_bps = quad.up_v4_bps.saturating_add(delta_bps);
            quad.up_v4_bytes = quad.up_v4_bytes.saturating_add(delta_bytes);
        }
        (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Egress as u8 => {
            quad.down_v4_bps = quad.down_v4_bps.saturating_add(delta_bps);
            quad.down_v4_bytes = quad.down_v4_bytes.saturating_add(delta_bytes);
        }
        (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Ingress as u8 => {
            quad.up_v6_bps = quad.up_v6_bps.saturating_add(delta_bps);
            quad.up_v6_bytes = quad.up_v6_bytes.saturating_add(delta_bytes);
        }
        (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Egress as u8 => {
            quad.down_v6_bps = quad.down_v6_bps.saturating_add(delta_bps);
            quad.down_v6_bytes = quad.down_v6_bytes.saturating_add(delta_bytes);
        }
        _ => {}
    }
}

// 将16字节数组转换为IP地址字符串
fn ip_to_string(ip_bytes: [u8; 16]) -> String {
    // 检查是否为IPv4映射的IPv6地址
    if ip_bytes[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        // IPv4地址
        format!("{}.{}.{}.{}", ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15])
    } else if ip_bytes[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] && (ip_bytes[12] != 0 || ip_bytes[13] != 0 || ip_bytes[14] != 0 || ip_bytes[15] != 0) {
        // 纯IPv4地址 (填充到16字节)
        format!("{}.{}.{}.{}", ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15])
    } else {
        // IPv6地址 - 以冒号十六进制格式显示
        format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
            ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7],
            ip_bytes[8], ip_bytes[9], ip_bytes[10], ip_bytes[11],
            ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]
        )
    }
}

// 新增：构建IP统计列表
fn build_ip_list(
    ip_stats: &HashMap<IpTrafficKey, TrafficValue>,
    runtime: &mut MonitorRuntime,
    monitor_ifaces: &HashSet<&str>,
    ifindex_by_name: &HashMap<&str, u32>,
    topology: &TopologySnapshot,
    sec: f64,
) -> Vec<IpListItem> {
    let mut ip_map: HashMap<String, IpListItem> = HashMap::new();

    for (k, v) in ip_stats {
        // 检查接口是否在监控范围内
        let iface_name = topology.by_ifindex(k.ifindex).map(|info| &info.name[..]).unwrap_or("");
        if !monitor_ifaces.is_empty() && !monitor_ifaces.contains(iface_name) {
            continue;
        }

        // 将IP地址转换回字符串形式
        let ip_str = if k.ip_version == 4 {
            // IPv4地址存储在前4个字节
            format!("{}.{}.{}.{}", k.ip_addr[0], k.ip_addr[1], k.ip_addr[2], k.ip_addr[3])
        } else {
            // IPv6地址使用全部16个字节
            format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                k.ip_addr[0], k.ip_addr[1], k.ip_addr[2], k.ip_addr[3],
                k.ip_addr[4], k.ip_addr[5], k.ip_addr[6], k.ip_addr[7],
                k.ip_addr[8], k.ip_addr[9], k.ip_addr[10], k.ip_addr[11],
                k.ip_addr[12], k.ip_addr[13], k.ip_addr[14], k.ip_addr[15]
            )
        };

        let key = (k.ifindex, ip_str.clone());
        let prev = runtime.prev_ip_bytes.get(&k).copied().unwrap_or(0);
        let delta = delta_bytes(v.bytes, prev);
        runtime.prev_ip_bytes.insert(*k, v.bytes);

        let mut metrics = CounterQuad::default();
        fill_quad(
            if k.ip_version == 4 { IpVersion::V4 } else { IpVersion::V6 },
            if k.direction == 1 { TrafficDirection::Ingress } else { TrafficDirection::Egress },
            &mut metrics,
            delta,
            sec,
        );

        let cum = runtime.cumulative_ip.entry(key.clone()).or_default();
        add_quad(cum, &metrics);

        let ip_item = IpListItem {
            ifindex: k.ifindex,
            ifname: iface_name.to_string(),
            ip_addr: ip_str,
            ip_version: k.ip_version,
            metrics,
            cumulative: *cum,
        };

        ip_map.insert(format!("{}-{}", k.ifindex, ip_str), ip_item);
    }

    ip_map.into_values().collect()
}

pub fn build_snapshot(
    ebpf: &mut Ebpf,
    runtime: &mut MonitorRuntime,
    topology: &TopologySnapshot,
    monitor_ifaces: &HashSet<&str>,
    now_ms: u64,
) -> anyhow::Result<SnapshotData> {
    let sec = if let Some(prev) = runtime.last_snapshot_ms {
        ((now_ms - prev) as f64) / 1000.0
    } else {
        1.0
    };

    let iface_stats = read_iface_stats(ebpf)?;
    let device_stats = read_device_stats(ebpf)?;
    // 新增：读取IP统计
    let ip_stats = read_ip_stats(ebpf)?;

    let mut interfaces = Vec::new();
    let mut ifindex_by_name = HashMap::new();
    for iface in topology.interfaces() {
        ifindex_by_name.insert(iface.name.as_str(), iface.ifindex);
        if !monitor_ifaces.is_empty() && !monitor_ifaces.contains(iface.name.as_str()) {
            continue;
        }
        let mut metrics = CounterQuad::default();
        for (k, v) in &iface_stats {
            if k.ifindex != iface.ifindex {
                continue;
            }
            let prev = runtime.prev_iface_bytes.get(k).copied().unwrap_or(0);
            let delta = delta_bytes(v.bytes, prev);
            runtime.prev_iface_bytes.insert(*k, v.bytes);
            fill_quad(k.ip_version, k.direction, &mut metrics, delta, sec);
        }
        let cum = runtime.cumulative_iface.entry(iface.ifindex).or_default();
        add_quad(cum, &metrics);
        interfaces.push(InterfaceOverviewItem {
            ifindex: iface.ifindex,
            ifname: iface.name.clone(),
            zone: format!("{:?}", iface.zone).to_ascii_lowercase(),
            metrics,
            cumulative: *cum,
        });
    }

    let subnet_map = system_utils::list_interface_subnets().unwrap_or_default();
    let filtered_neighbors = system_utils::list_neighbors_filtered(monitor_ifaces.iter().map(|s| s.to_string()).collect(), &subnet_map).unwrap_or_default();
    let hostname_by_mac = system_utils::list_hostname_by_mac();

    let mut dev_mac_to_ips: HashMap<(String, [u8; 6]), (Vec<String>, Vec<String>, String)> = HashMap::new();
    for n in filtered_neighbors {
        let entry = dev_mac_to_ips
            .entry((n.dev, n.mac))
            .or_insert_with(|| (Vec::new(), Vec::new(), String::new()));
        if n.ip.contains(':') {
            if !entry.1.contains(&n.ip) {
                entry.1.push(n.ip);
            }
        } else {
            if !entry.0.contains(&n.ip) {
                entry.0.push(n.ip);
            }
        }
        entry.2 = pick_best_neighbor_state(entry.2.as_str(), &n.state);
    }

    let mut devices_group: HashMap<(u32, [u8; 6]), DeviceListItem> = HashMap::new();
    for ((dev, mac), (ipv4_list, ipv6_list, best_state)) in dev_mac_to_ips {
        let Some(ifindex) = ifindex_by_name.get(dev.as_str()).copied() else {
            continue;
        };
        let Some(logical_iface) = topology.by_ifindex(ifindex) else {
            continue;
        };
        if !monitor_ifaces.is_empty() && !monitor_ifaces.contains(logical_iface.name.as_str()) {
            continue;
        }
        if ipv4_list.is_empty() {
            continue;
        }
        let subnet = ipv4_list
            .first()
            .and_then(|ip| {
                logical_iface
                    .ipv4_cidrs
                    .iter()
                    .find(|cidr| system_utils::ipv4_in_cidr(ip, cidr))
                    .cloned()
            })
            .unwrap_or_else(|| "".to_string());

        let mut metrics = CounterQuad::default();
        for (k, v) in &device_stats {
            if k.ifindex != ifindex || k.mac != mac {
                continue;
            }
            let prev = runtime.prev_device_bytes.get(k).copied().unwrap_or(0);
            let delta = delta_bytes(v.bytes, prev);
            runtime.prev_device_bytes.insert(*k, v.bytes);
            fill_quad(k.ip_version, k.direction, &mut metrics, delta, sec);
        }

        let hostname = hostname_by_mac.get(&mac).cloned().unwrap_or_else(|| "".to_string());
        let known = runtime.device_registry.entries.get(&(ifindex, mac));
        let persisted_hostname = known.and_then(|k| if k.hostname.is_empty() { None } else { Some(k.hostname.clone()) });

        let cum = runtime.cumulative_device.entry((ifindex, mac)).or_default();
        add_quad(cum, &metrics);

        devices_group.insert(
            (ifindex, mac),
            DeviceListItem {
                ifindex,
                logical_iface: logical_iface.name.clone(),
                subnet: subnet.clone(),
                ipv4: ipv4_list,
                ipv6: ipv6_list,
                mac: mac_utils::to_string(&mac),
                hostname: if hostname.is_empty() { persisted_hostname.unwrap_or_default() } else { hostname },
                metrics,
                cumulative: *cum,
                online: true,
                last_seen_ms: now_ms,
                neighbor_state: if best_state.is_empty() { None } else { Some(best_state) },
            },
        );
    }

    let mut devices = devices_group.into_values().collect::<Vec<_>>();
    devices.sort_by(|a, b| b.cumulative.up_v4_bytes.cmp(&a.cumulative.up_v4_bytes));

    // 构建IP列表
    let ips = build_ip_list(&ip_stats, runtime, monitor_ifaces, &ifindex_by_name, topology, sec);

    // 更新直方图状态
    update_histogram_state(&mut runtime.last_snapshot_histogram_state, &SnapshotData {
        timestamp_ms: now_ms,
        interfaces: interfaces.clone(),
        devices: devices.clone(),
        ips: ips.clone(),
    }, now_ms);

    runtime.last_snapshot_ms = Some(now_ms);

    Ok(SnapshotData {
        timestamp_ms: now_ms,
        interfaces,
        devices,
        ips, // 添加IP列表到快照
    })
}

fn add_quad(dst: &mut CounterQuad, src: &CounterQuad) {
    dst.up_v4_bps = dst.up_v4_bps.saturating_add(src.up_v4_bps);
    dst.down_v4_bps = dst.down_v4_bps.saturating_add(src.down_v4_bps);
    dst.up_v6_bps = dst.up_v6_bps.saturating_add(src.up_v6_bps);
    dst.down_v6_bps = dst.down_v6_bps.saturating_add(src.down_v6_bps);
    dst.up_v4_bytes = dst.up_v4_bytes.saturating_add(src.up_v4_bytes);
    dst.down_v4_bytes = dst.down_v4_bytes.saturating_add(src.down_v4_bytes);
    dst.up_v6_bytes = dst.up_v6_bytes.saturating_add(src.up_v6_bytes);
    dst.down_v6_bytes = dst.down_v6_bytes.saturating_add(src.down_v6_bytes);
}

fn add_bucket_bytes(dst: &mut CounterQuad, bucket: &AggregatedBucket) {
    dst.up_v4_bytes = dst.up_v4_bytes.saturating_add(bucket.up_v4_bytes);
    dst.down_v4_bytes = dst.down_v4_bytes.saturating_add(bucket.down_v4_bytes);
    dst.up_v6_bytes = dst.up_v6_bytes.saturating_add(bucket.up_v6_bytes);
    dst.down_v6_bytes = dst.down_v6_bytes.saturating_add(bucket.down_v6_bytes);
}

pub fn build_recovered_snapshot(runtime: &MonitorRuntime, topology: &TopologySnapshot) -> SnapshotData {
    let (cumulative_iface, cumulative_device, cumulative_ip) = runtime.last_snapshot_histogram_state.cumulative_from_all();
    let mut interfaces = Vec::new();
    for iface in topology.interfaces() {
        if let Some(metrics) = cumulative_iface.get(&iface.ifindex) {
            interfaces.push(InterfaceOverviewItem {
                ifindex: iface.ifindex,
                ifname: iface.name.clone(),
                zone: format!("{:?}", iface.zone).to_ascii_lowercase(),
                metrics: CounterQuad::default(),
                cumulative: *metrics,
            });
        }
    }

    let mut devices = Vec::new();
    for ((ifindex, mac), metrics) in &cumulative_device {
        if let Some(known) = runtime.device_registry.entries.get(&(*ifindex, *mac)) {
            devices.push(DeviceListItem {
                ifindex: *ifindex,
                logical_iface: known.logical_iface.clone(),
                subnet: known.subnet.clone(),
                ipv4: known.ipv4.clone(),
                ipv6: known.ipv6.clone(),
                mac: mac_utils::to_string(mac),
                hostname: known.hostname.clone(),
                metrics: CounterQuad::default(),
                cumulative: *metrics,
                online: false,
                last_seen_ms: known.last_seen_ms,
                neighbor_state: None,
            });
        }
    }

    // 添加IP恢复快照
    let mut ips = Vec::new();
    for ((ifindex, ip_addr), metrics) in &cumulative_ip {
        if let Some(iface) = topology.by_ifindex(*ifindex) {
            ips.push(IpListItem {
                ifindex: *ifindex,
                ifname: iface.name.clone(),
                ip_addr: ip_addr.clone(),
                ip_version: if ip_addr.contains(':') { 6 } else { 4 },
                metrics: CounterQuad::default(),
                cumulative: *metrics,
            });
        }
    }

    devices.sort_by(|a, b| b.cumulative.up_v4_bytes.cmp(&a.cumulative.up_v4_bytes));

    SnapshotData {
        timestamp_ms: runtime.last_snapshot_ms.unwrap_or(0),
        interfaces,
        devices,
        ips,
    }
}

fn bps_stats(v: &[u64]) -> (u64, u64, u64, u64) {
    if v.is_empty() {
        return (0, 0, 0, 0);
    }
    let mut sorted: Vec<u64> = v.to_vec();
    sorted.sort();
    let avg = (v.iter().sum::<u64>() as f64 / v.len() as f64).round() as u64;
    let min = *sorted.first().unwrap_or(&0);
    let max = *sorted.last().unwrap_or(&0);
    let p95_idx = ((sorted.len() as f64) * 0.95).floor() as usize;
    let p95 = sorted.get(p95_idx.min(sorted.len().saturating_sub(1))).copied().unwrap_or(0);
    (avg, min, max, p95)
}

fn bucket_accum_to_aggregated(a: BucketAccum) -> AggregatedBucket {
    let (up_v4_avg, up_v4_min, up_v4_max, up_v4_p95) = bps_stats(&a.up_v4_bps);
    let (down_v4_avg, down_v4_min, down_v4_max, down_v4_p95) = bps_stats(&a.down_v4_bps);
    let (up_v6_avg, up_v6_min, up_v6_max, up_v6_p95) = bps_stats(&a.up_v6_bps);
    let (down_v6_avg, down_v6_min, down_v6_max, down_v6_p95) = bps_stats(&a.down_v6_bps);
    AggregatedBucket {
        start_ts_ms: a.start_ts_ms,
        end_ts_ms: a.end_ts_ms,
        up_v4_bytes: a.up_v4_bytes,
        down_v4_bytes: a.down_v4_bytes,
        up_v6_bytes: a.up_v6_bytes,
        down_v6_bytes: a.down_v6_bytes,
        up_v4_bps_avg: up_v4_avg,
        up_v4_bps_min: up_v4_min,
        up_v4_bps_max: up_v4_max,
        up_v4_bps_p95: up_v4_p95,
        down_v4_bps_avg: down_v4_avg,
        down_v4_bps_min: down_v4_min,
        down_v4_bps_max: down_v4_max,
        down_v4_bps_p95: down_v4_p95,
        up_v6_bps_avg: up_v6_avg,
        up_v6_bps_min: up_v6_min,
        up_v6_bps_max: up_v6_max,
        up_v6_bps_p95: up_v6_p95,
        down_v6_bps_avg: down_v6_avg,
        down_v6_bps_min: down_v6_min,
        down_v6_bps_max: down_v6_max,
        down_v6_bps_p95: down_v6_p95,
    }
}

/// 裁剪历史队列长度不超过 max_points
fn trim_history_queue(queue: &mut VecDeque<HistoryPoint>, max_points: usize) {
    while queue.len() > max_points {
        let _ = queue.pop_front();
    }
}

/// 裁剪直方图完成队列长度不超过 max_buckets
fn trim_histogram_completed<T>(queue: &mut VecDeque<T>, max_buckets: usize) {
    while queue.len() > max_buckets {
        let _ = queue.pop_front();
    }
}

fn series_to_samples(series: &VecDeque<HistoryPoint>) -> Vec<HistorySample> {
    series
        .iter()
        .map(|point| {
            let m = &point.metrics;
            let c = &point.cumulative;
            HistorySample {
                ts_ms: point.ts_ms,
                up_v4_bps: m.up_v4_bps,
                up_v6_bps: m.up_v6_bps,
                down_v4_bps: m.down_v4_bps,
                down_v6_bps: m.down_v6_bps,
                up_v4_bytes: m.up_v4_bytes,
                up_v6_bytes: m.up_v6_bytes,
                down_v4_bytes: m.down_v4_bytes,
                down_v6_bytes: m.down_v6_bytes,
                up_v4_bytes_cumulative: c.up_v4_bytes,
                up_v6_bytes_cumulative: c.up_v6_bytes,
                down_v4_bytes_cumulative: c.down_v4_bytes,
                down_v6_bytes_cumulative: c.down_v6_bytes,
            }
        })
        .collect()
}

fn update_histogram_state(state: &mut HistogramHistory, snapshot: &SnapshotData, now_ms: u64) {
    // 处理接口级别的历史数据
    for iface in &snapshot.interfaces {
        let ifindex = iface.ifindex;
        let (hour_start, _) = hourly_bucket_local(snapshot.timestamp_ms);
        
        // 获取或创建当前小时的数据
        let (current_start, points) = state.current_hour_iface.entry(ifindex).or_insert_with(|| {
            (hour_start, Vec::new())
        });
        
        // 如果是新的小时，则将旧数据移到已完成列表
        if *current_start != hour_start {
            if !points.is_empty() {
                let bucket = points_to_bucket(*current_start, points);
                state.completed_iface.entry(ifindex).or_insert_with(Vec::new).push(bucket);
                points.clear();
            }
            *current_start = hour_start;
        }
        
        // 添加当前点
        points.push(CurrentHourPointState {
            ts_ms: snapshot.timestamp_ms,
            metrics: iface.metrics.clone(),
        });
    }

    // 处理设备级别的历史数据
    for device in &snapshot.devices {
        let key = DeviceSeriesKey {
            ifindex: device.ifindex,
            mac: device.mac.clone(),
        };
        let (hour_start, _) = hourly_bucket_local(snapshot.timestamp_ms);
        
        // 获取或创建当前小时的数据
        let (current_start, points) = state.current_hour_device.entry(key).or_insert_with(|| {
            (hour_start, Vec::new())
        });
        
        // 如果是新的小时，则将旧数据移到已完成列表
        if *current_start != hour_start {
            if !points.is_empty() {
                let bucket = points_to_bucket(*current_start, points);
                state.completed_device.entry(key).or_insert_with(Vec::new).push(bucket);
                points.clear();
            }
            *current_start = hour_start;
        }
        
        // 添加当前点
        points.push(CurrentHourPointState {
            ts_ms: snapshot.timestamp_ms,
            metrics: device.metrics.clone(),
        });
    }

    // 处理IP级别的历史数据
    for ip in &snapshot.ips {
        let key = IpSeriesKey {
            ifindex: ip.ifindex,
            ip: ip.ip_addr.clone(),
        };
        let (hour_start, _) = hourly_bucket_local(snapshot.timestamp_ms);
        
        // 获取或创建当前小时的数据
        let (current_start, points) = state.current_hour_ip.entry(key).or_insert_with(|| {
            (hour_start, Vec::new())
        });
        
        // 如果是新的小时，则将旧数据移到已完成列表
        if *current_start != hour_start {
            if !points.is_empty() {
                let bucket = points_to_bucket(*current_start, points);
                state.completed_ip.entry(key).or_insert_with(Vec::new).push(bucket);
                points.clear();
            }
            *current_start = hour_start;
        }
        
        // 添加当前点
        points.push(CurrentHourPointState {
            ts_ms: snapshot.timestamp_ms,
            metrics: ip.metrics.clone(),
        });
    }
}

#[derive(Default)]
pub struct TrafficHistory {
    iface_series: HashMap<u32, VecDeque<HistoryPoint>>,
    device_series: HashMap<DeviceSeriesKey, VecDeque<HistoryPoint>>,
    // 新增：IP历史记录
    ip_series: HashMap<IpSeriesKey, VecDeque<HistoryPoint>>,
    _max_points: usize,
}

impl TrafficHistory {
    pub fn new(max_points: usize) -> Self {
        Self {
            iface_series: HashMap::new(),
            device_series: HashMap::new(),
            ip_series: HashMap::new(),
            _max_points: max_points,
        }
    }

    pub fn ingest_snapshot(&mut self, snapshot: &SnapshotData) {
        for iface in &snapshot.interfaces {
            let series = self.iface_series.entry(iface.ifindex).or_default();
            series.push_back(HistoryPoint {
                ts_ms: snapshot.timestamp_ms,
                metrics: iface.metrics,
                cumulative: iface.cumulative,
            });
            trim_history_queue(series, self._max_points);
        }

        for dev in &snapshot.devices {
            let key = DeviceSeriesKey {
                ifindex: dev.ifindex,
                mac: dev.mac.clone(),
            };
            let series = self.device_series.entry(key).or_default();
            series.push_back(HistoryPoint {
                ts_ms: snapshot.timestamp_ms,
                metrics: dev.metrics,
                cumulative: dev.cumulative,
            });
            trim_history_queue(series, self._max_points);
        }

        // 新增：处理IP历史记录
        for ip in &snapshot.ips {
            let key = IpSeriesKey {
                ifindex: ip.ifindex,
                ip: ip.ip_addr.clone(),
            };
            let series = self.ip_series.entry(key).or_default();
            series.push_back(HistoryPoint {
                ts_ms: snapshot.timestamp_ms,
                metrics: ip.metrics,
                cumulative: ip.cumulative,
            });
            trim_history_queue(series, self._max_points);
        }
    }

    pub fn query_iface(&self, ifindex: u32, _traffic_type: HistoryTrafficType, _direction: HistoryDirection) -> Vec<HistorySample> {
        let Some(series) = self.iface_series.get(&ifindex) else {
            return Vec::new();
        };
        series_to_samples(series)
    }

    /// 按设备 MAC（可选按接口）查询历史流量，支持多接口合并
    pub fn query_device(
        &self,
        ifindex: Option<u32>,
        mac: &str,
        _traffic_type: HistoryTrafficType,
        _direction: HistoryDirection,
    ) -> Vec<HistorySample> {
        let mut merged: BTreeMap<u64, (CounterQuad, CounterQuad)> = BTreeMap::new();
        for (key, series) in &self.device_series {
            if let Some(expected_ifindex) = ifindex {
                if key.ifindex != expected_ifindex {
                    continue;
                }
            }
            if !key.mac.eq_ignore_ascii_case(mac) {
                continue;
            }
            for point in series {
                let entry = merged.entry(point.ts_ms).or_default();
                add_quad(&mut entry.0, &point.metrics);
                add_quad(&mut entry.1, &point.cumulative);
            }
        }

        merged
            .into_iter()
            .map(|(ts_ms, (metrics, cumulative))| HistorySample {
                ts_ms,
                up_v4_bps: metrics.up_v4_bps,
                up_v6_bps: metrics.up_v6_bps,
                down_v4_bps: metrics.down_v4_bps,
                down_v6_bps: metrics.down_v6_bps,
                up_v4_bytes: metrics.up_v4_bytes,
                up_v6_bytes: metrics.up_v6_bytes,
                down_v4_bytes: metrics.down_v4_bytes,
                down_v6_bytes: metrics.down_v6_bytes,
                up_v4_bytes_cumulative: cumulative.up_v4_bytes,
                up_v6_bytes_cumulative: cumulative.up_v6_bytes,
                down_v4_bytes_cumulative: cumulative.down_v4_bytes,
                down_v6_bytes_cumulative: cumulative.down_v6_bytes,
            })
            .collect()
    }

    // 新增：按IP查询历史流量
    pub fn query_ip(
        &self,
        ifindex: Option<u32>,
        ip: &str,
        _traffic_type: HistoryTrafficType,
        _direction: HistoryDirection,
    ) -> Vec<HistorySample> {
        let mut merged: BTreeMap<u64, (CounterQuad, CounterQuad)> = BTreeMap::new();
        for (key, series) in &self.ip_series {
            if let Some(expected_ifindex) = ifindex {
                if key.ifindex != expected_ifindex {
                    continue;
                }
            }
            if !key.ip.eq_ignore_ascii_case(ip) {
                continue;
            }
            for point in series {
                let entry = merged.entry(point.ts_ms).or_default();
                add_quad(&mut entry.0, &point.metrics);
                add_quad(&mut entry.1, &point.cumulative);
            }
        }

        merged
            .into_iter()
            .map(|(ts_ms, (metrics, cumulative))| HistorySample {
                ts_ms,
                up_v4_bps: metrics.up_v4_bps,
                up_v6_bps: metrics.up_v6_bps,
                down_v4_bps: metrics.down_v4_bps,
                down_v6_bps: metrics.down_v6_bps,
                up_v4_bytes: metrics.up_v4_bytes,
                up_v6_bytes: metrics.up_v6_bytes,
                down_v4_bytes: metrics.down_v4_bytes,
                down_v6_bytes: metrics.down_v6_bytes,
                up_v4_bytes_cumulative: cumulative.up_v4_bytes,
                up_v6_bytes_cumulative: cumulative.up_v6_bytes,
                down_v4_bytes_cumulative: cumulative.down_v4_bytes,
                down_v6_bytes_cumulative: cumulative.down_v6_bytes,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedCurrentHourIpState {
    pub ifindex: u32,
    pub ip: String,
    pub hour_start_ts_ms: u64,
    pub points: Vec<CurrentHourPointState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedCurrentHourState {
    pub iface: Vec<ExportedCurrentHourIfaceState>,
    pub device: Vec<ExportedCurrentHourDeviceState>,
    pub ip: Vec<ExportedCurrentHourIpState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedCurrentHourIfaceState {
    pub ifindex: u32,
    pub hour_start_ts_ms: u64,
    pub points: Vec<CurrentHourPointState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedCurrentHourDeviceState {
    pub ifindex: u32,
    pub mac: String,
    pub hour_start_ts_ms: u64,
    pub points: Vec<CurrentHourPointState>,
}
