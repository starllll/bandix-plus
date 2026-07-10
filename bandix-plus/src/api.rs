use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use chrono::{Datelike, Duration as ChronoDuration, Local, TimeZone};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

use crate::monitor::{
    AggregateBucket, AggregatedBucket, HistogramHistory, HistoryDirection, HistorySample, HistoryTrafficType, IpListItem, KnownDevice, MonitorRuntime,
    SnapshotData, TrafficHistory,
};
use crate::persistence::PersistenceManager;
use crate::policy::{
    CreateScheduledRuleRequest, GuestDefaultRateLimitApi, GuestWhitelistEntryApi, GuestWhitelistEntryRequest, InterfaceRateLimitApi,
    PolicyItem, PolicyRuntime, ScheduledRuleApi, SetInterfaceRateLimitRequest, UpdateScheduledRuleRequest, add_guest_whitelist,
    create_scheduled_rule, delete_guest_default, delete_iface_limit, delete_scheduled_rule, get_guest_defaults, get_guest_whitelist,
    get_iface_limits, get_scheduled_rules, policy_items, remove_guest_whitelist, set_guest_default, set_guest_default_enabled,
    set_iface_limit, update_scheduled_rule,
};
use crate::topology::TopologySnapshot;
use crate::utils::mac_utils;

#[derive(Clone)]
pub struct ApiState {
    pub snapshot: Arc<RwLock<SnapshotData>>,
    pub history: Arc<RwLock<TrafficHistory>>,
    pub histogram: Arc<RwLock<HistogramHistory>>,
    pub monitor_runtime: Arc<RwLock<MonitorRuntime>>,
    pub policy_runtime: Arc<RwLock<PolicyRuntime>>,
    pub topology: Arc<RwLock<TopologySnapshot>>,
    pub persistence: Option<Arc<PersistenceManager>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DevicesQuery {
    pub iface: Option<String>,
    pub period: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OverviewQuery {
    pub period: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SetDeviceHostnameRequest {
    pub iface: String,
    pub mac: String,
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct HistoryQuery {
    /// 内核网卡名（如 `eth0`），与 `/api/overview` 的 `ifname` 一致；服务端解析为 ifindex。
    pub iface: Option<String>,
    pub mac: Option<String>,
    pub traffic_type: Option<String>,
    pub direction: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AggregateQuery {
    /// 内核网卡名；服务端解析为 ifindex。
    pub iface: Option<String>,
    pub mac: Option<String>,
    /// 与 `/api/trend` 相同：`all` / `ipv4` / `ipv6`；响应中另一侧字节与 bps 统计置零。
    pub traffic_type: Option<String>,
    pub start_ms: Option<u64>,
    pub end_ms: Option<u64>,
    /// `hourly` / `daily`；默认为 `hourly`。
    pub bucket: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UsageRankingQuery {
    /// 内核网卡名；服务端解析为 ifindex。
    pub iface: Option<String>,
    /// 与 `/api/trend` 相同：`all` / `ipv4` / `ipv6`。
    pub traffic_type: Option<String>,
    pub start_ms: Option<u64>,
    pub end_ms: Option<u64>,
    /// 返回条目数；`0` 表示不限制。
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageRankingItem {
    pub iface: String,
    pub mac: String,
    pub hostname: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub total_bytes: u64,
}

// 新增：IP使用排名项
#[derive(Debug, Clone, Serialize)]
pub struct IpUsageRankingItem {
    pub iface: String,
    pub ip: String,
    pub ip_version: u8,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiEnvelope<T> {
    pub ok: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn router(state: ApiState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        .route("/api/health", get(health))
        .route("/api/snapshot", get(snapshot))
        .route("/api/overview", get(overview))
        .route("/api/devices", get(devices))
        .route("/api/ips", get(ips))  // 新增：IP统计API
        .route("/api/devices/hostname", put(set_device_hostname_handler))
        .route("/api/trend", get(history))
        .route("/api/histogram", get(aggregate))
        .route("/api/usage_ranking", get(usage_ranking))
        .route("/api/ip_usage_ranking", get(ip_usage_ranking))  // 新增：IP使用排名API
        .route("/api/policy", get(policy))
        .route("/api/rate_limit/schedules", get(get_schedules).post(create_schedule))
        .route(
            "/api/rate_limit/schedules/{id}",
            put(update_schedule).patch(update_schedule).delete(delete_schedule),
        )
        .route(
            "/api/rate_limit/iface_limits",
            get(get_iface_limits_handler).post(set_iface_limit_handler),
        )
        .route("/api/rate_limit/iface_limits/{iface}", delete(delete_iface_limit_handler))
        .route(
            "/api/rate_limit/guest_defaults",
            get(get_guest_defaults_handler).post(set_guest_default_handler),
        )
        .route("/api/rate_limit/guest_defaults/{iface}", delete(delete_guest_default_handler))
        .route(
            "/api/rate_limit/guest_defaults/{iface}/enable",
            put(set_guest_default_enable_handler),
        )
        .route(
            "/api/rate_limit/guest_whitelist",
            get(get_guest_whitelist_handler).post(add_guest_whitelist_handler),
        )
        .route("/api/rate_limit/guest_whitelist/{iface}/{mac}", delete(remove_guest_whitelist_handler))
        .layer(cors)
}

async fn health() -> Json<ApiEnvelope<&'static str>> {
    Json(ApiEnvelope {
        ok: true,
        data: "ok",
        error: None,
    })
}

async fn snapshot(State(state): State<ApiState>) -> Json<ApiEnvelope<SnapshotData>> {
    Json(ApiEnvelope {
        ok: true,
        data: state.snapshot.read().await.clone(),
        error: None,
    })
}

async fn overview(
    State(state): State<ApiState>,
    Query(q): Query<OverviewQuery>,
) -> Json<ApiEnvelope<Vec<crate::monitor::InterfaceOverviewItem>>> {
    let period = match parse_period_scope(q.period.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(e),
            });
        }
    };
    let mut data = state.snapshot.read().await.interfaces.clone();
    if let Some(scope) = period {
        let (start_ms, end_ms) = period_range_ms(scope, now_millis());
        let histogram = state.histogram.read().await;
        for item in &mut data {
            let buckets = histogram.query_aggregate(item.ifindex, None, start_ms, end_ms, AggregateBucket::Hourly);
            item.cumulative = cumulative_from_buckets(&buckets);
        }
    }
    Json(ApiEnvelope {
        ok: true,
        data,
        error: None,
    })
}

async fn devices(State(state): State<ApiState>, Query(q): Query<DevicesQuery>) -> Json<ApiEnvelope<Vec<crate::monitor::DeviceListItem>>> {
    let topology = state.topology.read().await;
    let mut data = state.snapshot.read().await.devices.clone();
    if let Some(iface) = &q.iface {
        let Some(ifindex) = topology.ifindex_by_name(iface) else {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(format!("unknown iface: {iface}")),
            });
        };
        data.retain(|d| d.ifindex == ifindex);
    }
    if let Some(scope) = match parse_period_scope(q.period.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(e),
            });
        }
    } {
        let (start_ms, end_ms) = period_range_ms(scope, now_millis());
        let histogram = state.histogram.read().await;
        for item in &mut data {
            let buckets = histogram.query_aggregate(
                item.ifindex,
                Some(&item.mac),
                start_ms,
                end_ms,
                AggregateBucket::Hourly,
            );
            item.cumulative = cumulative_from_buckets(&buckets);
        }
    }
    Json(ApiEnvelope {
        ok: true,
        data,
        error: None,
    })
}

// 新增：IP统计API处理器
async fn ips(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<IpListItem>>> {
    Json(ApiEnvelope {
        ok: true,
        data: state.snapshot.read().await.ips.clone(),
        error: None,
    })
}

async fn history(
    State(state): State<ApiState>,
    Query(q): Query<HistoryQuery>,
) -> Json<ApiEnvelope<Vec<HistorySample>>> {
    let topology = state.topology.read().await;
    let history = state.history.read().await;
    let traffic_type = parse_traffic_type(&q.traffic_type);
    let direction = parse_direction(&q.direction);

    if let (Some(iface), Some(mac)) = (&q.iface, &q.mac) {
        let Some(ifindex) = topology.ifindex_by_name(iface) else {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(format!("unknown iface: {iface}")),
            });
        };
        let data = history.query_device(Some(ifindex), mac, traffic_type, direction);
        return Json(ApiEnvelope { ok: true, data, error: None });
    }

    if let Some(iface) = &q.iface {
        let Some(ifindex) = topology.ifindex_by_name(iface) else {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(format!("unknown iface: {iface}")),
            });
        };
        let data = history.query_iface(ifindex, traffic_type, direction);
        return Json(ApiEnvelope { ok: true, data, error: None });
    }

    Json(ApiEnvelope {
        ok: false,
        data: Vec::new(),
        error: Some("missing iface param".to_string()),
    })
}

async fn aggregate(
    State(state): State<ApiState>,
    Query(q): Query<AggregateQuery>,
) -> Json<ApiEnvelope<Vec<AggregatedBucket>>> {
    let topology = state.topology.read().await;
    let histogram = state.histogram.read().await;

    let Some(iface) = &q.iface else {
        return Json(ApiEnvelope {
            ok: false,
            data: Vec::new(),
            error: Some("missing iface param".to_string()),
        });
    };
    let Some(ifindex) = topology.ifindex_by_name(iface) else {
        return Json(ApiEnvelope {
            ok: false,
            data: Vec::new(),
            error: Some(format!("unknown iface: {iface}")),
        });
    };

    let bucket = match q.bucket.as_deref().unwrap_or("hourly") {
        "hourly" => AggregateBucket::Hourly,
        "daily" => AggregateBucket::Daily,
        _ => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some("invalid bucket param, expect 'hourly' or 'daily'".to_string()),
            });
        }
    };

    let start_ms = q.start_ms.unwrap_or(0);
    let end_ms = q.end_ms.unwrap_or(u64::MAX);

    let data = histogram.query_aggregate(ifindex, q.mac.as_deref(), start_ms, end_ms, bucket);

    let traffic_type = parse_traffic_type(&q.traffic_type);
    let data = data.into_iter().map(|b| b.with_traffic_type(traffic_type)).collect();

    Json(ApiEnvelope { ok: true, data, error: None })
}

async fn usage_ranking(
    State(state): State<ApiState>,
    Query(q): Query<UsageRankingQuery>,
) -> Json<ApiEnvelope<Vec<UsageRankingItem>>> {
    let topology = state.topology.read().await;
    let histogram = state.histogram.read().await;

    let (completed_iface, completed_device, _completed_ip) = state.monitor_runtime.read().await.last_snapshot_histogram_state.cumulative_from_completed();
    let (current_iface, current_device, _current_ip) = histogram.cumulative_from_all();

    let mut items = Vec::new();
    let mut seen_macs = std::collections::HashSet::new();

    for ((ifindex, mac), cumulative) in current_device.iter().chain(completed_device.iter()) {
        if seen_macs.contains(&(*ifindex, *mac)) {
            continue;
        }
        seen_macs.insert((*ifindex, *mac));

        let Some(iface) = topology.by_ifindex(*ifindex) else {
            continue;
        };

        if let Some(expected_iface) = &q.iface {
            if &iface.name != expected_iface {
                continue;
            }
        }

        let mut total = *cumulative;
        let traffic_type = parse_traffic_type(&q.traffic_type);
        if traffic_type != HistoryTrafficType::All {
            total = zero_out_quad_for_traffic_type(total, traffic_type);
        }

        let mac_str = mac_utils::to_string(mac);
        let runtime = state.monitor_runtime.read().await;
        let known = runtime.device_registry.entries.get(&(*ifindex, *mac));
        let hostname = known.map(|k| k.hostname.clone()).unwrap_or_default();

        items.push(UsageRankingItem {
            iface: iface.name.clone(),
            mac: mac_str,
            hostname,
            ipv4: known.map(|k| k.ipv4.clone()).unwrap_or_default(),
            ipv6: known.map(|k| k.ipv6.clone()).unwrap_or_default(),
            up_bytes: total.up_v4_bytes + total.up_v6_bytes,
            down_bytes: total.down_v4_bytes + total.down_v6_bytes,
            total_bytes: total.up_v4_bytes + total.up_v6_bytes + total.down_v4_bytes + total.down_v6_bytes,
        });
    }

    items.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));

    if let Some(limit) = q.limit.filter(|l| *l > 0) {
        items.truncate(limit);
    }

    Json(ApiEnvelope { ok: true, data: items, error: None })
}

// 新增：IP使用排名API处理器
async fn ip_usage_ranking(
    State(state): State<ApiState>,
    Query(q): Query<UsageRankingQuery>,
) -> Json<ApiEnvelope<Vec<IpUsageRankingItem>>> {
    let topology = state.topology.read().await;
    let histogram = state.histogram.read().await;

    let (_completed_iface, _completed_device, completed_ip) = state.monitor_runtime.read().await.last_snapshot_histogram_state.cumulative_from_completed();
    let (_current_iface, _current_device, current_ip) = histogram.cumulative_from_all();

    let mut items = Vec::new();
    let mut seen_ips = std::collections::HashSet::new();

    for ((ifindex, ip_addr), cumulative) in current_ip.iter().chain(completed_ip.iter()) {
        if seen_ips.contains(&(*ifindex, ip_addr.clone())) {
            continue;
        }
        seen_ips.insert((*ifindex, ip_addr.clone()));

        let Some(iface) = topology.by_ifindex(*ifindex) else {
            continue;
        };

        if let Some(expected_iface) = &q.iface {
            if &iface.name != expected_iface {
                continue;
            }
        }

        let mut total = *cumulative;
        let traffic_type = parse_traffic_type(&q.traffic_type);
        if traffic_type != HistoryTrafficType::All {
            total = zero_out_quad_for_traffic_type(total, traffic_type);
        }

        let ip_version = if ip_addr.contains(':') { 6 } else { 4 };

        items.push(IpUsageRankingItem {
            iface: iface.name.clone(),
            ip: ip_addr.clone(),
            ip_version,
            up_bytes: total.up_v4_bytes + total.up_v6_bytes,
            down_bytes: total.down_v4_bytes + total.down_v6_bytes,
            total_bytes: total.up_v4_bytes + total.up_v6_bytes + total.down_v4_bytes + total.down_v6_bytes,
        });
    }

    items.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));

    if let Some(limit) = q.limit.filter(|l| *l > 0) {
        items.truncate(limit);
    }

    Json(ApiEnvelope { ok: true, data: items, error: None })
}

// 辅助函数：根据流量类型清零四元组
fn zero_out_quad_for_traffic_type(mut quad: crate::monitor::CounterQuad, traffic_type: HistoryTrafficType) -> crate::monitor::CounterQuad {
    match traffic_type {
        HistoryTrafficType::All => quad,
        HistoryTrafficType::Ipv4 => {
            quad.up_v6_bytes = 0;
            quad.down_v6_bytes = 0;
            quad.up_v6_bps = 0;
            quad.down_v6_bps = 0;
            quad
        },
        HistoryTrafficType::Ipv6 => {
            quad.up_v4_bytes = 0;
            quad.down_v4_bytes = 0;
            quad.up_v4_bps = 0;
            quad.down_v4_bps = 0;
            quad
        },
    }
}

fn parse_traffic_type(s: &Option<String>) -> HistoryTrafficType {
    match s.as_deref().unwrap_or("all") {
        "all" => HistoryTrafficType::All,
        "ipv4" => HistoryTrafficType::Ipv4,
        "ipv6" => HistoryTrafficType::Ipv6,
        _ => HistoryTrafficType::All,
    }
}

fn parse_direction(s: &Option<String>) -> HistoryDirection {
    match s.as_deref().unwrap_or("both") {
        "both" => HistoryDirection::Both,
        "up" => HistoryDirection::Up,
        "down" => HistoryDirection::Down,
        _ => HistoryDirection::Both,
    }
}

fn parse_period_scope(s: Option<&str>) -> Result<Option<PeriodScope>, String> {
    if let Some(s) = s {
        match s {
            "today" => Ok(Some(PeriodScope::Today)),
            "yesterday" => Ok(Some(PeriodScope::Yesterday)),
            "this_week" => Ok(Some(PeriodScope::ThisWeek)),
            "last_week" => Ok(Some(PeriodScope::LastWeek)),
            "this_month" => Ok(Some(PeriodScope::ThisMonth)),
            "last_month" => Ok(Some(PeriodScope::LastMonth)),
            "" => Ok(None),
            _ => Err(format!("unknown period: {s}")),
        }
    } else {
        Ok(None)
    }
}

fn cumulative_from_buckets(buckets: &[AggregatedBucket]) -> crate::monitor::CounterQuad {
    let mut total = crate::monitor::CounterQuad::default();
    for bucket in buckets {
        total.up_v4_bytes = total.up_v4_bytes.saturating_add(bucket.up_v4_bytes);
        total.down_v4_bytes = total.down_v4_bytes.saturating_add(bucket.down_v4_bytes);
        total.up_v6_bytes = total.up_v6_bytes.saturating_add(bucket.up_v6_bytes);
        total.down_v6_bytes = total.down_v6_bytes.saturating_add(bucket.down_v6_bytes);
    }
    total
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn period_range_ms(scope: PeriodScope, now_ms: u64) -> (u64, u64) {
    use chrono::{Datelike, Local, Timelike};
    
    let now = Local.timestamp_millis_opt(now_ms as i64).unwrap();
    match scope {
        PeriodScope::Today => {
            let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
            let start_ts = Local.from_local_datetime(&start).unwrap().timestamp_millis() as u64;
            let end = now.date_naive().and_hms_opt(23, 59, 59).unwrap();
            let end_ts = Local.from_local_datetime(&end).unwrap().timestamp_millis() as u64;
            (start_ts, end_ts)
        },
        PeriodScope::Yesterday => {
            let yesterday = now.date_naive() - ChronoDuration::days(1);
            let start = yesterday.and_hms_opt(0, 0, 0).unwrap();
            let start_ts = Local.from_local_datetime(&start).unwrap().timestamp_millis() as u64;
            let end = yesterday.and_hms_opt(23, 59, 59).unwrap();
            let end_ts = Local.from_local_datetime(&end).unwrap().timestamp_millis() as u64;
            (start_ts, end_ts)
        },
        PeriodScope::ThisWeek => {
            let days_since_monday = (now.weekday() as u32 + 7 - 1) % 7;
            let start_date = now.date_naive() - ChronoDuration::days(days_since_monday as i64);
            let start = start_date.and_hms_opt(0, 0, 0).unwrap();
            let start_ts = Local.from_local_datetime(&start).unwrap().timestamp_millis() as u64;
            let end_date = start_date + ChronoDuration::days(6);
            let end = end_date.and_hms_opt(23, 59, 59).unwrap();
            let end_ts = Local.from_local_datetime(&end).unwrap().timestamp_millis() as u64;
            (start_ts, end_ts)
        },
        PeriodScope::LastWeek => {
            let days_since_monday = (now.weekday() as u32 + 7 - 1) % 7;
            let start_date = now.date_naive() - ChronoDuration::days(days_since_monday as i64 + 7);
            let start = start_date.and_hms_opt(0, 0, 0).unwrap();
            let start_ts = Local.from_local_datetime(&start).unwrap().timestamp_millis() as u64;
            let end_date = start_date + ChronoDuration::days(6);
            let end = end_date.and_hms_opt(23, 59, 59).unwrap();
            let end_ts = Local.from_local_datetime(&end).unwrap().timestamp_millis() as u64;
            (start_ts, end_ts)
        },
        PeriodScope::ThisMonth => {
            let start = now.date_naive().with_day(1).unwrap().and_hms_opt(0, 0, 0).unwrap();
            let start_ts = Local.from_local_datetime(&start).unwrap().timestamp_millis() as u64;
            let end = now.date_naive().with_day(1).unwrap().with_month(12.min(now.month() + 1)).unwrap_or_else(|| {
                now.date_naive().with_year(now.year() + 1).unwrap().with_month(1).unwrap().with_day(1).unwrap()
            }).and_hms_opt(23, 59, 59).unwrap();
            let end_ts = Local.from_local_datetime(&end).unwrap().timestamp_millis() as u64;
            (start_ts, end_ts)
        },
        PeriodScope::LastMonth => {
            let prev_month = if now.month() == 1 {
                (now.year() - 1, 12)
            } else {
                (now.year(), now.month() - 1)
            };
            let start = NaiveDate::from_ymd_opt(prev_month.0, prev_month.1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap();
            let start_ts = Local.from_local_datetime(&start).unwrap().timestamp_millis() as u64;
            let end = NaiveDate::from_ymd_opt(prev_month.0, prev_month.1, 1).unwrap().with_month(12.min(prev_month.1 + 1)).unwrap_or_else(|| {
                NaiveDate::from_ymd_opt(prev_month.0 + 1, 1, 1).unwrap()
            }).and_hms_opt(23, 59, 59).unwrap();
            let end_ts = Local.from_local_datetime(&end).unwrap().timestamp_millis() as u64;
            (start_ts, end_ts)
        },
    }
}

#[derive(Debug, Clone, Copy)]
enum PeriodScope {
    Today,
    Yesterday,
    ThisWeek,
    LastWeek,
    ThisMonth,
    LastMonth,
}

// ... existing code for other API handlers ...