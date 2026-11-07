use super::*;
use std::sync::Mutex;

const FULL_FIXTURE: &str = include_str!("../../tests/fixtures/stats_full.txt");
const MONITOR_FIXTURE: &str = include_str!("../../tests/fixtures/stats_monitor.txt");
const DISK_FIXTURE: &str = include_str!("../../tests/fixtures/disk.txt");
const DISTRO_FIXTURE: &str = include_str!("../../tests/fixtures/distro.txt");
const GPU_FIXTURE: &str = include_str!("../../tests/fixtures/monitor_gpu.txt");

#[test]
fn scripts_are_byte_identical_to_electron() {
    assert_eq!(stats_command(false), FULL_FIXTURE);
    assert_eq!(stats_command(true), MONITOR_FIXTURE);
    assert_eq!(linux_disk_stats_command(), DISK_FIXTURE);
    assert_eq!(distro_command(), DISTRO_FIXTURE);
    assert_eq!(monitor_gpu_command(), GPU_FIXTURE);
}

#[test]
fn every_probe_fits_dropbears_limit() {
    for command in [
        stats_command(false),
        stats_command(true),
        linux_disk_stats_command(),
        monitor_gpu_command(),
    ] {
        assert!(
            command.len() <= DROPBEAR_MAX_COMMAND_BYTES,
            "{}",
            command.len()
        );
    }
    assert!(stats_command(false).contains("sleep 10"));
    assert!(!stats_command(true).contains("procs=$("));
    assert!(LINUX_STATS_FULL.matches("nvidia-smi").count() == 1);
}

const LINUX_STATS: &str =
    "CPURAW:1000 900|CORES:4|PERCORERAW:|MEMINFO:8000 4000 100 900 0 0|PROCS:|DISKS:|NET:";

fn finalize(line: &str, baseline: &mut StatsBaseline, now: i64) -> Result<Value, String> {
    finalize_stats(
        parse_stats_output(line),
        baseline,
        now,
        Some(3.0),
        Some(7.0),
    )
}

#[test]
fn host_identity_load_and_uptime() {
    let mut b = StatsBaseline::default();
    let s = finalize(
        "CPURAW:1000 900|CORES:4|PERCORERAW:|MEMINFO:8000 4000 100 900 0 0|PROCS:|DISKS:/:20:80:25|NET:eth0:1000:2000|HOST:demo-box|OS:Ubuntu 24.04 LTS|KERNEL:6.8.0|UPTIME:12345|LOAD:0.10 0.20 0.30",
        &mut b,
        1000,
    )
    .unwrap();
    assert_eq!(s["hostname"], "demo-box");
    assert_eq!(s["osName"], "Ubuntu 24.04 LTS");
    assert_eq!(s["kernelRelease"], "6.8.0");
    assert_eq!(s["uptimeSeconds"], 12345);
    assert_eq!(s["loadAverage"], json!([0.1, 0.2, 0.3]));
    assert_eq!(s["memUsed"], 3000);
    assert_eq!(s["diskPercent"], 25);
    assert_eq!(s["latencyMs"], 3);
    assert_eq!(s["responseLatencyMs"], 7);
    assert_eq!(s["networkReady"], false);
}

#[test]
fn derives_disk_percent_when_capacity_is_not_numeric() {
    let mut b = StatsBaseline::default();
    let s = finalize(
        "CPURAW:1000 900|CORES:4|PERCORERAW:|MEMINFO:8000 4000 100 900 0 0|PROCS:|DISKS:/:1:8:-:rpool/data/subvol-101-disk-0|NET:",
        &mut b,
        1,
    )
    .unwrap();
    assert_eq!(
        s["disks"],
        json!([{ "mountPoint": "/", "used": 1, "total": 8, "percent": 13, "capacityKey": "rpool/data/subvol-101-disk-0" }])
    );
    assert_eq!(s["diskPercent"], 13);
}

#[test]
fn filesystem_type_metadata_is_split() {
    let mut b = StatsBaseline::default();
    let s = finalize(
        &format!("{LINUX_STATS}|DISKS:/:1.5:10:15:fs=ext4:/dev/sda1,/data:2:4:50:fs=zfs:tank/data"),
        &mut b,
        1,
    )
    .unwrap();
    assert_eq!(s["disks"][0]["filesystemType"], "ext4");
    assert_eq!(s["disks"][0]["capacityKey"], "/dev/sda1");
    assert_eq!(s["disks"][0]["used"], 1.5);
    assert_eq!(s["disks"][1]["capacityKey"], "tank/data");
}

#[test]
fn blank_load_and_uptime_are_missing() {
    let mut b = StatsBaseline::default();
    let s = finalize(&format!("{LINUX_STATS}|UPTIME:|LOAD:"), &mut b, 1).unwrap();
    assert_eq!(s["uptimeSeconds"], Value::Null);
    assert_eq!(s["loadAverage"], json!([]));
}

#[test]
fn macos_line_parses_direct_cpu_and_processes() {
    let mut b = StatsBaseline::default();
    let s = finalize(
        "NC_LATENCY_MARK|CPU:27|CORES:10|MEMINFO:32768 4096 0 8192 2048 1536|PROCS:123;1.2;Finder|DISKS:/:120:460:26:apfs:/dev/disk3|NET:en0:1000:3000",
        &mut b,
        1,
    )
    .unwrap();
    assert_eq!(s["cpu"], 27);
    assert_eq!(s["cpuCores"], 10);
    assert_eq!(s["swapTotal"], 2048);
    assert_eq!(s["swapUsed"], 512);
    assert_eq!(
        s["topProcesses"],
        json!([{ "pid": "123", "memPercent": 1.2, "command": "Finder" }])
    );
    assert_eq!(s["disks"][0]["capacityKey"], "apfs:/dev/disk3");
    assert_eq!(s["diskReadSpeed"], Value::Null);
}

#[test]
fn cpu_network_and_disk_io_use_deltas() {
    let mut b = StatsBaseline::default();
    let first = finalize(
        "CPURAW:1000 900|CORES:2|PERCORERAW:500:450,500:450|MEMINFO:8000 4000 100 900 0 0|NET:eth0:1000:2000|DISKIO:100;sda:100:200,",
        &mut b,
        10_000,
    )
    .unwrap();
    assert_eq!(first["cpu"], Value::Null);
    assert_eq!(first["cpuPerCore"], json!([0, 0]));
    assert_eq!(first["netRxSpeed"], 0);
    let second = finalize(
        "CPURAW:2000 1400|CORES:2|PERCORERAW:1000:950,1000:500|MEMINFO:8000 4000 100 900 0 0|NET:eth0:3000:2500|DISKIO:102;sda:104:208,",
        &mut b,
        12_000,
    )
    .unwrap();
    assert_eq!(second["cpu"], 50);
    assert_eq!(second["cpuPerCore"], json!([0, 90]));
    assert_eq!(second["netRxSpeed"], 1000);
    assert_eq!(second["netTxSpeed"], 250);
    assert_eq!(second["networkReady"], true);
    assert_eq!(second["netInterfaces"][0]["rxSpeed"], 1000);
    assert_eq!(second["diskReadSpeed"], 1024);
    assert_eq!(second["diskWriteSpeed"], 2048);
}

#[test]
fn unsupported_and_unparseable_output() {
    let mut b = StatsBaseline::default();
    assert_eq!(
        finalize("NC_LATENCY_MARK|UNSUPPORTED_OS:FreeBSD", &mut b, 1).unwrap_err(),
        "Server stats not supported on this OS (FreeBSD)"
    );
    assert_eq!(
        finalize("garbage", &mut b, 1).unwrap_err(),
        "Unable to parse server stats (unsupported OS or shell)"
    );
}

#[test]
fn gpu_fields_in_the_stats_line() {
    let mut b = StatsBaseline::default();
    let s = finalize(
        &format!("{LINUX_STATS}|GPU:73 2048 24576 NVIDIA GeForce RTX 4090"),
        &mut b,
        1,
    )
    .unwrap();
    assert_eq!(s["gpu"], 73);
    assert_eq!(s["gpuName"], "NVIDIA GeForce RTX 4090");
    assert_eq!(s["gpuMemUsed"], 2048);
    assert_eq!(s["gpus"], json!([]));
    let s = finalize(&format!("{LINUX_STATS}|GPU:[Not Supported]"), &mut b, 2).unwrap();
    assert_eq!(s["gpu"], Value::Null);
    assert_eq!(s["gpuName"], Value::Null);
}

#[test]
fn gpu_parser_cases() {
    let parsed = parse_gpu_stats(
        "GPU:72 3072 49152 NVIDIA RTX 4090 ;; 0\tNVIDIA RTX 4090\t73\t2048\t24576 ;; 1\tNVIDIA A100 80GB\t71\t1024\t24576",
    );
    assert_eq!(parsed.gpu, Some(72));
    assert_eq!(parsed.gpu_mem_total, Some(49152));
    assert_eq!(parsed.gpus.len(), 2);
    assert_eq!(parsed.gpus[1].name, "NVIDIA A100 80GB");

    let cards = (0..8)
        .map(|i| {
            format!(
                "{i}\tNVIDIA A100 {i}\t{}\t{}\t81920",
                if i == 3 { 140 } else { 10 + i },
                1024 * (i + 1)
            )
        })
        .collect::<Vec<_>>()
        .join(" ;; ");
    let parsed = parse_gpu_stats(&format!("GPU:40 36864 655360 NVIDIA A100 0 ;; {cards}"));
    assert_eq!(parsed.gpus.len(), 8);
    assert_eq!(parsed.gpus[3].utilization, Some(100));

    let parsed = parse_gpu_stats(
        "GPU:73 2048 24576 NVIDIA RTX 4090 ;; not-a-card ;; 0\tNVIDIA RTX 4090\t73\tN/A\t24576 ;; 2\tNVIDIA A100\tN/A\t1024\t8192",
    );
    assert_eq!(
        parsed.gpus,
        vec![
            GpuCard {
                index: 0,
                name: "NVIDIA RTX 4090".into(),
                utilization: Some(73),
                memory_used: None,
                memory_total: Some(24576)
            },
            GpuCard {
                index: 2,
                name: "NVIDIA A100".into(),
                utilization: None,
                memory_used: Some(1024),
                memory_total: Some(8192)
            },
        ]
    );
    for output in [
        "",
        "GPU:",
        "GPU:[Not Supported]",
        "GPU:N/A N/A N/A",
        "CPURAW:1 1|MEMINFO:1",
    ] {
        assert_eq!(parse_gpu_stats(output), GpuStats::default(), "{output}");
    }
}

#[test]
fn disk_io_parsing_and_rates() {
    let before = parse_disk_io("100.25;sda:100:200,nvme0n1:50:100,");
    let after = parse_disk_io("101.75;nvme0n1:80:140,sda:130:220,");
    assert_eq!(
        disk_io_rates(after.as_ref(), before.as_ref()),
        (Some(20480.0), Some(20480.0))
    );
    let base = parse_disk_io("100;sda:100:200,");
    assert_eq!(disk_io_rates(base.as_ref(), None), (None, None));
    for text in [
        "100;sda:110:210",
        "99;sda:110:210",
        "101;sda:99:210",
        "101;sda:110:199",
        "101;sdb:110:210",
        "101;sda:110:210,sdb:0:0",
    ] {
        assert_eq!(
            disk_io_rates(parse_disk_io(text).as_ref(), base.as_ref()),
            (None, None),
            "{text}"
        );
    }
    for text in [
        "",
        "100;",
        "NaN;sda:1:2",
        "100;sda:-1:2",
        "100;sda:1:NaN",
        "100;sda:1:2,sda:1:2",
        "100;sda:9007199254740992:1",
        "100;sda:1:2:3",
        "100;sda:1:2;extra",
    ] {
        assert_eq!(parse_disk_io(text), None, "{text}");
    }
}

#[test]
fn partition_rates_follow_mountinfo() {
    let disk = |m: &str| DiskInfo {
        mount_point: m.into(),
        used: 1.0,
        total: 2.0,
        percent: 50.0,
        capacity_key: None,
        filesystem_type: None,
        disk_read_speed: None,
        disk_write_speed: None,
    };
    let disks = vec![disk("/"), disk("/data space"), disk("/bind"), disk("/pool")];
    let mounts = "/:8-1,/data\\040space:253-0,/bind:8-1,/pool:0-42,";
    let previous = parse_disk_io("10;8-1:100:200,253-0:10:20,");
    let current = parse_disk_io("12;8-1:104:208,253-0:30:60,8-2:0:0,");
    let out = with_partition_io(disks.clone(), mounts, current.as_ref(), previous.as_ref());
    let rates: Vec<_> = out
        .iter()
        .map(|d| (d.disk_read_speed, d.disk_write_speed))
        .collect();
    assert_eq!(
        rates,
        vec![
            (Some(1024.0), Some(2048.0)),
            (Some(5120.0), Some(10240.0)),
            (Some(1024.0), Some(2048.0)),
            (None, None)
        ]
    );
    let out = with_partition_io(disks, mounts, current.as_ref(), None);
    assert_eq!(out[0].disk_read_speed, None);
}

#[test]
fn js_number_helpers() {
    assert_eq!(js_round(12.5), 13.0);
    assert_eq!(js_round(-2.5), -2.0);
    assert_eq!(js_parse_float("12.5abc"), 12.5);
    assert!(js_parse_float("").is_nan());
    assert!(js_parse_float("-").is_nan());
    assert_eq!(js_parse_float("1e3x"), 1000.0);
    assert_eq!(js_parse_int(" 42%"), Some(42));
    assert_eq!(js_parse_int("-7"), Some(-7));
    assert_eq!(js_parse_int("x"), None);
    assert_eq!(quote_shell_arg("it's"), "'it'\\''s'");
}

#[test]
fn history_points_are_rate_limited_and_windowed() {
    let mut h = StatsHistory::default();
    let stats = json!({"cpu": 10, "memTotal": 200, "memUsed": 50, "diskPercent": 5,
                       "networkReady": true, "netRxSpeed": 1, "netTxSpeed": 2});
    let reply = json!({"success": true, "stats": stats});
    h.record(&reply, false, 10_000, 0);
    h.record(&reply, false, 10_500, 0);
    assert_eq!(h.points.len(), 1);
    assert_eq!(h.points[0].memory, Some(25.0));
    assert_eq!(h.points[0].rx, Some(1.0));
    // A panel restart after the last point accepts the next sample at once.
    h.record(&reply, false, 10_600, 10_100);
    assert_eq!(h.points.len(), 2);
    h.record(&reply, true, 10_000 + HISTORY_WINDOW_MS + 700, 0);
    assert_eq!(h.points.len(), 1);
    assert!(h.full_result.is_some());
    h.record(&json!({"success": false}), true, 99_999_999, 0);
    assert_eq!(h.points.len(), 1);
}

#[test]
fn gpu_cache_lifecycle() {
    let mut c = GpuCache::default();
    assert!(c.due(0));
    c.pending = true;
    assert!(!c.due(0));
    c.finish_probe(Some("GPU:50 1 2 Card"), false, 1000);
    assert_eq!(c.stats.gpu, Some(50));
    assert_eq!(c.next_at, 11_000);
    let mut stats = json!({"cpu": 1, "gpu": null});
    c.overlay(&mut stats);
    assert_eq!(stats["gpu"], 50);
    assert_eq!(stats["gpuName"], "Card");
    let first = c.updated_at;
    c.finish_probe(None, true, 2000);
    assert!(c.disabled && c.stats.gpu.is_none() && c.updated_at > first);
    c.cache_full(&json!({"gpu": 9, "gpus": [{"index": 0, "name": "x", "utilization": 9, "memoryUsed": null, "memoryTotal": 1}]}), 3000);
    assert_eq!(c.stats.gpus.len(), 1);
    assert_eq!(c.next_at, 13_000);
}

struct FakeTransport {
    replies: Mutex<Vec<Result<StatsExecOutput, StatsExecError>>>,
    commands: Mutex<Vec<String>>,
    ping: Option<f64>,
}

impl FakeTransport {
    fn new(replies: Vec<Result<&str, StatsExecError>>) -> Self {
        Self {
            replies: Mutex::new(
                replies
                    .into_iter()
                    .rev()
                    .map(|r| {
                        r.map(|s| StatsExecOutput {
                            stdout: s.to_string(),
                            opened_after_ms: Some(4.4),
                        })
                    })
                    .collect(),
            ),
            commands: Mutex::new(Vec::new()),
            ping: Some(3.0),
        }
    }
}

#[async_trait]
impl StatsTransport for FakeTransport {
    async fn run(
        &self,
        command: &str,
        _timeout_ms: u64,
        _max: usize,
    ) -> Result<StatsExecOutput, StatsExecError> {
        self.commands.lock().unwrap().push(command.to_string());
        self.replies
            .lock()
            .unwrap()
            .pop()
            .unwrap_or(Err(StatsExecError::Other("no reply".into())))
    }
    async fn ping_ms(&self) -> Option<f64> {
        self.ping
    }
}

#[tokio::test]
async fn collect_runs_the_disk_probe_for_linux_only() {
    let t = FakeTransport::new(vec![
        Ok("NC_LATENCY_MARK|CPURAW:1000 900|CORES:4|MEMINFO:8000 4000 100 900 0 0"),
        Ok("DISKS:/:20:80:25:fs=ext4:/dev/sda1\n"),
    ]);
    let mut b = StatsBaseline::default();
    let r = collect_stats(&t, &mut b, false, || 5).await;
    assert_eq!(r["success"], true, "{r}");
    assert_eq!(r["stats"]["diskPercent"], 25);
    assert_eq!(r["stats"]["latencyMs"], 3);
    assert_eq!(r["stats"]["responseLatencyMs"], 4);
    assert_eq!(t.commands.lock().unwrap().len(), 2);

    let t = FakeTransport::new(vec![Ok(
        "NC_LATENCY_MARK|CPU:5|CORES:8|MEMINFO:1 1 0 0 0 0",
    )]);
    let r = collect_stats(&t, &mut StatsBaseline::default(), false, || 5).await;
    assert_eq!(r["stats"]["cpu"], 5);
    assert_eq!(t.commands.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn collect_maps_timeouts_and_disk_failures() {
    let t = FakeTransport::new(vec![Err(StatsExecError::Timeout)]);
    let r = collect_stats(&t, &mut StatsBaseline::default(), false, || 5).await;
    assert_eq!(
        r,
        json!({"success": false, "error": "Timeout getting server stats"})
    );
    let t = FakeTransport::new(vec![
        Ok("CPURAW:1 1|MEMINFO:1 1 1 1"),
        Err(StatsExecError::Other("channel closed".into())),
    ]);
    let r = collect_stats(&t, &mut StatsBaseline::default(), true, || 5).await;
    assert_eq!(r, json!({"success": false, "error": "channel closed"}));
}

#[cfg(unix)]
#[test]
fn real_shell_runs_the_linux_disk_parser() {
    // Feed the real awk program a fixed mount table + df output (same idea
    // as the Electron BusyBox tests): loop-backed images and FUSE mounts are
    // excluded, the root filesystem is kept.
    let awk_start = LINUX_DISK_STATS.find("awk '").unwrap();
    let awk_end = LINUX_DISK_STATS[awk_start..].find("' | sed").unwrap() + awk_start + 1;
    let awk = &LINUX_DISK_STATS[awk_start..awk_end];
    let table = "/dev/sda1 on / type ext4 (rw)\nrclone on /mnt/cloud type fuse.rclone (rw)\n__NETCATTY_DF__\nFilesystem Type 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 ext4 1048576 524288 524288 50% /\n/dev/loop3 squashfs 1024 1024 0 100% /snap/core/1\nrclone fuse.rclone 1073741824 1 1073741823 1% /mnt/cloud\n";
    let script = format!("printf '%s' {} | {awk}", quote_shell_arg(table));
    let out = std::process::Command::new("sh")
        .args(["-c", &script])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text, "/:0.500000:1.000000:50:fs=ext4:/dev/sda1,");
}
