//! Throughput benchmarks for the dissection hot path.
//!
//! Run with `cargo bench`. The headline number the README quotes is `pipeline/mixed`, which
//! measures packets/sec through the full read → dissect → flow path.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use pcapracer::dissect::{dissect_frame, Ctx};
use pcapracer::pipeline::{run, Config};
use pcapracer::schema::Packet;

fn eth_ip_tcp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    v.extend_from_slice(&[0x08, 0x00]);

    let total = 40 + payload.len();
    v.extend_from_slice(&[
        0x45,
        0,
        (total >> 8) as u8,
        total as u8,
        0,
        1,
        0x40,
        0,
        64,
        6,
        0,
        0,
        10,
        0,
        0,
        5,
        93,
        184,
        216,
        34,
    ]);
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&1000u32.to_be_bytes());
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    v.extend_from_slice(payload);
    v
}

fn eth_ip_udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    v.extend_from_slice(&[0x08, 0x00]);
    let total = 28 + payload.len();
    v.extend_from_slice(&[
        0x45,
        0,
        (total >> 8) as u8,
        total as u8,
        0,
        1,
        0x40,
        0,
        64,
        17,
        0,
        0,
        10,
        0,
        0,
        5,
        8,
        8,
        8,
        8,
    ]);
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    v
}

fn dns_query() -> Vec<u8> {
    let mut v = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    v.extend_from_slice(&[3, b'w', b'w', b'w', 7]);
    v.extend_from_slice(b"example");
    v.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
    v
}

fn bench_single_packet(c: &mut Criterion) {
    let http = eth_ip_tcp(
        50000,
        80,
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\n\r\n",
    );
    let dns = eth_ip_udp(40000, 53, &dns_query());
    let bare = eth_ip_tcp(50000, 80, &[]);

    let mut group = c.benchmark_group("packet");
    for (name, frame) in [("http", &http), ("dns", &dns), ("tcp-ack-only", &bare)] {
        group.throughput(Throughput::Bytes(frame.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), frame, |b, frame| {
            let mut pkt = Packet::default();
            b.iter(|| {
                pkt.clear();
                let mut ctx = Ctx::new(&mut pkt);
                let _ = dissect_frame(frame, 1, &mut ctx);
                ctx.finish();
            });
        });
    }
    group.finish();
}

fn build_capture(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(&0i32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&65535u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());

    let http = eth_ip_tcp(
        50000,
        80,
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\n\r\n",
    );
    let dns = eth_ip_udp(40000, 53, &dns_query());

    for i in 0..n {
        let frame = if i % 2 == 0 { &http } else { &dns };
        v.extend_from_slice(&(i as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        v.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        v.extend_from_slice(frame);
    }
    v
}

fn bench_pipeline(c: &mut Criterion) {
    const PACKETS: usize = 100_000;
    let mut path = std::env::temp_dir();
    path.push("pcapracer-bench.pcap");
    std::fs::write(&path, build_capture(PACKETS)).unwrap();

    let mut group = c.benchmark_group("pipeline");
    group.sample_size(10);
    group.throughput(Throughput::Elements(PACKETS as u64));

    for (name, cfg) in [
        ("mixed", Config::default()),
        (
            "no-reassembly",
            Config {
                reassemble: false,
                ..Default::default()
            },
        ),
        (
            "single-thread",
            Config {
                threads: 1,
                ..Default::default()
            },
        ),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| {
                let mut rows = 0usize;
                run(&path, cfg.clone(), |batch| {
                    rows += batch.num_rows();
                    Ok(())
                })
                .unwrap();
                assert_eq!(rows, PACKETS);
            });
        });
    }
    group.finish();
    std::fs::remove_file(path).ok();
}

criterion_group!(benches, bench_single_packet, bench_pipeline);
criterion_main!(benches);
