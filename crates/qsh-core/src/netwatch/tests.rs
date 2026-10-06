use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn home_wifi() -> NetSnapshot {
    NetSnapshot {
        ipv4: Some(DefaultRoute {
            interface: "wlan0".into(),
            source: "192.168.1.217".parse().unwrap(),
            gateway: Some("192.168.1.1".parse().unwrap()),
        }),
        ipv6: Some(DefaultRoute {
            interface: "wlan0".into(),
            source: "2001:db8:1:2:a1b2:c3d4:e5f6:1234".parse().unwrap(),
            gateway: Some("fe80::1".parse().unwrap()),
        }),
        addresses: vec!["192.168.1.217".parse().unwrap(), "2001:db8:1:2::".parse().unwrap()],
    }
}

#[test]
fn fingerprint_is_stable() {
    let a = home_wifi();
    assert_eq!(a.fingerprint(), a.clone().fingerprint());
    // Pinned: the fingerprint is a key on disk (path memory); format v1 must not drift
    assert_eq!(a.fingerprint().to_string(), PINNED_HOME_WIFI);
    assert_eq!(a.fingerprint().to_string().len(), 32);
}

const PINNED_HOME_WIFI: &str = "0c6b8633231596b0ecd79b4fe78cf1be";

#[test]
fn fingerprint_ignores_privacy_address_rotation() {
    let a = home_wifi();
    let mut b = a.clone();
    b.ipv6.as_mut().unwrap().source = "2001:db8:1:2:ffff:eeee:dddd:cccc".parse().unwrap();
    assert_eq!(a.fingerprint(), b.fingerprint());
}

#[test]
fn fingerprint_tells_networks_apart() {
    let a = home_wifi();
    let mut gateway = a.clone();
    gateway.ipv4.as_mut().unwrap().gateway = Some("192.168.1.254".parse().unwrap());
    let mut interface = a.clone();
    interface.ipv4.as_mut().unwrap().interface = "eth0".into();
    let mut no_v6 = a.clone();
    no_v6.ipv6 = None;
    let mut prefix = a.clone();
    prefix.addresses[1] = "2001:db8:1:3::".parse().unwrap();
    let all = [&a, &gateway, &interface, &no_v6, &prefix, &NetSnapshot::default()];
    for (i, x) in all.iter().enumerate() {
        for y in &all[i + 1..] {
            assert_ne!(x.fingerprint(), y.fingerprint(), "{x:?} vs {y:?}");
        }
    }
    assert!(!NetSnapshot::default().is_online());
    assert_eq!(NetSnapshot::default().to_string(), "offline");
    assert_eq!(
        a.to_string(),
        "wlan0 from 192.168.1.217 via 192.168.1.1, wlan0 from 2001:db8:1:2:a1b2:c3d4:e5f6:1234 via fe80::1"
    );
}

#[test]
fn route_addresses_are_sorted_cut_and_filtered() {
    let entry = |interface: &str, address: &str| sys::InterfaceAddress {
        interface: interface.into(),
        address: address.parse().unwrap(),
        up: true,
        loopback: interface == "lo",
    };
    let interfaces = [
        entry("lo", "127.0.0.1"),
        entry("wlan0", "fe80::1234"),
        entry("wlan0", "2001:db8:1:2::aaaa"),
        entry("wlan0", "2001:db8:1:2::bbbb"),
        entry("wlan0", "192.168.1.217"),
        entry("docker0", "172.17.0.1"),
    ];
    let route = Some(DefaultRoute {
        interface: "wlan0".into(),
        source: "192.168.1.217".parse().unwrap(),
        gateway: None,
    });
    let addresses = route_addresses(&interfaces, [&route, &None]);
    let expected: Vec<IpAddr> = vec!["192.168.1.217".parse().unwrap(), "2001:db8:1:2::".parse().unwrap()];
    assert_eq!(addresses, expected);
}

// Captured from a Linux 6.8 host with an RTM_GETROUTE / RTM_GETADDR dump (the kernel sends the
// same RTM_NEWROUTE / RTM_NEWADDR messages to the multicast groups); little-endian.
/// default via 192.168.1.1 dev eth0, main table
const DEFAULT_ROUTE: &str =
    "340000001800020001000000612e3b0002000000fe0400010000000008000f00fe00000008000500c0a801010800040002000000";
/// 192.168.1.0/24 dev eth0, main table
const SUBNET_ROUTE: &str = "3c0000001800020001000000612e3b0002180000fe02fd010000000008000f00fe00000008000100c0a8010008000700c0a801d90800040002000000";
/// local 127.0.0.1, local table
const LOCAL_ROUTE: &str = "3c0000001800020001000000612e3b0002200000ff02fe020000000008000f00ff000000080001007f000001080007007f0000010800040001000000";
/// 192.168.1.217/24 on eth0
const ADDRESS: &str = "580000001400020001000000612e3b00021880000200000008000100c0a801d908000200c0a801d908000400c0a801ff090003006574683000000000080008008000000014000600ffffffffffffffff4605000046050000";

/// An RTM_NEWLINK for interface 3 with one attribute.
fn link_message(attribute_type: u16, change: u32) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&(16u32 + 16 + 8).to_ne_bytes());
    m.extend_from_slice(&RTM_NEWLINK.to_ne_bytes());
    m.extend_from_slice(&0u16.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    // ifinfomsg: family, pad, type, index, flags, change
    m.extend_from_slice(&[0, 0]);
    m.extend_from_slice(&1u16.to_ne_bytes());
    m.extend_from_slice(&3i32.to_ne_bytes());
    m.extend_from_slice(&0x1043u32.to_ne_bytes());
    m.extend_from_slice(&change.to_ne_bytes());
    m.extend_from_slice(&8u16.to_ne_bytes());
    m.extend_from_slice(&attribute_type.to_ne_bytes());
    m.extend_from_slice(&[0; 4]);
    m
}

#[cfg(target_endian = "little")]
#[test]
fn netlink_messages_are_classified() {
    assert!(netlink_relevant(&hex(DEFAULT_ROUTE)));
    assert!(!netlink_relevant(&hex(SUBNET_ROUTE)));
    assert!(!netlink_relevant(&hex(LOCAL_ROUTE)));
    assert!(netlink_relevant(&hex(ADDRESS)));
    // Several messages in one datagram: the relevant one is found after the others
    let mut batch = hex(SUBNET_ROUTE);
    batch.extend(hex(LOCAL_ROUTE));
    assert!(!netlink_relevant(&batch));
    batch.extend(hex(DEFAULT_ROUTE));
    assert!(netlink_relevant(&batch));
}

#[test]
fn netlink_link_messages_skip_wireless_events() {
    assert!(!netlink_relevant(&link_message(IFLA_WIRELESS, 0)));
    // IFLA_OPERSTATE: the carrier came or went
    assert!(netlink_relevant(&link_message(16, 0)));
    let mut deleted = link_message(16, 0);
    deleted[4..6].copy_from_slice(&RTM_DELLINK.to_ne_bytes());
    assert!(netlink_relevant(&deleted));
}

#[test]
fn netlink_garbage_counts_as_a_change() {
    assert!(!netlink_relevant(&[]));
    // Shorter than a header, a length beyond the datagram, a length below the header's
    assert!(netlink_relevant(&[1, 2, 3]));
    let mut long = link_message(16, 0);
    long[0..4].copy_from_slice(&1000u32.to_ne_bytes());
    assert!(netlink_relevant(&long));
    let mut short = link_message(16, 0);
    short[0..4].copy_from_slice(&8u32.to_ne_bytes());
    assert!(netlink_relevant(&short));
    // A route message too short for its rtmsg
    let mut route = Vec::new();
    route.extend_from_slice(&20u32.to_ne_bytes());
    route.extend_from_slice(&RTM_NEWROUTE.to_ne_bytes());
    route.extend_from_slice(&[0; 14]);
    assert!(netlink_relevant(&route));
    // Done and other kinds: not about the network
    let mut done = Vec::new();
    done.extend_from_slice(&20u32.to_ne_bytes());
    done.extend_from_slice(&3u16.to_ne_bytes());
    done.extend_from_slice(&[0; 14]);
    assert!(!netlink_relevant(&done));
}

/// A macOS routing message: rt_msghdr up to rtm_flags, padded to `len`.
fn route_message(kind: u8, flags: u32, len: u16) -> Vec<u8> {
    let mut m = vec![0u8; len as usize];
    m[0..2].copy_from_slice(&len.to_ne_bytes());
    m[2] = 5; // RTM_VERSION
    m[3] = kind;
    if m.len() >= 12 {
        m[8..12].copy_from_slice(&flags.to_ne_bytes());
    }
    m
}

#[test]
fn route_socket_messages_are_classified() {
    // A default route added: RTF_UP | RTF_GATEWAY | RTF_STATIC
    assert!(route_message_relevant(&route_message(RTM_ADD, 0x803, 92)));
    // An ARP entry: RTF_HOST | RTF_LLINFO | RTF_WASCLONED
    assert!(!route_message_relevant(&route_message(RTM_ADD, 0x20405, 92)));
    assert!(!route_message_relevant(&route_message(RTM_DELETE, 0x20405, 92)));
    assert!(route_message_relevant(&route_message(RTM_NEWADDR_BSD, 0, 20)));
    assert!(route_message_relevant(&route_message(RTM_DELADDR_BSD, 0, 20)));
    assert!(route_message_relevant(&route_message(RTM_IFINFO, 0, 112)));
    // RTM_MISS, RTM_GET and friends
    assert!(!route_message_relevant(&route_message(0x7, 0, 92)));
    assert!(!route_message_relevant(&[]));
    assert!(route_message_relevant(&[9]));
    assert!(route_message_relevant(&route_message(RTM_ADD, 0, 8)));
    let mut wrong = route_message(RTM_IFINFO, 0, 112);
    wrong[0..2].copy_from_slice(&200u16.to_ne_bytes());
    assert!(route_message_relevant(&wrong));
}

#[test]
fn proc_routes_are_parsed() {
    // Captured from a Linux 6.8 host (little-endian), with a second default route added
    let v4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
              eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
              eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
              wwan0\t00000000\t00000000\t0001\t0\t0\t700\t00000000\t0\t0\t0\n";
    let routes = parse_ipv4_route(v4);
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[1].gateway, None);
    assert_eq!(routes[1].metric, 700);
    if cfg!(target_endian = "little") {
        assert_eq!(
            routes[0],
            ProcRoute {
                interface: "eth0".into(),
                gateway: Some("192.168.1.1".parse().unwrap()),
                metric: 100,
            }
        );
    }
    let v6 = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n\
              00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n\
              00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000021122fffe334455 00000400 00000001 00000000 00000003    wlan0\n";
    assert_eq!(
        parse_ipv6_route(v6),
        vec![ProcRoute {
            interface: "wlan0".into(),
            gateway: Some("fe80::211:22ff:fe33:4455".parse().unwrap()),
            metric: 1024,
        }]
    );
    assert!(parse_ipv4_route("").is_empty());
    assert!(parse_ipv6_route("garbage\n1 2 3\n").is_empty());
}

#[test]
fn snapshot_of_this_host() {
    let a = NetSnapshot::take();
    let b = NetSnapshot::take();
    // Unless the network changed in between, which a test host does not do
    assert_eq!(a.fingerprint(), b.fingerprint(), "{a} / {b}");
    if let Some(route) = &a.ipv4 {
        assert!(route.source.is_ipv4());
        assert!(!a.addresses.is_empty() || route.interface.is_empty());
    }
}

/// A fake network: the snapshot the watcher sees, and how often it looked.
#[derive(Clone)]
struct Fake {
    snapshot: Arc<Mutex<NetSnapshot>>,
    looks: Arc<AtomicUsize>,
}

impl Fake {
    fn new() -> Fake {
        Fake {
            snapshot: Arc::new(Mutex::new(home_wifi())),
            looks: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn source(&self) -> Arc<dyn Fn() -> NetSnapshot + Send + Sync> {
        let fake = self.clone();
        Arc::new(move || {
            fake.looks.fetch_add(1, Ordering::SeqCst);
            fake.snapshot.lock().unwrap().clone()
        })
    }

    fn switch_to_cellular(&self) {
        *self.snapshot.lock().unwrap() = NetSnapshot {
            ipv4: Some(DefaultRoute {
                interface: "rmnet0".into(),
                source: "10.64.3.9".parse().unwrap(),
                gateway: None,
            }),
            ipv6: None,
            addresses: vec!["10.64.3.9".parse().unwrap()],
        };
    }

    fn looks(&self) -> usize {
        self.looks.load(Ordering::SeqCst)
    }
}

fn start_fake(fake: &Fake) -> (NetWatch, mpsc::Sender<()>) {
    let (tx, rx) = mpsc::channel(1);
    let watch = NetWatch::start(
        &tokio::runtime::Handle::current(),
        Some((rx, Mechanism::Netlink)),
        fake.source(),
        Options::default(),
    );
    (watch, tx)
}

#[tokio::test(start_paused = true)]
async fn a_change_is_reported_after_the_messages_settle() {
    let fake = Fake::new();
    let (mut watch, kicks) = start_fake(&fake);
    let before = watch.fingerprint();
    assert_eq!(watch.mechanism(), Mechanism::Netlink);
    fake.switch_to_cellular();
    let started = Instant::now();
    kicks.send(()).await.unwrap();
    let change = watch.changed().await;
    let waited = started.elapsed();
    assert!(waited >= DEBOUNCE && waited < DEBOUNCE * 2, "{waited:?}");
    assert_eq!(change.previous, before);
    assert_eq!(change.fingerprint, fake.snapshot.lock().unwrap().fingerprint());
    assert_eq!(change.snapshot.ipv4.as_ref().unwrap().interface, "rmnet0");
    assert_eq!(watch.fingerprint(), change.fingerprint);
}

#[tokio::test(start_paused = true)]
async fn a_burst_of_messages_is_one_look_within_the_maximum() {
    let fake = Fake::new();
    let (mut watch, kicks) = start_fake(&fake);
    let initial = fake.looks();
    fake.switch_to_cellular();
    let started = Instant::now();
    let sender = tokio::spawn(async move {
        // A message every 100 ms for 3 s: never quiet for 250 ms
        for _ in 0..30 {
            let _ = kicks.try_send(());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        kicks
    });
    watch.changed().await;
    let waited = started.elapsed();
    assert!(waited >= DEBOUNCE_MAX && waited < DEBOUNCE_MAX + DEBOUNCE, "{waited:?}");
    let _kicks = sender.await.unwrap();
    // About one look per second of the burst, not one per message
    let looks = fake.looks() - initial;
    assert!((2..=5).contains(&looks), "{looks} looks");
}

#[tokio::test(start_paused = true)]
async fn messages_without_a_change_report_nothing() {
    let fake = Fake::new();
    let (mut watch, kicks) = start_fake(&fake);
    let initial = fake.looks();
    kicks.send(()).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(10), watch.changed()).await;
    assert!(r.is_err(), "no change expected");
    assert_eq!(fake.looks(), initial + 1);
}

#[tokio::test(start_paused = true)]
async fn a_dead_reader_falls_back_to_polling() {
    let fake = Fake::new();
    let (mut watch, kicks) = start_fake(&fake);
    drop(kicks);
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(watch.mechanism(), Mechanism::Polling);
    fake.switch_to_cellular();
    let started = Instant::now();
    watch.changed().await;
    assert!(started.elapsed() <= POLL_INTERVAL, "{:?}", started.elapsed());
}

#[tokio::test(start_paused = true)]
async fn check_now_looks_at_once() {
    let fake = Fake::new();
    let (mut watch, _kicks) = start_fake(&fake);
    fake.switch_to_cellular();
    let started = Instant::now();
    watch.check_now();
    watch.changed().await;
    assert!(started.elapsed() < Duration::from_millis(10), "{:?}", started.elapsed());
}

#[tokio::test(start_paused = true)]
async fn every_clone_sees_the_change_and_the_last_one_stops_the_watcher() {
    let fake = Fake::new();
    let (mut a, kicks) = start_fake(&fake);
    let mut b = a.clone();
    fake.switch_to_cellular();
    a.check_now();
    let (x, y) = tokio::join!(a.changed(), b.changed());
    assert_eq!(x.fingerprint, y.fingerprint);
    drop(a);
    drop(b);
    // The watcher's task ends and drops its end of the messages
    tokio::time::timeout(Duration::from_secs(1), kicks.closed())
        .await
        .expect("watcher stopped");
}

#[tokio::test]
async fn the_real_watcher_starts() {
    let watch = NetWatch::spawn().unwrap();
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        // Polling only where a sandbox forbids the socket
        eprintln!("mechanism: {}", watch.mechanism());
    } else {
        assert_eq!(watch.mechanism(), Mechanism::Polling);
    }
    assert_eq!(watch.fingerprint(), watch.snapshot().fingerprint());
    let polling = NetWatch::spawn_with(Options {
        kernel_events: false,
        ..Options::default()
    })
    .unwrap();
    assert_eq!(polling.mechanism(), Mechanism::Polling);
}

#[test]
fn spawn_needs_a_runtime() {
    assert!(NetWatch::spawn().is_err());
}

#[test]
fn parsers_take_any_bytes() {
    let mut rng = crate::testutil::Rng::new(7);
    for _ in 0..5000 {
        let len = rng.range(0, 200) as usize;
        let mut data = rng.bytes(len);
        // Plausible lengths in the headers now and then, so the loops run more than once
        if data.len() >= 4 && rng.range(0, 2) == 0 {
            let n = rng.range(0, data.len() as u64 + 8);
            data[0..4].copy_from_slice(&(n as u32).to_ne_bytes());
            data[0..2].copy_from_slice(&(n as u16).to_ne_bytes());
        }
        let _ = netlink_relevant(&data);
        let _ = route_message_relevant(&data);
    }
}
