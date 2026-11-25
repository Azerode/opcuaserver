//! The subscription hot path (sample, queue, encode a NotificationMessage,
//! acknowledge) must not touch the heap once warmed up.

use fastua::address_space::{NodeKind, ServerInfo, ValueSource};
use fastua::codec::Writer;
use fastua::reload::Store;
use fastua::server::Limits;
use fastua::subscription::{ItemParams, PublishRequest, SessionSubs, SubParams, Subscription};
use fastua::types::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counting = Counting;

#[test]
fn steady_state_publishing_does_not_allocate() {
    let dir = std::env::temp_dir().join(format!("fastua-noalloc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut items = String::new();
    for i in 0..100 {
        if i > 0 {
            items.push(',');
        }
        items.push_str(&format!(r#"{{ "Name": "V{i}", "NodeId": "ns=2;i={}", "Type": "Double" }}"#, i + 1));
    }
    std::fs::write(
        dir.join("m.json"),
        format!(
            r#"{{ "Name": "M", "Namespace": "urn:m", "Subscriptions": [ {{ "Name": "G", "Items": [{items}] }} ] }}"#
        ),
    )
    .unwrap();
    let store = Store::open(&dir, ServerInfo::default()).unwrap();
    let space = store.load_full();
    let cells: Vec<_> = (1..=100)
        .map(|i| match &space.get(&NodeId::Numeric(2, i)).unwrap().kind {
            NodeKind::Variable { value: ValueSource::Cell(c), .. } => c.clone(),
            _ => unreachable!(),
        })
        .collect();

    let l = Limits::default();
    let mut st = SessionSubs::default();
    let mut sub = Subscription::new(1, SubParams::revise(&l, 1.0, 1000, 10, 0, 0), true, 0);
    for i in 0..100u32 {
        let p = ItemParams {
            client_handle: i,
            sampling_ms: 1.0,
            filter: Default::default(),
            percent_deadband: false,
            filter_present: false,
            queue_size: 4,
            discard_oldest: true,
        };
        sub.create_item(&l, &space, NodeId::Numeric(2, i + 1), 13, 2, (true, true), &p, true, 0).unwrap();
    }
    st.subs.push(sub);

    let mut out: Vec<u8> = Vec::with_capacity(1 << 16);
    let mut now = 0u64;
    let mut seq_to_ack = None;
    let mut run = |rounds: usize, st: &mut SessionSubs| {
        for round in 0..rounds {
            // Half of the values change every millisecond.
            for (i, c) in cells.iter().enumerate() {
                if i % 2 == round % 2 {
                    c.write(&Variant::Double((round * 1000 + i) as f64), status::GOOD, 1, 2);
                }
            }
            now += 1_000_000;
            let mut acks = st.ack_buffer();
            if let Some(seq) = seq_to_ack.take() {
                acks.push(st.acknowledge(1, seq));
            }
            st.queue(&l, PublishRequest { request_id: 1, channel_id: 1, handle: 1, deadline: u64::MAX, acks })
                .map_err(|_| ())
                .unwrap();
            st.tick(now, &space);
            out.clear();
            let ready = st.write_next(&l, now, 1, 1 << 20, &mut Writer::new(&mut out));
            assert!(ready.is_some());
            assert!(out.len() > 50 * 25, "50 notifications expected, {} bytes", out.len());
            // The message sequence number sits after type id (4), header
            // (28), subscription id (4), the available array and `more`.
            let n = u32::from_le_bytes(out[36..40].try_into().unwrap()) as usize;
            let at = 40 + 4 * n + 1;
            seq_to_ack = Some(u32::from_le_bytes(out[at..at + 4].try_into().unwrap()));
        }
    };
    run(200, &mut st); // warm-up: queues, pools and buffers reach their size
    let before = ALLOCS.load(Ordering::Relaxed);
    run(1000, &mut st);
    let allocated = ALLOCS.load(Ordering::Relaxed) - before;
    assert_eq!(allocated, 0, "{allocated} allocations in 1000 publish cycles");
}
