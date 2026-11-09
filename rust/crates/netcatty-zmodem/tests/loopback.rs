//! Netcatty's sender against Netcatty's receiver: a multi-file batch over an
//! in-memory "wire" that delivers bytes in odd-sized pieces.

use netcatty_zmodem::header::{self, FrameType, Header};
use netcatty_zmodem::session::{FileInfo, ReceiveEvent, ReceiveSession, SendEvent, SendSession};

fn deliver_rx(rx: &mut ReceiveSession, bytes: &[u8]) -> Vec<ReceiveEvent> {
    let mut events = Vec::new();
    for piece in bytes.chunks(97) {
        let (ev, garbage) = rx.consume(piece).expect("receiver accepts sender bytes");
        assert!(garbage.is_empty(), "unexpected garbage {garbage:?}");
        events.extend(ev);
    }
    events
}

fn deliver_tx(tx: &mut SendSession, bytes: &[u8]) -> Vec<SendEvent> {
    let mut events = Vec::new();
    for piece in bytes.chunks(5) {
        let (ev, garbage) = tx.consume(piece).expect("sender accepts receiver bytes");
        assert!(garbage.is_empty(), "unexpected garbage {garbage:?}");
        events.extend(ev);
    }
    events
}

#[test]
fn batch_of_files_round_trips() {
    let files: Vec<(String, Vec<u8>)> = vec![
        ("empty.bin".into(), Vec::new()),
        ("small.txt".into(), b"hello\r\n\x11\x13\x18 world".to_vec()),
        (
            "big.bin".into(),
            (0..200_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect(),
        ),
    ];

    let mut rx = ReceiveSession::new();
    rx.start();
    let zrinit = rx.take_outgoing();
    let (h, _) = header::parse_hex(&zrinit).unwrap().unwrap();
    let mut tx = SendSession::new(h).unwrap();

    let mut received: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, data) in &files {
        tx.offer(&FileInfo {
            name: name.clone(),
            size: Some(data.len() as u64),
            ..Default::default()
        })
        .unwrap();
        // ZSINIT (first file only) / ZFILE ⇄ ZACK / offer.
        let mut offered = None;
        for _ in 0..4 {
            let out = tx.take_outgoing();
            for e in deliver_rx(&mut rx, &out) {
                if let ReceiveEvent::Offer(info) = e {
                    offered = Some(info);
                }
            }
            if offered.is_some() {
                break;
            }
            let back = rx.take_outgoing();
            assert!(deliver_tx(&mut tx, &back).is_empty());
        }
        let info = offered.expect("offer reached the receiver");
        assert_eq!(info.name, *name);
        assert_eq!(info.size, Some(data.len() as u64));
        rx.accept(0).unwrap();
        let accepted = deliver_tx(&mut tx, &rx.take_outgoing());
        assert_eq!(accepted, vec![SendEvent::OfferAccepted { offset: 0 }]);

        let mut chunks = data.chunks(64 * 1024).peekable();
        if chunks.peek().is_none() {
            tx.send_data(&[], true).unwrap();
        }
        while let Some(chunk) = chunks.next() {
            tx.send_data(chunk, chunks.peek().is_none()).unwrap();
        }
        let mut got = Vec::new();
        let mut ended = false;
        for e in deliver_rx(&mut rx, &tx.take_outgoing()) {
            match e {
                ReceiveEvent::Data(d) => got.extend(d),
                ReceiveEvent::FileEnd => ended = true,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(ended, "{name}: no ZEOF");
        let confirmed = deliver_tx(&mut tx, &rx.take_outgoing());
        assert_eq!(confirmed, vec![SendEvent::FileReceived]);
        received.push((name.clone(), got));
    }

    tx.close().unwrap();
    let rx_events = deliver_rx(&mut rx, &tx.take_outgoing());
    assert_eq!(rx_events, vec![ReceiveEvent::SessionEnd]);
    let tx_events = deliver_tx(&mut tx, &rx.take_outgoing());
    assert_eq!(tx_events, vec![SendEvent::Closed]);
    assert!(tx.has_ended() && rx.has_ended());
    deliver_rx(&mut rx, &tx.take_outgoing());
    assert_eq!(rx.take_trailing(), b"OO".to_vec());
    assert_eq!(received, files);
}

#[test]
fn mid_file_zrpos_restarts_the_data_frame() {
    let mut tx = SendSession::new(Header::zrinit(0x63, 0)).unwrap();
    tx.offer(&FileInfo {
        name: "f".into(),
        size: Some(10),
        ..Default::default()
    })
    .unwrap();
    tx.take_outgoing();
    let ev = tx
        .consume(&Header::with_offset(FrameType::ZRPOS, 0).to_hex())
        .unwrap()
        .0;
    assert_eq!(ev, vec![SendEvent::OfferAccepted { offset: 0 }]);
    tx.send_data(b"01234", false).unwrap();
    tx.take_outgoing();
    let ev = tx
        .consume(&Header::with_offset(FrameType::ZRPOS, 2).to_hex())
        .unwrap()
        .0;
    assert_eq!(ev, vec![SendEvent::Reposition { offset: 2 }]);
    tx.reposition(2);
    tx.send_data(b"23456789", true).unwrap();
    let wire = tx.take_outgoing();
    let (h, _, _) = header::parse(&wire).unwrap().unwrap();
    assert_eq!((h.frame, h.offset()), (FrameType::ZDATA, 2));
}
