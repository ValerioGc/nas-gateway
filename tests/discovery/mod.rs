use super::*;

#[test]
fn recognizes_only_versioned_queries_with_a_complete_nonce() {
    assert_eq!(
        query_nonce(b"NAS-OS-DISCOVER/1 1234567890abcdef"),
        Some("1234567890abcdef")
    );
    for invalid in [
        b"NAS-OS-DISCOVER/2 1234567890abcdef".as_slice(),
        b"NAS-OS-DISCOVER/1 short",
        b"NAS-OS-DISCOVER/1 1234567890abcdef\n",
        b"NAS-OS-DISCOVER/1 ................",
    ] {
        assert!(query_nonce(invalid).is_none());
    }
}

#[test]
fn exposes_a_domain_specific_identifier_without_the_machine_id() {
    let machine = "0123456789abcdef0123456789abcdef";
    let id = identity(machine).unwrap();
    assert_eq!(id.len(), 64);
    assert!(!id.contains(machine));
    assert_eq!(identity(&format!("{machine}\n")), Some(id));
    assert!(identity("").is_none());
    assert!(identity("not-a-machine-identifier").is_none());
}

#[test]
fn rejects_public_ipv6_and_privileged_reply_destinations() {
    assert!(local_peer("192.168.1.20:40000".parse().unwrap()));
    assert!(local_peer("169.254.1.20:40000".parse().unwrap()));
    assert!(!local_peer("8.8.8.8:40000".parse().unwrap()));
    assert!(!local_peer("192.168.1.20:53".parse().unwrap()));
    assert!(!local_peer("[::1]:40000".parse().unwrap()));
}

#[test]
fn replies_match_the_finder_contract_for_both_configuration_states() {
    let id = "a".repeat(64);
    assert_eq!(
        reply("1234567890abcdef", &id, "nas-studio", false, 80, false).unwrap(),
        format!("NAS-OS/1\n1234567890abcdef\n{id}\nnas-studio\nsetup\n80\nhttp\n")
    );
    let ready = reply("1234567890abcdef", &id, "nas-studio", true, 443, true).unwrap();
    assert!(ready.ends_with("ready\n443\nhttps\n"));
    assert!(ready.len() < 512);
}

#[test]
fn rejects_names_that_could_inject_fields_or_markup() {
    for name in ["", "nas\nready", "<script>", "nas with spaces"] {
        assert!(!valid_name(name));
        assert!(reply("1234567890abcdef", &"a".repeat(64), name, false, 80, false).is_none());
    }
    assert!(reply("1234567890abcdef", &"a".repeat(64), "nas", false, 0, false).is_none());
}

#[tokio::test]
async fn responds_to_local_queries_and_releases_the_port_on_handover() {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(respond(socket, "a".repeat(64), false, 80, false));
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    client
        .send_to(b"NAS-OS-DISCOVER/1 1234567890abcdef", address)
        .await
        .unwrap();
    let mut buffer = [0; 512];
    // A loaded machine may take its time: the answer is waited for, not raced.
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let reply = std::str::from_utf8(&buffer[..length]).unwrap();
    assert!(reply.starts_with("NAS-OS/1\n1234567890abcdef\n"));
    assert!(reply.ends_with("setup\n80\nhttp\n"));
    task.abort();
    let _ = task.await;
    // The port is free again. Another process of the machine may take a released ephemeral port
    // at once: then the port is no longer ours, and nothing of ours answers there.
    match UdpSocket::bind(address).await {
        Ok(rebound) => assert_eq!(rebound.local_addr().unwrap(), address),
        Err(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
            client
                .send_to(b"NAS-OS-DISCOVER/1 1234567890abcdef", address)
                .await
                .unwrap();
            let answered =
                tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buffer))
                    .await;
            assert!(
                !matches!(answered, Ok(Ok((length, _))) if buffer[..length].starts_with(b"NAS-OS/1"))
            );
        }
    }
}

#[tokio::test]
async fn malformed_queries_produce_no_reply() {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(respond(socket, "a".repeat(64), true, 443, true));
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    client
        .send_to(b"not a discovery query", address)
        .await
        .unwrap();
    let mut buffer = [0; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buffer))
            .await
            .is_err()
    );
    task.abort();
    let _ = task.await;
}
