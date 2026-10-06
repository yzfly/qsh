//! The hub end to end: several terminals in one resident client share one connection to the
//! server; when it dies, all of them resume over one new connection without losing output.

mod common;

use std::time::Duration;

use common::*;
use qsh_core::client::{Input, Terminal};
use qsh_core::hub::{self, HubConfig, OpenRequest, Request};
use qsh_core::Paths;
use tokio::sync::mpsc;

struct Term {
    input: mpsc::Sender<Input>,
    output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    exit: tokio::task::JoinHandle<Option<i32>>,
}

impl Term {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }

    async fn wait_for(&self, needle: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while !self.text().contains(needle) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "no {needle:?} in {:?}",
                self.text()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn open(paths: &Paths, world: &World, command: &str) -> Term {
    let request = OpenRequest {
        destination: "srv".into(),
        ssh_program: Some(world.dir.join("bin/ssh").display().to_string()),
        command: Some(command.into()),
        cols: 80,
        rows: 24,
        ..Default::default()
    };
    let (input, input_rx) = mpsc::channel(64);
    let (output_tx, mut output_rx) = mpsc::channel::<Vec<u8>>(64);
    let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = output.clone();
    tokio::spawn(async move {
        while let Some(bytes) = output_rx.recv().await {
            sink.lock().unwrap().extend_from_slice(&bytes);
        }
    });
    let paths = paths.clone();
    let exit = tokio::spawn(async move {
        let terminal = Terminal {
            input: input_rx,
            output: output_tx,
            events: None,
        };
        hub::open(&paths, &request, terminal).await.unwrap()
    });
    Term { input, output, exit }
}

#[test]
fn hub_sessions_share_one_connection_and_resume_together() {
    let world = World::new("hub");
    // The hub runs in this process: the ssh it starts needs the world's environment
    for (k, v) in &world.env {
        std::env::set_var(k, v);
    }
    let paths = Paths::under(&world.dir.join("hubd"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let hub_paths = paths.clone();
        tokio::spawn(async move {
            hub::run(
                &hub_paths,
                HubConfig {
                    idle_exit: Duration::from_secs(60),
                },
            )
            .await
        });
        let socket = paths.hub_socket();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::net::UnixStream::connect(&socket).await.is_err() {
            assert!(tokio::time::Instant::now() < deadline, "the hub did not start");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let t1 = open(&paths, &world, "echo hi-1; exec cat");
        t1.wait_for("hi-1").await;
        let t2 = open(&paths, &world, "echo hi-2; exec cat");
        // Under sh: how the login shell reacts to SIGHUP differs (zsh exits 1)
        let t3 = open(&paths, &world, &format!("exec sh -c '{TICKER}'"));
        t2.wait_for("hi-2").await;
        t3.wait_for("tick-5\r").await;
        assert!(
            !t1.text().contains("hi-2") && !t2.text().contains("hi-1"),
            "outputs mixed up"
        );
        t1.input.send(Input::Data(b"ping-1\n".to_vec())).await.unwrap();
        t2.input.send(Input::Data(b"ping-2\n".to_vec())).await.unwrap();
        t1.wait_for("ping-1").await;
        t2.wait_for("ping-2").await;

        let stats = world.stats();
        assert_eq!(stats["quic_connections"], 1, "one connection for all: {stats}");
        assert_eq!(stats["channels"], 3, "{stats}");
        let status = hub::request(&paths, Request::Status).await.unwrap().unwrap();
        assert_eq!(status["sessions"].as_array().unwrap().len(), 3, "{status}");
        assert_eq!(status["connections"].as_array().unwrap().len(), 1, "{status}");

        // The shared connection dies: every session resumes over one new connection, and the
        // ticker's output arrives complete and in order
        let before = ticks(&t3.text()).last().copied().unwrap();
        assert_eq!(hub::request(&paths, Request::Reset).await.unwrap().unwrap()["ok"], true);
        t1.input.send(Input::Data(b"after-1\n".to_vec())).await.unwrap();
        t1.wait_for("after-1").await;
        t3.wait_for(&format!("tick-{}\r", before + 40)).await;
        let seen = ticks(&t3.text());
        let expected: Vec<u64> = (1..=*seen.last().unwrap()).collect();
        assert_eq!(seen, expected, "ticks lost or repeated across the reconnect");
        let stats = world.stats();
        assert_eq!(stats["quic_connections"], 2, "{stats}");

        // Exit statuses pass through the hub; a client that detaches leaves its session
        t1.input.send(Input::Data(b"\x04".to_vec())).await.unwrap();
        assert_eq!(t1.exit.await.unwrap(), Some(0));
        t2.input.send(Input::Detach).await.unwrap();
        assert_eq!(t2.exit.await.unwrap(), Some(0));
        t3.input.send(Input::Hangup).await.unwrap();
        assert_eq!(t3.exit.await.unwrap(), Some(129));
        let sessions = world.status().unwrap()["sessions"].clone();
        assert_eq!(
            sessions.as_array().unwrap().len(),
            1,
            "only the detached one is left: {sessions}"
        );
    });
    runtime.shutdown_timeout(Duration::from_secs(1));
}
