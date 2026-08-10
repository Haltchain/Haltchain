use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn serve_health_and_check() {
    // Use port 0 so the OS picks a free port; read it back from the first stdout line.
    let mut child = Command::new(env!("CARGO_BIN_EXE_haltchain-mcp"))
        .args(["serve", "--port", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn haltchain-mcp serve");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut first_line = String::new();
    reader.read_line(&mut first_line).expect("read first line");

    // parse port from "haltchain-mcp listening on http://127.0.0.1:PORT"
    let port: u16 = first_line
        .trim()
        .rsplit(':')
        .next()
        .and_then(|s| s.parse().ok())
        .expect(&format!("failed to parse port from: {first_line:?}"));

    // poll until the port accepts connections (max 3s)
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            child.kill().ok();
            panic!("server never became ready on port {port}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let health = ureq::get(&format!("http://127.0.0.1:{port}/health"))
        .call()
        .expect("health request");
    assert_eq!(health.status(), 200);

    let check = ureq::post(&format!("http://127.0.0.1:{port}/check"))
        .send_json(ureq::json!({"tool": "read_file", "args": "{}"}))
        .expect("check request");
    assert_eq!(check.status(), 200);
    let body: serde_json::Value = check.into_json().expect("json body");
    // With no baseline, read_file now returns "block" (no-baseline-configured).
    // That is the correct fail-closed behaviour — test that it blocks, not allows.
    assert_eq!(body["decision"], "block", "expected block with no baseline: {body}");

    let blocked = ureq::post(&format!("http://127.0.0.1:{port}/check"))
        .send_json(ureq::json!({"tool": "exec_shell", "args": "{\"cmd\":\"rm -rf /\"}"}))
        .expect("blocked check request");
    assert_eq!(blocked.status(), 200);
    let blocked_body: serde_json::Value = blocked.into_json().expect("blocked json body");
    assert_eq!(blocked_body["decision"], "block");

    child.kill().ok();
    let _ = child.wait();
}
