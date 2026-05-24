use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn serve_health_and_check() {
    let port = 9876u16;
    let mut child = Command::new(env!("CARGO_BIN_EXE_haltchain-mcp"))
        .args(["serve", "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn haltchain-mcp serve");

    thread::sleep(Duration::from_millis(500));

    let health = ureq::get(&format!("http://127.0.0.1:{port}/health"))
        .call()
        .expect("health request");
    assert_eq!(health.status(), 200);

    let check = ureq::post(&format!("http://127.0.0.1:{port}/check"))
        .send_json(ureq::json!({"tool": "read_file", "args": "{}"}))
        .expect("check request");
    assert_eq!(check.status(), 200);
    let body: serde_json::Value = check.into_json().expect("json body");
    assert_eq!(body["decision"], "allow");

    let blocked = ureq::post(&format!("http://127.0.0.1:{port}/check"))
        .send_json(ureq::json!({"tool": "exec_shell", "args": "{\"cmd\":\"rm -rf /\"}"}))
        .expect("blocked check request");
    assert_eq!(blocked.status(), 200);
    let blocked_body: serde_json::Value = blocked.into_json().expect("blocked json body");
    assert_eq!(blocked_body["decision"], "block");

    child.kill().ok();
}
