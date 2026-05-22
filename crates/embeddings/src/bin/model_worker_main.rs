// Child process: ONNX in isolated PID. Parent talks length-prefixed UTF-8 → f64[].
// Seccomp: load profile before heavy work (Linux); see Roadmap D.

use haltchain_embeddings::onnx_model::OnnxModel;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: haltchain-model-worker <model_dir>");
    let t0 = Instant::now();
    let mut model = OnnxModel::from_dir(Path::new(&dir)).unwrap_or_else(|e| {
        eprintln!("haltchain-model-worker: load failed: {e}");
        std::process::exit(2);
    });
    eprintln!(
        "haltchain-model-worker: ready in {:?} (dims={})",
        t0.elapsed(),
        model.dims()
    );

    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    const MAX_REQ: usize = 1 << 20;

    loop {
        let mut len_b = [0u8; 4];
        if stdin.read_exact(&mut len_b).is_err() {
            break;
        }
        let n = u32::from_le_bytes(len_b) as usize;
        if n == 0 || n > MAX_REQ {
            break;
        }
        let mut buf = vec![0u8; n];
        if stdin.read_exact(&mut buf).is_err() {
            break;
        }
        let text = String::from_utf8_lossy(&buf);
        let v = model.embed_text(text.as_ref());
        let d = v.len() as u32;
        if stdout.write_all(&d.to_le_bytes()).is_err() {
            break;
        }
        for x in &v {
            if stdout.write_all(&x.to_le_bytes()).is_err() {
                std::process::exit(3);
            }
        }
        let _ = stdout.flush();
    }
}
