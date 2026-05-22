// ONNX in child PID; IPC length-prefixed UTF-8 → u32 dim + f64[]. Seccomp profile TBD (Linux).

use parking_lot::Mutex;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const MAX_REQ: usize = 1 << 20;

struct WorkerConn {
    child: Child,
    stdin: BufWriter<std::process::ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
    expected_dims: usize,
}

impl WorkerConn {
    fn embed(&mut self, text: &str) -> Result<Vec<f64>, String> {
        let bytes = text.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_REQ {
            return Err(format!(
                "text length {} invalid (max {})",
                bytes.len(),
                MAX_REQ
            ));
        }
        let len = bytes.len() as u32;
        self.stdin
            .write_all(&len.to_le_bytes())
            .map_err(|e| e.to_string())?;
        self.stdin.write_all(bytes).map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;

        let mut dbuf = [0u8; 4];
        self.stdout
            .read_exact(&mut dbuf)
            .map_err(|e| format!("read dims: {e}"))?;
        let d = u32::from_le_bytes(dbuf) as usize;
        if d == 0 || d > 65_536 {
            return Err(format!("bad dim count {d}"));
        }
        if d != self.expected_dims {
            return Err(format!(
                "worker dims {d} != expected {}",
                self.expected_dims
            ));
        }
        let mut out = vec![0f64; d];
        for slot in &mut out {
            let mut b = [0u8; 8];
            self.stdout
                .read_exact(&mut b)
                .map_err(|e| format!("read vec: {e}"))?;
            *slot = f64::from_le_bytes(b);
        }
        Ok(out)
    }
}

impl Drop for WorkerConn {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn resolve_worker_bin() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("HALTCHAIN_MODEL_WORKER_BIN") {
        return Ok(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in ["haltchain-model-worker", "haltchain_model_worker"] {
                let c = dir.join(name);
                if c.exists() {
                    return Ok(c);
                }
            }
        }
    }
    Ok(PathBuf::from("haltchain-model-worker"))
}

pub struct ModelWorker {
    inner: Mutex<WorkerConn>,
}

impl ModelWorker {
    pub fn spawn(model_dir: &Path, expected_dims: usize) -> Result<Self, String> {
        let bin = resolve_worker_bin()?;
        let mut cmd = Command::new(&bin);
        cmd.arg(model_dir.as_os_str());
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().map_err(|e| format!("spawn {:?}: {e}", bin))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "child stdin".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "child stdout".to_string())?;
        Ok(Self {
            inner: Mutex::new(WorkerConn {
                child,
                stdin: BufWriter::new(stdin),
                stdout: BufReader::new(stdout),
                expected_dims,
            }),
        })
    }

    pub fn embed(&self, text: &str) -> Result<Vec<f64>, String> {
        self.inner.lock().embed(text)
    }
}

pub fn try_spawn_from_env(expected_dims: usize) -> Result<Option<ModelWorker>, String> {
    let v = std::env::var("HALTCHAIN_ONNX_SUBPROCESS").unwrap_or_default();
    let on = v == "1" || v.eq_ignore_ascii_case("true");
    if !on {
        return Ok(None);
    }
    let dir = std::env::var("HALTCHAIN_MODEL_DIR")
        .map_err(|_| "HALTCHAIN_ONNX_SUBPROCESS=1 requires HALTCHAIN_MODEL_DIR".to_string())?;
    let p = PathBuf::from(&dir);
    if !p.is_dir() {
        return Err(format!("HALTCHAIN_MODEL_DIR not a directory: {p:?}"));
    }
    Ok(Some(ModelWorker::spawn(&p, expected_dims)?))
}
