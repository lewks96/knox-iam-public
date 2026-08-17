use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let sha = std::env::var("KNOX_GIT_SHA")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "--short", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string());

    let build_time = std::env::var("KNOX_BUILD_TIME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!("@{secs}")
        });

    println!("cargo:rustc-env=KNOX_GIT_SHA={sha}");
    println!("cargo:rustc-env=KNOX_BUILD_TIME={build_time}");
    println!("cargo:rerun-if-env-changed=KNOX_GIT_SHA");
    println!("cargo:rerun-if-env-changed=KNOX_BUILD_TIME");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
}
