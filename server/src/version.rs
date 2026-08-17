use serde::Serialize;

pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_SHA: &str = env!("KNOX_GIT_SHA");
pub const BUILD_TIME: &str = env!("KNOX_BUILD_TIME");

#[derive(Serialize)]
pub struct VersionInfo {
    pub version: &'static str,
    pub git_sha: &'static str,
    pub build_time: &'static str,
}

pub const fn info() -> VersionInfo {
    VersionInfo {
        version: PKG_VERSION,
        git_sha: GIT_SHA,
        build_time: BUILD_TIME,
    }
}
