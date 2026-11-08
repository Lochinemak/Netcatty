//! MCP helper modes of the Netcatty executable (`--mcp-server`,
//! `--tool-cli ...`, and the External MCP stdio server started by clients
//! with `NETCATTY_MCP_HELPER=external`). Runs before any window is created;
//! see `netcatty_mcp::stdio_server::run_if_requested`.

/// `Some(exit_code)` when this process was started as an MCP helper.
pub fn run_if_requested() -> Option<i32> {
    netcatty_mcp::stdio_server::run_if_requested(&netcatty_store::AppPaths::resolve().data_dir)
}
