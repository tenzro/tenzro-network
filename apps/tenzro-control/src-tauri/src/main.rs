// Prevents an additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // A model file's header is parsed by this executable re-run as a
    // locked-down child, which must lock itself down before any thread.
    tenzro_model::parse_jail::enter_if_requested();
    tenzro_control::run()
}
