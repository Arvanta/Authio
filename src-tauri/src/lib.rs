//! Authio library target — holds the whole application so `cargo test` can run
//! against it. The binary target (`main.rs`) is a thin wrapper around [`run`].

mod commands;
mod crypto;
mod importers;
mod migration;
mod model;
mod otp;
mod otpauth;
mod qr;
mod state;
mod vault;

use state::AppState;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager, PhysicalPosition, PhysicalSize, WindowEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            let state = Arc::new(AppState::new(dir));
            app.manage(state.clone());

            let win = app.get_window("main").ok_or("main window missing")?;

            // Restore persisted window geometry before revealing the window.
            if let Ok(settings) = state.settings.lock() {
                if let Some(g) = settings.window {
                    let _ = win.set_size(PhysicalSize::new(g.w.max(380), g.h.max(560)));
                    let _ = win.set_position(PhysicalPosition::new(g.x, g.y));
                }
            }

            // Prevent screen-capture / screen-share of one-time codes.
            let _ = win.set_content_protected(true);

            // Persist window geometry (throttled) on move/resize, always on close.
            {
                let state_e = state.clone();
                let win_e = win.clone();
                win.on_window_event(move |event| match event {
                    WindowEvent::Resized(_) | WindowEvent::Moved(_) => {
                        save_window_geo(&state_e, &win_e, false)
                    }
                    WindowEvent::CloseRequested { .. } => save_window_geo(&state_e, &win_e, true),
                    WindowEvent::Destroyed => state_e.do_lock(),
                    _ => {}
                });
            }

            // Auto-lock supervisor: idle timeout + lock-on-minimize. Both wipe the
            // decrypted session from memory and notify the UI to show the lock screen.
            {
                let handle = app.handle().clone();
                let state_t = state.clone();
                std::thread::spawn(move || loop {
                    std::thread::sleep(Duration::from_secs(1));
                    if !state_t.is_unlocked() {
                        continue;
                    }
                    let (auto_min, lock_min) = state_t
                        .settings
                        .lock()
                        .map(|s| (s.auto_lock_minutes, s.lock_on_minimize))
                        .unwrap_or((0, false));
                    let idle_secs = state_t
                        .last_activity
                        .lock()
                        .map(|t| t.elapsed().as_secs())
                        .unwrap_or(0);
                    let idle_expired = auto_min > 0 && idle_secs >= auto_min * 60;
                    let minimized = lock_min
                        && handle
                            .get_window("main")
                            .map(|w| w.is_minimized().unwrap_or(false))
                            .unwrap_or(false);
                    if idle_expired || minimized {
                        state_t.do_lock();
                        let _ = handle.emit("authio://locked", ());
                    }
                });
            }

            let _ = win.show();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::setup_vault,
            commands::unlock,
            commands::lock,
            commands::list_accounts,
            commands::get_codes,
            commands::hotp_next,
            commands::add_account,
            commands::add_from_uri,
            commands::update_account,
            commands::delete_account,
            commands::set_pinned,
            commands::reorder,
            commands::reveal_secret,
            commands::export_backup,
            commands::import_text,
            commands::import_file,
            commands::import_qr,
            commands::import_apply,
            commands::get_settings,
            commands::set_settings,
            commands::user_activity,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Authio");
}

fn save_window_geo(state: &Arc<AppState>, win: &tauri::Window, force: bool) {
    {
        let Ok(mut ts) = state.last_geo_save.lock() else {
            return;
        };
        if !force && ts.elapsed() < Duration::from_millis(1500) {
            return;
        }
        *ts = Instant::now();
    }
    if win.is_minimized().unwrap_or(false) {
        return;
    }
    let (Ok(pos), Ok(size)) = (win.outer_position(), win.outer_size()) else {
        return;
    };
    if size.width < 100 || size.height < 100 {
        return;
    }
    if let Ok(mut s) = state.settings.lock() {
        s.window = Some(model::WindowGeo {
            x: pos.x,
            y: pos.y,
            w: size.width,
            h: size.height,
        });
    }
    state.save_settings();
}
