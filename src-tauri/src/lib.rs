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
            // Portable mode: `--portable` keeps vault + settings next to the exe
            // (USB-stick scenario) instead of %APPDATA%.
            let portable = std::env::args().any(|a| a.eq_ignore_ascii_case("--portable"));
            let dir = if portable {
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                    .map(|d| d.join("authio-data"))
                    .ok_or("could not resolve the executable directory for portable mode")?
            } else {
                app.path().app_data_dir().map_err(|e| e.to_string())?
            };
            let state = Arc::new(AppState::new(dir));
            app.manage(state.clone());

            // System tray (visible unless disabled in settings).
            {
                use tauri::menu::MenuBuilder;
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

                let tray_enabled = state.settings.lock().map(|s| s.tray).unwrap_or(true);
                let menu = MenuBuilder::new(app)
                    .text("show", "Show Authio")
                    .text("lock", "Lock")
                    .separator()
                    .text("quit", "Quit")
                    .build()?;
                let tray = TrayIconBuilder::with_id("authio-tray")
                    .tooltip("Authio")
                    .icon(app.default_window_icon().expect("window icon missing").clone())
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app, event| match event.id().as_ref() {
                        "show" => show_main_window(app),
                        "lock" => {
                            if let Some(s) = app.try_state::<Arc<AppState>>() {
                                s.do_lock();
                            }
                        }
                        "quit" => app.exit(0),
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            show_main_window(tray.app_handle());
                        }
                    })
                    .build(app)?;
                // TrayIconBuilder has no `visible()` proxy on pinned tray-icon; toggle post-build.
                let _ = tray.set_visible(tray_enabled);
            }

            let win = app.get_webview_window("main").ok_or("main window missing")?;

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
                    WindowEvent::CloseRequested { api, .. } => {
                        save_window_geo(&state_e, &win_e, true);
                        // With the tray enabled, closing hides the window instead of quitting.
                        let tray_on = state_e.settings.lock().map(|s| s.tray).unwrap_or(false);
                        if tray_on {
                            api.prevent_close();
                            let _ = win_e.hide();
                        }
                    }
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
                    // "No security" mode: never auto-lock (the user asked for zero friction).
                    let no_security = state_t
                        .session
                        .lock()
                        .map(|g| g.as_ref().is_some_and(|s| matches!(s.kdf, vault::Kdf::None { .. })))
                        .unwrap_or(false);
                    if no_security {
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
                            .get_webview_window("main")
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
            commands::change_unlock_mode,
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

/// Bring the main window back from minimized / hidden (tray) state.
fn show_main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn save_window_geo(state: &Arc<AppState>, win: &tauri::WebviewWindow, force: bool) {
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
    // Save the INNER size — restore applies it with set_size() (also inner), so
    // using outer_size here would grow the window by the decoration size on
    // every launch.
    let (Ok(pos), Ok(size)) = (win.outer_position(), win.inner_size()) else {
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
