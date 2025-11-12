use std::path::Path;

use fangorn::crypto::cipher::handle_encrypt;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;


use crate::{App, CurrentScreen};


pub async fn handle_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.current_screen = CurrentScreen::Main;
            app.generated_pubkey = None;
        }
        KeyCode::Enter => {
            // Get the input and handle confirmation logic
            // assuming the input element is already initialized...
            let password = app.password_input.as_mut().unwrap().lines().join("\n");
            let file_path = app.file_path.as_mut().unwrap();
            let filename_raw = Path::new(file_path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown");
            let filename = String::from(filename_raw);
            let config_path = String::from("config.txt");
            let keystore_path = String::from("tmp/keystore");
            let intent_str = String::from(format!("Password({})", password));
            let contract_addr = String::from("5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7");
            handle_encrypt(&filename, &filename, &config_path, &keystore_path, &intent_str, &contract_addr).await;
            // use password for encryption
            // Clear state and move on
            app.password_input = None;
            app.file_path = None;
            app.current_screen = CurrentScreen::Main;
        }
        _ => {
            if let Some(input) = app.password_input.as_mut() {
                input.input(key);
            }
        }
    }
}

pub fn render_password_selection(app: &mut App, frame: &mut Frame) {
    let area = frame.area();
    let input = app.password_input.as_mut().unwrap();
    frame.render_widget(input.widget(), area);
}