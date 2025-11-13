use fangorn::crypto::cipher::handle_decrypt;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout},
    Frame,
};


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
            if app.input_selection == 0 {
                app.input_selection = 1;
            } else {
                let password = app.password_input.lines().join("\n");
                let filename = app.filename_input.lines().join("\n");
                let config_path = String::from("config.txt");
                let witness_string = &password;
                let contract_addr = String::from("5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7");
                handle_decrypt(&config_path, &filename, witness_string, &filename, &contract_addr).await;

                // Clear state and move on
                app.reset_password_input();
                app.reset_filename_input();
                app.file_path = None;
                app.input_selection = 0;
                app.current_screen = CurrentScreen::Main;
            }
        }
        _ => {
            if app.input_selection == 0 {
                 app.filename_input.input(key);
            } else {
                app.password_input.input(key);
            }
        }
    }
}


pub fn render_decrypt_info(app: &mut App, frame: &mut Frame) {
    let vertical_layout = Layout::vertical([
        Constraint::Min(10), // Instructions
        Constraint::Min(10),   // File explorer
    ]);
    let [filename_area, password_area] = vertical_layout.areas(frame.area());
    let password_input = &app.password_input;
    let filename_input = &app.filename_input;
    frame.render_widget(password_input, password_area);
    frame.render_widget(filename_input, filename_area);
}