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
            cleanup(app);
        }
        KeyCode::Enter => {
            // Get the input and handle confirmation logic
            // assuming the input element is already initialized...
            if app.input_selection == 0 {
                app.input_selection = 1;
                App::inactivate(&mut app.filename_input);
                App::activate(&mut app.password_input);
            } else {
                let password = app.password_input.lines().join("\n");
                let filename = app.filename_input.lines().join("\n");
                let config_path = String::from("config.txt");
                let witness_string = &password;
                let contract_addr = String::from("5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7");
                handle_decrypt(&config_path, &filename, witness_string, &filename, &contract_addr).await;
                cleanup(app);
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
        Constraint::Max(10),
        Constraint::Max(10), // filename area
        Constraint::Max(10), // password area
        Constraint::Max(10)
    ]);
    let [_, filename_area_vert, password_area_vert, _] = vertical_layout.areas(frame.area());
    let horizontal_layout = Layout::horizontal([
        Constraint::Max(5),
        Constraint::Min(5),
        Constraint::Max(5)
    ]);

    let [_, filename_area, _] = horizontal_layout.areas(filename_area_vert); 
    let [_, password_area, _] = horizontal_layout.areas(password_area_vert); 
    let password_input = &app.password_input;
    let filename_input = &app.filename_input;
    frame.render_widget(password_input, password_area);
    frame.render_widget(filename_input, filename_area);
}

fn cleanup(app: &mut App) {
    app.generated_pubkey = None;
    app.reset_password_input();
    app.reset_filename_input();
    app.file_path = None;
    app.input_selection = 0;
    app.current_screen = CurrentScreen::Main;
}