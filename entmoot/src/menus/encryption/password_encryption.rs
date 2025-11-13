use std::path::Path;

use fangorn::crypto::cipher::handle_encrypt;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::Paragraph;


use crate::{App, CurrentScreen};


pub async fn handle_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            cleanup(app);
        }
        KeyCode::Tab => {}
        KeyCode::Enter => {
            // Get the input and handle confirmation logic
            // assuming the input element is already initialized...
            let password = app.password_input.lines().join("\n");
            if password.len() == 0 {
                App::indicate_error(&mut app.password_input);
            } else {
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
                cleanup(app);
            }
        }
        _ => {
            App::activate(&mut app.password_input);
            app.password_input.input(key);
        }
    }
}

pub fn render_password_selection(app: &mut App, frame: &mut Frame) {
    let vertical_layout = Layout::vertical([
        Constraint::Max(4),
        Constraint::Max(10),
        Constraint::Max(10),  // password area
        Constraint::Length(3)

    ]);
    let [_, password_area_vert, _, footer_area] = vertical_layout.areas(frame.area());
    let horizontal_layout = Layout::horizontal([
        Constraint::Max(5),
        Constraint::Min(5),
        Constraint::Max(5)
    ]);

    let [_, area, _] = horizontal_layout.areas(password_area_vert);
    
    let input = &app.password_input;
    render_footer(footer_area, frame);
    frame.render_widget(input, area);
}

fn render_footer(area: Rect, frame: &mut Frame) {
    let footer = Paragraph::new("Enter: Submit  │  Esc: Back")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(footer, area);
}

fn cleanup(app: &mut App) {
    app.reset_password_input();
    app.generated_pubkey = None;
    app.file_path = None;
    app.current_screen = CurrentScreen::Main;
}