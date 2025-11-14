use fangorn::crypto::cipher::handle_decrypt;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::Paragraph;
use ratatui::{
    layout::{Constraint, Layout},
    Frame,
};


use crate::{App, CurrentScreen};

pub async fn handle_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            cleanup(app);
        }
        KeyCode::Tab =>  {
            app.decrypt_input_selection = (app.decrypt_input_selection + 1) % 2;
            if app.decrypt_input_selection == 0 {
                App::activate(&mut app.filename_input);
                App::inactivate(&mut app.password_input);
            } else {
                App::inactivate(&mut app.filename_input);
                App::activate(&mut app.password_input);
            }
        }
        KeyCode::Enter => {
            let password = app.password_input.lines().join("\n");
            let filename = app.filename_input.lines().join("\n");
            // Make sure that we don't submit empty fields
            if password.len() == 0 || filename.len() == 0{
                if password.len() == 0 {
                    App::indicate_error(&mut app.password_input);
                }
                if filename.len() == 0 {
                    App::indicate_error(&mut app.filename_input);
                }
            } else {
                let config_path = String::from("config.txt");
                let contract_addr = String::from("5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7");
                handle_decrypt(&config_path, &filename, &password, &filename, &contract_addr).await;
                cleanup(app);
            }
        }
        _ => {
            if app.decrypt_input_selection == 0 {
                 app.filename_input.input(key);
                 App::activate(&mut app.filename_input);
            } else {
                app.password_input.input(key);
                App::activate(&mut app.password_input);
            }
        }
    }
}


pub fn render_decrypt_info(app: &mut App, frame: &mut Frame) {
    let vertical_layout = Layout::vertical([
        Constraint::Max(4),
        Constraint::Max(10),  // filename area
        Constraint::Max(10),  // password area
        Constraint::Length(3) // footer area
    ]);
    let [_, filename_area_vert, password_area_vert, footer_area] = vertical_layout.areas(frame.area());
    let horizontal_layout = Layout::horizontal([
        Constraint::Max(5),
        Constraint::Min(5),
        Constraint::Max(5)
    ]);

    let [_, filename_area, _] = horizontal_layout.areas(filename_area_vert); 
    let [_, password_area, _] = horizontal_layout.areas(password_area_vert); 
    let password_input = &app.password_input;
    let filename_input = &app.filename_input;
    render_footer(footer_area, frame);
    frame.render_widget(password_input, password_area);
    frame.render_widget(filename_input, filename_area);
}

fn render_footer(area: Rect, frame: &mut Frame) {
    let footer = Paragraph::new("Tab: Change Input  │  Enter: Submit  │  Esc: Back")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(footer, area);
}

fn cleanup(app: &mut App) {
    app.generated_pubkey = None;
    app.reset_input_fields();
    app.file_path = None;
    app.decrypt_input_selection = 0;
    app.current_screen = CurrentScreen::Main;
}