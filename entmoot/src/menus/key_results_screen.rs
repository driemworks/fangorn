use fangorn::crypto::{
    keystore::{Keystore, Sr25519Keystore},
    FANGORN,
};
use ratatui::crossterm::event::KeyCode;
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Color, Style},
    text::Text,
    widgets::{Block, Borders, Paragraph},
    Frame,
};


use crate::{App, CurrentScreen};

pub fn handle_input(app: &mut App, key_code: KeyCode) {
    match key_code {
        // Input to handle the 'Close' button
        KeyCode::Esc | KeyCode::Char('c') => {
            app.current_screen = CurrentScreen::Main;
            app.generated_pubkey = None; // Clear the data
        }
        _ => {}
    }
}

pub fn render_key_results_screen(app: &mut App, frame: &mut Frame) {
    let areas = Layout::vertical([
        Constraint::Length(3), // Title
        Constraint::Min(5),    // Key Results
        Constraint::Length(3), // Buttons
    ])
    .split(frame.area());
    // --- Title Block ---
    let title_block = Block::new()
        .title(" 🔑 Generated Keys ")
        .title_alignment(Alignment::Center)
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::Cyan));
    frame.render_widget(title_block, areas[0]);
    // --- Key Results Paragraph ---
    let key_content = app
        .generated_pubkey
        .as_deref()
        .unwrap_or("Error: Keys not found.");
    let key_paragraph = Paragraph::new(Text::from(key_content))
        .wrap(ratatui::widgets::Wrap { trim: true })
        .block(Block::default().padding(ratatui::widgets::Padding::uniform(1)));
    frame.render_widget(key_paragraph, areas[1]);
    // --- Buttons ---
    let button_layout = Layout::horizontal([Constraint::Percentage(100)]).split(areas[2]);
    // Close Button
    let close_button = Paragraph::new(" [ C / Esc: Close ] ")
        .style(Style::default().fg(Color::Black).bg(Color::Red))
        .alignment(Alignment::Center)
        .block(Block::default().padding(ratatui::widgets::Padding::horizontal(1)));
    frame.render_widget(close_button, button_layout[0]);
}

pub fn generate_keys(app: &mut App) {
    // generate the keys
    let keystore = Sr25519Keystore::new("tmp/keystore".into(), FANGORN).unwrap();
    keystore.generate_key().unwrap();
    let key = keystore.list_keys().unwrap()[0];
    let pubkey = format!("Public: {:?}", keystore.to_ss58(&key));
    // Update state and switch screen
    app.generated_pubkey = Some(pubkey);
    app.current_screen = CurrentScreen::KeyResults;
}

pub fn inspect_keys(app: &mut App) {
    let keystore = Sr25519Keystore::new("tmp/keystore".into(), FANGORN).unwrap();
    if let Ok(keys) = keystore.list_keys() {
        if !keys.is_empty() {
            let pubkey = format!("Public: {:?}", keystore.to_ss58(&keys[0]));
            app.generated_pubkey = Some(pubkey);
            app.current_screen = CurrentScreen::KeyResults;
        } else {
            app.generated_pubkey = Some("No keys found in keystore".to_string());
            app.current_screen = CurrentScreen::KeyResults;
        }
    }
}