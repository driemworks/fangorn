use color_eyre::Result;
use ratatui::crossterm::event::{Event, KeyCode};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use tui_textarea::TextArea;


use crate::{App, CurrentScreen};



pub fn handle_input(app: &mut App, key_code: KeyCode, event: Event) -> Result<()> {
    match key_code {
        KeyCode::Esc | KeyCode::Char('c') => {
            app.current_screen = CurrentScreen::Main;
            app.generated_pubkey = None;
        }
        KeyCode::Enter => {
            // copy file into memory
            let selected = app.file_explorer.current();
            if selected.is_file() {
                // User selected a file - do something with it
                app.file_path = Some(selected.path().display().to_string());
                // For now, just go back to main menu
                // You can store the selected file path and use it later
                app.current_screen = CurrentScreen::PasswordSelection;
                app.reset_password_input();
            }
        }
        _ => {
            app.file_explorer.handle(&event)?;
        }
    }

    Ok(())

}
pub fn render_file_explorer_screen(app: &mut App, frame: &mut Frame) {
    let vertical_layout = Layout::vertical([
        Constraint::Length(3), // Instructions
        Constraint::Min(10),   // File explorer
        Constraint::Length(3), // Footer
    ]);
    let [instructions_area, explorer_area, footer_area] = vertical_layout.areas(frame.area());
    // Instructions
    let instructions = Paragraph::new("Select a file and press Enter")
        .style(Style::default().fg(Color::Cyan))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(instructions, instructions_area);
    // Render the file explorer widget
    frame.render_widget(&app.file_explorer.widget(), explorer_area);
    // Footer with navigation instructions
    let footer = Paragraph::new("↑↓: Navigate  │  ← →: Dirs  │  Enter: Select  │  Esc: Back")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(footer, footer_area);
}
