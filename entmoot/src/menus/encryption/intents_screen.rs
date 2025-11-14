use std::path::Path;

use fangorn::crypto::cipher::handle_encrypt;
use ratatui::crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::Stylize;
use ratatui::widgets::{BorderType, List, ListItem};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    Frame,
};


use crate::{App, CurrentScreen};

pub async fn handle_input(app: &mut App, key_code: KeyCode) {
    match key_code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.current_screen = CurrentScreen::Main;
            app.generated_pubkey = None;
            app.reset_intent_list();
        }
        KeyCode::Enter => {

            app.display_password_input = app.intent_list_items.get(0).unwrap().1;
            app.display_contract_address_input = app.intent_list_items.get(1).unwrap().1;
            app.sr25519_intent = app.intent_list_items.get(2).unwrap().1;

            if !app.sr25519_intent & !app.display_contract_address_input && !app.display_password_input {

                //TODO: Implement error message to show that says "At least one intent must be selected"

            } else {
                if app.is_encrypt_path {
                    // If only the sr25519 intent is chosen, we can directly encrypt since no more user
                    // input is needed.
                    if app.sr25519_intent && !app.display_contract_address_input && !app.display_password_input {
                        let file_path = app.file_path.as_mut().unwrap();
                        let filename_raw = Path::new(file_path)
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("unknown");
                        let filename = String::from(filename_raw);
                        let config_path = String::from("config.txt");
                        let keystore_path = String::from("tmp/keystore");
                        let intent_str = String::from("Sr25519()");
                        let contract_addr = String::from("5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7");
                        handle_encrypt(&filename, &filename, &config_path, &keystore_path, &intent_str, &contract_addr).await;
                        app.current_screen = CurrentScreen::Main;
                        app.generated_pubkey = None;
                        app.reset_intent_list();
                        app.sr25519_intent = false;
                    } else {
                        if app.display_password_input {
                            App::activate(&mut app.password_input);
                            App::inactivate(&mut app.contract_address_input);
                            App::inactivate(&mut app.token_count_input);
                        } else {
                            App::activate(&mut app.contract_address_input);
                            App::inactivate(&mut app.token_count_input);
                        }
                        app.current_screen = CurrentScreen::EncryptionInputScreen;
                        app.menu_title = String::from("Enter Encryption Info");
                    }
                } else {
                    app.menu_title = String::from(" Decrypt Files ");
                    app.current_screen = CurrentScreen::DecryptScreen;
                    App::activate(&mut app.filename_input);
                    if app.display_password_input {
                        App::inactivate(&mut app.password_input);
                    }
                }

            }
        }
        KeyCode::Char(' ') => {
            select(app);
        }
        KeyCode::Down => {
            next(app);
        }
        KeyCode::Up => {
            previous(app);
        }
        _ => {}
    }
}

pub fn render_intents_screen(app: &mut App, frame: &mut Frame) {

    let vertical_layout = Layout::vertical([
        Constraint::Max(1),
        Constraint::Min(10),    // Menu
        Constraint::Length(3),  // Footer
    ]);

    let [_, menu_area, footer_area] = vertical_layout.areas(frame.area());

        // Center the menu
    let menu_layout = Layout::vertical([
        Constraint::Percentage(30),
        Constraint::Length((app.intent_list_items.len() * 3) as u16),
        Constraint::Percentage(30),
    ]);
    let [_, menu_area, _] = menu_layout.areas(menu_area);

    let horizontal_layout = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ]);
    let [_, centered_menu, _] = horizontal_layout.areas(menu_area);

    let menu_items: Vec<ListItem> = app.intent_list_items
        .iter()
        .enumerate()
        .map(|(i, (item, item_selected))| {
            let icon = match i {
                0 => ">",
                1 => ">",
                2 => ">",
                _ => "•",
            };
            if *item_selected {
                ListItem::new(format!("  {}  {}", icon, item)).style(Style::default().fg(Color::LightGreen))
            } else {
                ListItem::new(format!("  {}  {}", icon, item)).style(Style::default().fg(Color::White))
            }
            
        })
        .collect();

    let list = List::new(menu_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Intents ")
                .title_alignment(Alignment::Center),
        )
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan).bold())
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(list, centered_menu, &mut app.intent_list_state);
    render_footer(footer_area, frame);

}

fn next(app: &mut App) {
    let i = match app.intent_list_state.selected() {
        Some(i) => {
            if i >= app.intent_list_items.len() - 1 {
                0
            } else {
                i + 1
            }
        }
        None => 0,
    };
    app.intent_list_state.select(Some(i));
}

fn previous(app: &mut App) {
    let i = match app.intent_list_state.selected() {
        Some(i) => {
            if i == 0 {
                app.intent_list_items.len() - 1
            } else {
                i - 1
            }
        }
        None => 0,
    };
    app.intent_list_state.select(Some(i));
}

fn select(app: &mut App) {
    if let Some(selected) = app.intent_list_state.selected() {
        let (_, item_selected) = app.intent_list_items.get_mut(selected).unwrap();
        *item_selected = !*item_selected;
    }
}

fn render_footer(area: Rect, frame: &mut Frame) {
    let footer = Paragraph::new("↑↓: Navigate  │  Space: Select/Deselect | Enter: Submit  │  Esc/q: Quit")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(footer, area);
}