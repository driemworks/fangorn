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
        KeyCode::Esc  => {
            cleanup(app);
        }
        KeyCode::Tab => {
            if app.display_contract_address_input && app.display_password_input {
                app.encrypt_input_selection = (app.encrypt_input_selection + 1) % 3;
                if app.encrypt_input_selection == 0 {
                    App::activate(&mut app.password_input);
                    App::inactivate(&mut app.contract_address_input);
                    App::inactivate(&mut app.token_count_input);
                }
                else if app.encrypt_input_selection == 1 {
                    App::inactivate(&mut app.password_input);
                    App::activate(&mut app.contract_address_input);
                    App::inactivate(&mut app.token_count_input);
                }
                else {
                    App::inactivate(&mut app.password_input);
                    App::inactivate(&mut app.contract_address_input);
                    App::activate(&mut app.token_count_input);
                }
            } else if app.display_contract_address_input {
                app.encrypt_input_selection = (app.encrypt_input_selection + 1) % 2;
                if app.encrypt_input_selection == 0 {
                    App::activate(&mut app.contract_address_input);
                    App::inactivate(&mut app.token_count_input);
                } else {
                    App::inactivate(&mut app.contract_address_input);
                    App::activate(&mut app.token_count_input);
                }
            }
        }
        KeyCode::Enter => {
            // Get the input and handle confirmation logic
            // assuming the input element is already initialized...
            
            if app.display_contract_address_input && app.display_password_input {

                let password = app.password_input.lines().join("\n");
                let contract_address = app.contract_address_input.lines().join("\n");
                let token_count = app.token_count_input.lines().join("\n");
                if password.len() == 0 || contract_address.len() == 0 || token_count.len() == 0 {
                    if password.len() == 0 {
                        App::indicate_error(&mut app.password_input);
                    }
                    if contract_address.len() == 0 {
                        App::indicate_error(&mut app.contract_address_input);
                    }
                    if token_count.len() == 0 {
                        App::indicate_error(&mut app.token_count_input);
                    }
                } else {
                    handle_encrypt_all(app, password, contract_address, token_count).await;
                    cleanup(app);
                }         
            } else if app.display_contract_address_input {
                let contract_address = app.contract_address_input.lines().join("\n");
                let token_count = app.token_count_input.lines().join("\n");
                if contract_address.len() == 0 || token_count.len() == 0 {
                    if contract_address.len() == 0 {
                        App::indicate_error(&mut app.contract_address_input);
                    }
                    if token_count.len() == 0 {
                        App::indicate_error(&mut app.token_count_input);
                    }
                } else {
                    handle_encrypt_psp22(app, contract_address, token_count).await;
                    cleanup(app);
                }
            } else {
                let password = app.password_input.lines().join("\n");
                if password.len() == 0 {
                    App::indicate_error(&mut app.password_input);
                } else {
                    handle_encrypt_password(app, password).await;
                    cleanup(app);
                }
            }
        }
        _ => {
            // If both are active, then there will be 3 inputs. Else only the password
            // input is active or only the contract info is active
            if app.display_contract_address_input && app.display_password_input {
                match app.encrypt_input_selection {
                    0 =>  {
                        App::activate(&mut app.password_input);
                        app.password_input.input(key);
                    }
                    1 => {
                        App::activate(&mut app.contract_address_input);
                        app.contract_address_input.input(key);
                    }
                    2 => {
                        match_num_chars(app, key);
                    }
                    _ => {}
                }
            } else if app.display_contract_address_input {
                match app.encrypt_input_selection {
                    0 => {
                        App::activate(&mut app.contract_address_input);
                        app.contract_address_input.input(key);
                    }
                    1 => {
                        match_num_chars(app, key);
                    }
                    _ => {}
                }
            } else {
                App::activate(&mut app.password_input);
                app.password_input.input(key);
            }

        }
    }
}

pub fn render_encryption_inputs(app: &mut App, frame: &mut Frame) {
    
    let vertical_layout = Layout::vertical([
        Constraint::Max(4),
        Constraint::Max(10),  // contract info
        Constraint::Max(10),  // password area
        Constraint::Length(3)

    ]);
    let [_, password_area_vert, contract_area_vert, footer_area] = vertical_layout.areas(frame.area());
    let horizontal_layout = Layout::horizontal([
        Constraint::Max(5),
        Constraint::Min(5),
        Constraint::Max(5)
    ]);

    if app.display_contract_address_input {
        let contract_address_input = &app.contract_address_input;
        let token_count_input = &app.token_count_input;
        let contract_split = Layout::horizontal([
            Constraint::Max(5),
            Constraint::Min(10),
            Constraint::Max(30),
            Constraint::Max(5)
        ]);
        let [_, contract_address_area, token_count_area, _] = contract_split.areas(contract_area_vert);
        frame.render_widget(contract_address_input, contract_address_area);
        frame.render_widget(token_count_input, token_count_area);
    }

    if app.display_password_input {
        let [_, password_area, _] = horizontal_layout.areas(password_area_vert);
        let password_input = &app.password_input;
        frame.render_widget(password_input, password_area);
    }
    render_footer(footer_area, frame);
}

fn render_footer(area: Rect, frame: &mut Frame) {
    let footer = Paragraph::new("Tab: Change input | Enter: Submit  │  Esc: Back")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(footer, area);
}

fn cleanup(app: &mut App) {
    app.reset_input_fields();
    app.generated_pubkey = None;
    app.file_path = None;
    app.current_screen = CurrentScreen::Main;
    app.reset_intent_list();
    app.display_contract_address_input = false;
    app.display_password_input = false;
    app.encrypt_input_selection = 0;
}

fn match_num_chars(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('0') => {
            App::activate(&mut app.token_count_input);
            let token_count = app.token_count_input.lines().join("\n");
            if token_count.len() > 0 {
                app.token_count_input.input(key);
            }
        }
        KeyCode::Char('1') => {
            App::activate(&mut app.token_count_input);
            app.token_count_input.input(key);
        }
        KeyCode::Char('2') => {
            App::activate(&mut app.token_count_input);
            app.token_count_input.input(key);
        }
        KeyCode::Char('3') => {
            App::activate(&mut app.token_count_input);
            app.token_count_input.input(key);
        }
        KeyCode::Char('4') => {
            App::activate(&mut app.token_count_input);
            app.token_count_input.input(key);
        }
        KeyCode::Char('5') => {
            App::activate(&mut app.token_count_input);
            app.token_count_input.input(key);
        }
        KeyCode::Char('6') => {
            App::activate(&mut app.token_count_input);
            app.token_count_input.input(key);
        }
        KeyCode::Char('7') => {
            App::activate(&mut app.token_count_input);
            app.token_count_input.input(key);
        }
        KeyCode::Char('8') => {
            App::activate(&mut app.token_count_input);
            app.token_count_input.input(key);
        }
        KeyCode::Char('9') => {
            App::activate(&mut app.token_count_input);
            app.token_count_input.input(key);
        }
        KeyCode::Backspace => {
            App::activate(&mut app.token_count_input);
            app.token_count_input.input(key);
        }
        _ => {}
    }

}

async fn handle_encrypt_all(app: &mut App, password: String, contract_address: String, token_count: String) {

    let mut intent_str = String::from(format!("Password({}) && Psp22({}, {})", password, contract_address, token_count));
    let file_path = app.file_path.as_mut().unwrap();
    let filename_raw = Path::new(file_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");
    let filename = String::from(filename_raw);
    let config_path = String::from("config.txt");
    let keystore_path = String::from("tmp/keystore");
    let intent_store_address = String::from("5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7");

    if app.sr25519_intent {
        intent_str = String::from(format!("Password({}) && Psp22({}, {}) && Sr25519()", password, contract_address, token_count));
    }

    handle_encrypt(&filename, &filename, &config_path, &keystore_path, &intent_str, &intent_store_address).await;

}

async fn handle_encrypt_psp22(app: &mut App, contract_address: String, token_count: String) {

    let file_path = app.file_path.as_mut().unwrap();
    let filename_raw = Path::new(file_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");
    let filename = String::from(filename_raw);
    let config_path = String::from("config.txt");
    let keystore_path = String::from("tmp/keystore");
    let intent_store_address = String::from("5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7");

    let mut intent_str = String::from(format!("Psp22({}, {})", contract_address, token_count));

    if app.sr25519_intent {
        intent_str = String::from(format!("Psp22({}, {}) && Sr25519()", contract_address, token_count));
    }

    handle_encrypt(&filename, &filename, &config_path, &keystore_path, &intent_str, &intent_store_address).await;

}

async fn handle_encrypt_password(app: &mut App, password: String) {
    let file_path = app.file_path.as_mut().unwrap();
    let filename_raw = Path::new(file_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");
    let filename = String::from(filename_raw);
    let config_path = String::from("config.txt");
    let keystore_path = String::from("tmp/keystore");
    let mut intent_str = String::from(format!("Password({})", password));
    if app.sr25519_intent {
        intent_str = String::from(format!("Password({}) && Sr25519()", password));
    }
    let intent_store_address = String::from("5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7");
    handle_encrypt(&filename, &filename, &config_path, &keystore_path, &intent_str, &intent_store_address).await;

}