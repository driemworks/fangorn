use std::str::FromStr;

use fangorn::backend::BlockchainBackend;
use anyhow::Result;
use fangorn::crypto::cipher::handle_decrypt;
use fangorn::crypto::keystore::KeystoreError;
use fangorn::utils::{decode_public_key, load_mnemonic};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::Paragraph;
use ratatui::{
    layout::{Constraint, Layout},
    Frame,
};
use subxt_signer::bip39::Mnemonic;
use subxt_signer::sr25519::Keypair;


use crate::{App, CurrentScreen};

pub async fn handle_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            cleanup(app);
        }
        KeyCode::Tab =>  {
            if app.display_password_input {
                app.decrypt_input_selection = (app.decrypt_input_selection + 1) % 2;
                if app.decrypt_input_selection == 0 {
                    App::activate(&mut app.filename_input);
                    App::inactivate(&mut app.password_input);
                } else {
                    App::inactivate(&mut app.filename_input);
                    App::activate(&mut app.password_input);
                }
            }
        }
        KeyCode::Enter => {
            let filename = app.filename_input.lines().join("\n");
            if app.display_password_input {
                let password = app.password_input.lines().join("\n");

                if filename.len() == 0 {
                    App::indicate_error(&mut app.filename_input);
                }
                // Make sure that we don't submit empty fields
                if password.len() == 0 || filename.len() == 0{
                    if password.len() == 0 {
                        App::indicate_error(&mut app.password_input);
                    }
                } else {
                    let config_path = String::from("config.txt");
                    let witness_string = &prepare_witness_string(app, password).await.expect("Something went wrong when creating witness string");
                    let contract_addr = String::from("5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7");
                    
                    handle_decrypt(&config_path, &filename, witness_string, &filename, &contract_addr).await;
                    cleanup(app);
                }
            } else {
                if filename.len() == 0 {
                    App::indicate_error(&mut app.filename_input);
                } else {
                    let config_path = String::from("config.txt");
                    let witness_string = &prepare_witness_string(app, String::from("")).await.expect("Something went wrong when creating witness string");
                    let contract_addr = String::from("5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7");
                    
                    handle_decrypt(&config_path, &filename, witness_string, &filename, &contract_addr).await;
                    cleanup(app);
                }
            } 
        }
        _ => {
            if app.display_password_input {
                if app.decrypt_input_selection == 0 {
                 app.filename_input.input(key);
                 App::activate(&mut app.filename_input);
                } else {
                    app.password_input.input(key);
                    App::activate(&mut app.password_input);
                }
            } else {
                app.filename_input.input(key);
                App::activate(&mut app.filename_input);
            }

        }
    }
}

async fn prepare_witness_string(app: &mut App, password: String) -> Result<String, KeystoreError> {


    let mut witness_string = String::from("");
    let mnemonic_string = load_mnemonic(&String::from("tmp/keystore"));
    let mnemonic = Mnemonic::from_str(&mnemonic_string).unwrap();
    let signer = Keypair::from_phrase(&mnemonic, None).unwrap();
    // Quick and dirty. Added update_signer to re-use backend.
    app.substrate_backend.as_mut().unwrap().update_signer(signer.clone());   
    
    if app.display_password_input && app.display_contract_address_input && app.sr25519_intent {
        // All chosen
        let pubkey = signer.public_key().to_account_id().to_string();
        let pubkey_bytes = decode_public_key(&pubkey);
        let message_bytes = app.substrate_backend.as_ref().unwrap().nonce(pubkey_bytes).await.unwrap().to_le_bytes();
        let signature = signer.sign(&message_bytes).0;
        let signature_hex = hex::encode(signature);
        
        witness_string = String::from(format!("{},{},{}{}", password, pubkey, pubkey, signature_hex));

    } else if !app.display_password_input && app.display_contract_address_input && app.sr25519_intent {
        // Token and sr25519
        let pubkey = signer.public_key().to_account_id().to_string();
        let pubkey_bytes = decode_public_key(&pubkey);
        let message_bytes = app.substrate_backend.as_ref().unwrap().nonce(pubkey_bytes).await.unwrap().to_le_bytes();
        let signature = signer.sign(&message_bytes).0;
        let signature_hex = hex::encode(signature);
        witness_string = String::from(format!("{},{}{}", pubkey, pubkey, signature_hex));

    } else if app.display_password_input && !app.display_contract_address_input && app.sr25519_intent {
        // password and sr25519
        let pubkey = signer.public_key().to_account_id().to_string();
        let pubkey_bytes = decode_public_key(&pubkey);
        let message_bytes = app.substrate_backend.as_ref().unwrap().nonce(pubkey_bytes).await.unwrap().to_le_bytes();
        let signature = signer.sign(&message_bytes).0;
        let signature_hex = hex::encode(signature);
        witness_string = String::from(format!("{},{}{}", password, pubkey, signature_hex));

    } else if app.display_password_input && app.display_contract_address_input && !app.sr25519_intent {
        // password and token
        let pubkey = signer.public_key().to_account_id().to_string();
        witness_string = String::from(format!("{},{}", password, pubkey));

    } else if !app.display_password_input && app.display_contract_address_input && !app.sr25519_intent {
        // only token
        let pubkey = signer.public_key().to_account_id().to_string();
        witness_string = String::from(pubkey);

    } else if app.display_password_input && !app.display_contract_address_input && !app.sr25519_intent {
        // only password
        witness_string = password;

    } else if !app.display_password_input && !app.display_contract_address_input && app.sr25519_intent {
        // only sr25519
        let pubkey = signer.public_key().to_account_id().to_string();
        let pubkey_bytes = decode_public_key(&pubkey);
        let message_bytes = app.substrate_backend.as_ref().unwrap().nonce(pubkey_bytes).await.unwrap().to_le_bytes();
        let signature = signer.sign(&message_bytes).0;
        let signature_hex = hex::encode(signature);
        witness_string = String::from(format!("{}{}", pubkey, signature_hex));
    }

    Ok(witness_string)
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
    let filename_input = &app.filename_input;
    frame.render_widget(filename_input, filename_area);
    
    if app.display_password_input {
        let [_, password_area, _] = horizontal_layout.areas(password_area_vert); 
        let password_input = &app.password_input;
        frame.render_widget(password_input, password_area);
    }
    
    render_footer(footer_area, frame);
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
    app.reset_intent_list();
}