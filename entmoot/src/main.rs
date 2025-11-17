// use color_eyre::Result;
use anyhow::Result;

use fangorn::backend::SubstrateBackend;
use ratatui::crossterm::event::{self, poll, Event, KeyCode, KeyEventKind};
use ratatui::style::Modifier;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph},
    DefaultTerminal, Frame,
};
use ratatui_explorer::{FileExplorer, Theme};
use std::time::Duration;
use tui_textarea::TextArea;

use crate::menus::encryption::intents_screen;
use crate::menus::{decryption::{decrypt_screen}, encryption::{encrypt_fileselect_screen, encryption_screen}, key_results_screen};
use crate::constants::*;

pub mod menus;
pub mod constants;


// 1. Enum to manage the active screen/view
#[derive(Debug)]
pub enum CurrentScreen {
    Main,
    KeyResults,
    EncryptFileSelectScreen,
    EncryptionInputScreen,
    DecryptScreen,
    IntentSelection,
}

#[derive(Debug)]
pub struct App {

    /// List state used to determine which row is 
    /// indicated as selected on main menu.
    menu_state: ListState,

    /// Corresponding list for what options
    /// are avaialable
    menu_items: Vec<&'static str>,

    /// Controls what the title that is
    /// displayed on the outermost box
    /// that is common to all menus
    menu_title: String,

    /// List state used to determine which row is
    /// indicated as selected on intents menu.
    intent_list_state: ListState,

    /// Corresponding list of intent names
    /// and whether they have been chosen
    /// for encyrption/decryption
    intent_list_items: Vec<(&'static str, bool)>,

    /// determines which menu/screen should be rendered
    current_screen: CurrentScreen,

    generated_pubkey: Option<String>,
    
    // the file explorer: todo - this could probably be an option, load it when we select the screen
    file_explorer: FileExplorer,
    // the file path of the message to be encrypted (plaintext)
    file_path: Option<String>,

    /// various text inputs
    filename_input: TextArea<'static>,
    password_input: TextArea<'static>,
    contract_address_input: TextArea<'static>,
    token_count_input: TextArea<'static>,

    /// used to toggle between password_input and filename_input
    /// on decryption and encryption screens
    decrypt_input_selection: u8,
    encrypt_input_selection: u8,

    /// Mutliple uses:
    /// Encryption - display the relevant fields and
    ///              create relevant intents
    /// Decryption - used to construct witness string
    ///            - and conditionally display password input
    display_password_input: bool,
    display_contract_address_input: bool,
    sr25519_intent: bool,

    /// Used to determine how to handle logic
    /// on intents screen depending on 
    /// if encrypting or decrypting
    is_encrypt_path: bool,

    substrate_backend: Option<SubstrateBackend>
}

impl Default for App {
    fn default() -> Self {
        let mut state = ListState::default();
        state.select(Some(0));

        let mut intent_list = ListState::default();
        intent_list.select(Some(0));

        // Create the file explorer with a theme
        let theme = Theme::default().add_default_title().with_block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)),
        );
        let file_explorer =
            FileExplorer::with_theme(theme).expect("Failed to create file explorer");

        Self {
            menu_state: state,
            intent_list_state: intent_list,
            intent_list_items: vec![("Password", false), ("PSP22", false), ("SR25519", false)],
            display_contract_address_input: false,
            display_password_input: false,
            sr25519_intent: false,
            substrate_backend: None,
            is_encrypt_path: true,
            menu_title: String::from(" Main Menu "),
            menu_items: vec!["Generate Keys", "Inspect Keys", "Encrypt", "Decrypt"],
            current_screen: CurrentScreen::Main,
            generated_pubkey: None,
            file_explorer,
            file_path: None,
            password_input: initialize_input_field(String::from(PWD_INPUT_PLACEHOLDER), String::from(PWD_INPUT_TITLE), true),
            filename_input: initialize_input_field(String::from(FILENAME_INPUT_PLACEHOLDER), String::from(FILENAME_INPUT_TITLE), false),
            contract_address_input: initialize_input_field(String::from(PSP22_INPUT_PLACEHOLDER), String::from(PSP22_INPUT_TITLE), false),
            token_count_input: initialize_input_field(String::from(PSP22_TOKEN_COUNT_PLACEHOLDER), String::from(PSP22_TOKEN_TITLE), false),
            encrypt_input_selection: 0,
            decrypt_input_selection: 0
        }
    }
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let mut terminal = ratatui::init();
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on( async {
            App::default().run(&mut terminal).await.expect("An error occurred running the UI");
        });
    ratatui::restore();
    Ok(())
}

impl App {
    async fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        self.substrate_backend = Some(SubstrateBackend::new(String::from(WS_URL), None).await?);
        loop {
            // --- DRAW PHASE ---
            terminal.draw(|frame| {
                self.render(frame);
            })?;

            // --- EVENT HANDLING PHASE ---
            if poll(Duration::from_millis(100))? {
                let event = event::read()?;
                if let Event::Key(key) = event {
                    // Ignore key release events
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match self.current_screen {
                        CurrentScreen::Main => match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => {
                                // Quit the whole application
                                break;
                            }
                            KeyCode::Up | KeyCode::Char('k') => self.previous(),
                            KeyCode::Down | KeyCode::Char('j') => self.next(),
                            KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Right => self.select(),
                            _ => {}
                        },
                        CurrentScreen::KeyResults => key_results_screen::handle_input(self, key.code),
                        CurrentScreen::EncryptFileSelectScreen => encrypt_fileselect_screen::handle_input(self, key.code, event)?,
                        CurrentScreen::EncryptionInputScreen => encryption_screen::handle_input(self, key).await,
                        CurrentScreen::DecryptScreen => decrypt_screen::handle_input(self, key).await,
                        CurrentScreen::IntentSelection => intents_screen::handle_input(self, key.code).await,
                    }
                }
            }
        }
        Ok(())
    }

    fn next(&mut self) {
        let i = match self.menu_state.selected() {
            Some(i) => {
                if i >= self.menu_items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.menu_state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.menu_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.menu_items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.menu_state.select(Some(i));
    }

    fn select(&mut self) {
        if let Some(selected) = self.menu_state.selected() {
            match selected {
                // gen keys
                0 => {
                    self.menu_title = String::from(" Generate Keys ");
                    key_results_screen::generate_keys(self);
                }
                // inspect keys
                1 => {
                    self.menu_title = String::from(" Inspect Keys ");
                    key_results_screen::inspect_keys(self);
                }
                // encrypt
                2 => {
                    self.menu_title = String::from(" Select File ");
                    self.is_encrypt_path = true;
                    self.current_screen = CurrentScreen::EncryptFileSelectScreen;
                }
                // decrypt
                3 => {
                    self.menu_title = String::from(" Select Intents ");
                    self.is_encrypt_path = false;
                    self.current_screen = CurrentScreen::IntentSelection;
                }
                _ => {}
            }
        }
    }

    // use current_screen to choose which view to render
    fn render(&mut self, frame: &mut Frame) {
        match self.current_screen {
            CurrentScreen::Main => self.render_main_screen(frame),
            CurrentScreen::KeyResults => key_results_screen::render_key_results_screen(self, frame),
            CurrentScreen::EncryptFileSelectScreen => encrypt_fileselect_screen::render_file_explorer_screen(self, frame),
            CurrentScreen::EncryptionInputScreen => encryption_screen::render_encryption_inputs(self, frame),
            CurrentScreen::DecryptScreen => decrypt_screen::render_decrypt_info(self, frame),
            CurrentScreen::IntentSelection => intents_screen::render_intents_screen(self, frame),
        }
        // Outer border
        frame.render_widget(
            Block::new()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Color::Cyan))
                .title(self.menu_title.clone()),
            frame.area(),
        );
    }

    fn render_main_screen(&mut self, frame: &mut Frame) {
        self.menu_title = String::from(" Main Menu ");
        let vertical_layout = Layout::vertical([
            Constraint::Length(10), // Title
            Constraint::Min(10),    // Menu
            Constraint::Length(3),  // Footer
        ]);

        let [title_area, menu_area, footer_area] = vertical_layout.areas(frame.area());

        render_title(title_area, frame);
        render_menu(menu_area, frame, &self.menu_items, &mut self.menu_state);
        render_footer(footer_area, frame);
    }

    pub fn reset_input_fields(&mut self) {
        self.password_input = initialize_input_field(String::from(PWD_INPUT_PLACEHOLDER), String::from(PWD_INPUT_TITLE), true);
        self.filename_input = initialize_input_field(String::from(FILENAME_INPUT_PLACEHOLDER), String::from(FILENAME_INPUT_TITLE), false);
        self.contract_address_input = initialize_input_field(String::from(PSP22_INPUT_PLACEHOLDER), String::from(PSP22_INPUT_TITLE), false);
        self.token_count_input = initialize_input_field(String::from(PSP22_TOKEN_COUNT_PLACEHOLDER), String::from(PSP22_TOKEN_TITLE), false);
    }

    pub fn reset_intent_list(&mut self) {
        self.intent_list_state.select(None);
        self.intent_list_state.select(Some(0));
        for (_, item_selected) in self.intent_list_items.iter_mut() {
            *item_selected = false;
        }
    }

    pub fn inactivate(textarea: &mut TextArea<'_>) {
        textarea.set_cursor_line_style(Style::default().add_modifier(Modifier::HIDDEN));
        textarea.set_cursor_style(Style::default().add_modifier(Modifier::HIDDEN));
        textarea.set_style(Style::default().fg(Color::DarkGray));
        let inactivate_block = textarea.block().unwrap().clone().border_style(Style::default().fg(Color::DarkGray));
        textarea.set_block(inactivate_block);
    }

    pub fn activate(textarea: &mut TextArea<'_>) {
        textarea.set_cursor_line_style(Style::default().add_modifier(Modifier::UNDERLINED));
        textarea.set_cursor_style(Style::default().add_modifier(Modifier::REVERSED));
        textarea.set_style(Style::default().fg(Color::LightGreen));
        let activate_block = textarea.block().unwrap().clone().border_style(Color::LightGreen);
        textarea.set_block(activate_block);
    }

    pub fn indicate_error(textarea: &mut TextArea<'_>) {
        textarea.set_style(Style::default().fg(Color::Red));
        let error_block = textarea.block().unwrap().clone().border_style(Style::default().fg(Color::Red));
        textarea.set_placeholder_text("Input cannot be empty");
        textarea.set_block(error_block);
    }

}

fn render_title(title_area: Rect, frame: &mut Frame) {
    let logo = Paragraph::new(
        "  
             _                         _   
            | |                       | |  
   ___ _ __ | |_ _ __ ___   ___   ___ | |_ 
  / _ \\ '_ \\| __| '_ ` _ \\ / _ \\ / _ \\| __|
 |  __/ | | | |_| | | | | | (_) | (_) | |_ 
  \\___|_| |_|\\__|_| |_| |_|\\___/ \\___/ \\__|
                               by Ideal Labs
  ",
    )
    .centered()
    .style(Style::default().fg(Color::Cyan));
    frame.render_widget(logo, title_area);
}

fn render_menu(area: Rect, frame: &mut Frame, items: &[&str], state: &mut ListState) {
    // Center the menu
    let menu_layout = Layout::vertical([
        Constraint::Percentage(30),
        Constraint::Length((items.len() * 3) as u16),
        Constraint::Percentage(30),
    ]);
    let [_, menu_area, _] = menu_layout.areas(area);

    let horizontal_layout = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ]);
    let [_, centered_menu, _] = horizontal_layout.areas(menu_area);

    let menu_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let icon = match i {
                0 => ">",
                1 => ">",
                2 => ">",
                3 => ">",
                _ => "•",
            };
            ListItem::new(format!("  {}  {}", icon, item)).style(Style::default().fg(Color::White))
        })
        .collect();

    let list = List::new(menu_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Main Menu ")
                .title_alignment(Alignment::Center),
        )
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan).bold())
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(list, centered_menu, state);
}

fn render_footer(area: Rect, frame: &mut Frame) {
    let footer = Paragraph::new("↑↓/j/k: Navigate  │  Enter: Select  │  Esc/q: Quit")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(footer, area);
}

fn initialize_input_field(placeholder: String, title: String, masked: bool) -> TextArea<'static> {
    let mut textarea = TextArea::default();
    textarea.set_cursor_line_style(Style::default());
    if masked {
        textarea.set_mask_char('\u{2022}'); //U+2022 BULLET (•)
    }
    textarea.set_placeholder_text(placeholder);
    textarea.set_style(Style::default().fg(Color::LightGreen));
    textarea.set_block(Block::default().borders(Borders::ALL).border_style(Color::LightGreen).title(title));
    textarea
}