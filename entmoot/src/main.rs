use color_eyre::Result;
use fangorn::crypto::{
    cipher::{handle_decrypt, handle_encrypt},
    keystore::{Keystore, Sr25519Keystore},
    FANGORN,
};
use ratatui::crossterm::event::{self, poll, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    prelude::*,
    style::{Color, Style, Stylize},
    text::Text,
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph},
    DefaultTerminal, Frame,
};
use ratatui_explorer::{FileExplorer, Theme};
use std::{path::Path, thread::sleep, time::Duration};
use tui_textarea::TextArea;

// 1. Enum to manage the active screen/view
#[derive(Debug)]
pub enum CurrentScreen {
    Main,
    KeyResults,
    EncryptScreen,
    PasswordSelection,
    DecryptScreen,
    DecryptInfoScreen,
}

#[derive(Debug)]
pub struct App {
    menu_state: ListState,
    menu_items: Vec<&'static str>,
    current_screen: CurrentScreen,
    generated_pubkey: Option<String>,
    // the file explorer: todo - this could probably be an option, load it when we select the screen
    file_explorer: FileExplorer,
    // the file path of the message to be encrypted (plaintext)
    file_path: Option<String>,
    /// the text area for password input
    /// Used for both encryption and decryption
    password_input: Option<TextArea<'static>>,
    /// the text area for filename input
    /// only used during decryption
    filename_input: Option<TextArea<'static>>,

    input_selection: u8
}

impl Default for App {
    fn default() -> Self {
        let mut state = ListState::default();
        state.select(Some(0));

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
            menu_items: vec!["Generate Keys", "Inspect Keys", "Encrypt", "Decrypt"],
            current_screen: CurrentScreen::Main,
            generated_pubkey: None,
            file_explorer,
            file_path: None,
            password_input: None,
            filename_input: None,
            input_selection: 0
        }
    }
}

fn main() -> Result<()> {
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
                        CurrentScreen::KeyResults => match key.code {
                            // Input to handle the 'Close' button
                            KeyCode::Esc | KeyCode::Char('c') => {
                                self.current_screen = CurrentScreen::Main;
                                self.generated_pubkey = None; // Clear the data
                            }
                            _ => {}
                        },
                        CurrentScreen::EncryptScreen => match key.code {
                            KeyCode::Esc | KeyCode::Char('c') => {
                                self.current_screen = CurrentScreen::Main;
                                self.generated_pubkey = None;
                            }
                            KeyCode::Enter => {
                                // copy file into memory
                                let selected = self.file_explorer.current();
                                if selected.is_file() {
                                    // User selected a file - do something with it
                                    self.file_path = Some(selected.path().display().to_string());
                                    // For now, just go back to main menu
                                    // You can store the selected file path and use it later
                                    self.current_screen = CurrentScreen::PasswordSelection;
                                    // initialize the password input
                                    let mut textarea = TextArea::default();
                                    textarea.set_cursor_line_style(Style::default());
                                    textarea.set_mask_char('\u{2022}'); //U+2022 BULLET (•)
                                    textarea.set_placeholder_text("Please enter your password");
                                    let constraints = [Constraint::Length(3), Constraint::Min(1)];
                                    let layout = Layout::default().constraints(constraints);
                                    textarea.set_style(Style::default().fg(Color::LightGreen));
                                    textarea.set_block(Block::default().borders(Borders::ALL).title("Password"));
                                    self.password_input = Some(textarea);
                                }
                            }
                            _ => {
                                self.file_explorer.handle(&event)?;
                            }
                        },
                        CurrentScreen::PasswordSelection => match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => {
                                self.current_screen = CurrentScreen::Main;
                                self.generated_pubkey = None;
                            }
                            KeyCode::Enter => {
                                // Get the input and handle confirmation logic
                                // assuming the input element is already initialized...
                                let password = self.password_input.as_mut().unwrap().lines().join("\n");

                                let file_path = self.file_path.as_mut().unwrap();

                                println!("File path: {}", file_path);

                                let filename_raw = Path::new(file_path)
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or("unknown");
                                let filename = String::from(filename_raw);

                                let config_path = String::from("config.txt");
                                let keystore_path = String::from("tmp/keystore");
                                let intent_str = String::from(format!("Password({})", password));
                                let contract_addr = String::from("5EVh9hx7xKUHjNqgoWa7DFknE13f9LQ2qkFgNFG5romgZ8N7");

                                println!("intent string: {}", intent_str);

                                // sleep(Duration::from_secs(10));

                                handle_encrypt(&filename, &filename, &config_path, &keystore_path, &intent_str, &contract_addr).await;
                                //  use password for encryption
                                // Clear state and move on
                                self.password_input = None;
                                self.file_path = None;
                                self.current_screen = CurrentScreen::Main;
                            }
                            _ => {
                                if let Some(input) = self.password_input.as_mut() {
                                    input.input(key);
                                }
                            }
                        },
                        CurrentScreen::DecryptScreen => match key.code {
                            KeyCode::Esc | KeyCode::Char('c') => {
                                self.current_screen = CurrentScreen::Main;
                                self.generated_pubkey = None;
                            }
                            KeyCode::Enter => {
                                // copy file into memory
                                let selected = self.file_explorer.current();
                                if selected.is_file() {
                                    // User selected a file - do something with it
                                    self.file_path = Some(selected.path().display().to_string());
                                    // For now, just go back to main menu
                                    // You can store the selected file path and use it later
                                    self.current_screen = CurrentScreen::DecryptInfoScreen;
                                    // initialize the password input
                                    let mut password_text_area = TextArea::default();
                                    password_text_area.set_cursor_line_style(Style::default());
                                    password_text_area.set_mask_char('\u{2022}'); //U+2022 BULLET (•)
                                    password_text_area.set_placeholder_text("Please enter your password");
                                    password_text_area.set_style(Style::default().fg(Color::LightGreen));
                                    password_text_area.set_block(Block::default().borders(Borders::ALL).title("Password"));
                                    self.password_input = Some(password_text_area);

                                    let mut filename_text_area = TextArea::default();
                                    filename_text_area.set_cursor_line_style(Style::default());
                                    // filename_text_area.set_mask_char('\u{2022}'); //U+2022 BULLET (•)
                                    filename_text_area.set_placeholder_text("Please enter the file name");
                                    filename_text_area.set_style(Style::default().fg(Color::LightGreen));
                                    filename_text_area.set_block(Block::default().borders(Borders::ALL).title("File Name"));
                                    self.filename_input = Some(filename_text_area);
                                }
                            }
                            _ => {
                                self.file_explorer.handle(&event)?;
                            }

                        },
                        CurrentScreen::DecryptInfoScreen => match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => {
                                self.current_screen = CurrentScreen::Main;
                                self.generated_pubkey = None;
                            }
                            KeyCode::Enter => {
                                // Get the input and handle confirmation logic
                                // assuming the input element is already initialized...

                                if self.input_selection == 0 {
                                    self.input_selection = 1;
                                } else {

                                    let password = self.password_input.as_mut().unwrap().lines().join("\n");
                                    let filename = self.filename_input.as_mut().unwrap().lines().join("\n");

                                    let file_path = self.file_path.as_mut().unwrap();

                                    println!("File path: {}", file_path);

                                    let config_path = String::from("config.txt");
                                    let witness_string = &password;
                                    let contract_addr = String::from("5EVh9hx7xKUHjNqgoWa7DFknE13f9LQ2qkFgNFG5romgZ8N7");

                                    println!("File name: {}", filename);
                                    println!("password: {}", password);

                                    // sleep(Duration::from_secs(10));

                                    handle_decrypt(&config_path, &filename, witness_string, &filename, &contract_addr).await;
                                    //  use password for encryption
                                    // Clear state and move on
                                    self.password_input = None;
                                    self.filename_input = None;
                                    self.file_path = None;
                                    self.input_selection = 0;
                                    self.current_screen = CurrentScreen::Main;

                                }
                            }
                            _ => {
                                if self.input_selection == 0 {
                                     if let Some(input) = self.filename_input.as_mut() {
                                        input.input(key);
                                     }
                                } else {
                                    if let Some(input) = self.password_input.as_mut() {
                                        input.input(key);
                                    }
                                }

                            }
                        },

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
                    // generate the keys
                    let keystore = Sr25519Keystore::new("tmp/keystore".into(), FANGORN).unwrap();
                    keystore.generate_key().unwrap();
                    let key = keystore.list_keys().unwrap()[0];

                    let pubkey = format!("Public: {:?}", keystore.to_ss58(&key));

                    // Update state and switch screen
                    self.generated_pubkey = Some(pubkey);
                    self.current_screen = CurrentScreen::KeyResults;
                }
                // inspect keys
                1 => {
                    let keystore = Sr25519Keystore::new("tmp/keystore".into(), FANGORN).unwrap();
                    if let Ok(keys) = keystore.list_keys() {
                        if !keys.is_empty() {
                            let pubkey = format!("Public: {:?}", keystore.to_ss58(&keys[0]));
                            self.generated_pubkey = Some(pubkey);
                            self.current_screen = CurrentScreen::KeyResults;
                        } else {
                            self.generated_pubkey = Some("No keys found in keystore".to_string());
                            self.current_screen = CurrentScreen::KeyResults;
                        }
                    }
                }
                // encrypt
                2 => {
                    self.current_screen = CurrentScreen::EncryptScreen;
                }
                // decrypt
                3 => {
                    self.current_screen = CurrentScreen::DecryptScreen;
                }
                _ => {}
            }
        }
    }

    // use current_screen to choose which view to render
    fn render(&mut self, frame: &mut Frame) {
        match self.current_screen {
            CurrentScreen::Main => self.render_main_screen(frame),
            CurrentScreen::KeyResults => self.render_key_results_screen(frame),
            CurrentScreen::EncryptScreen => self.render_file_explorer_screen(frame),
            CurrentScreen::PasswordSelection => self.render_password_selection(frame),
            CurrentScreen::DecryptScreen => self.render_file_explorer_screen(frame),
            CurrentScreen::DecryptInfoScreen => self.render_decrypt_info(frame), 
        }

        // Outer border
        frame.render_widget(
            Block::new()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Color::Cyan)),
            frame.area(),
        );
    }

    fn render_main_screen(&mut self, frame: &mut Frame) {
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

    fn render_key_results_screen(&mut self, frame: &mut Frame) {
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
        let key_content = self
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

    fn render_file_explorer_screen(&mut self, frame: &mut Frame) {
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
        frame.render_widget(&self.file_explorer.widget(), explorer_area);

        // Footer with navigation instructions
        let footer = Paragraph::new("↑↓: Navigate  │  ← →: Dirs  │  Enter: Select  │  Esc: Back")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        frame.render_widget(footer, footer_area);
    }

    pub fn render_password_selection(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let input = self.password_input.as_mut().unwrap();
        frame.render_widget(input.widget(), area);
    }

    pub fn render_decrypt_info(&mut self, frame: &mut Frame) {

        let vertical_layout = Layout::vertical([
            Constraint::Min(10), // Instructions
            Constraint::Min(10),   // File explorer
        ]);

        let [filename_area, password_area] = vertical_layout.areas(frame.area());
        let password_input = self.password_input.as_mut().unwrap();
        let filename_input = self.filename_input.as_mut().unwrap();
        frame.render_widget(password_input.widget(), password_area);
        frame.render_widget(filename_input.widget(), filename_area);

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

fn inactivate_input(textarea: &mut TextArea<'_>) {
        textarea.set_cursor_line_style(Style::default());
        textarea.set_cursor_style(Style::default());
        textarea.set_block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::DarkGray))
                // .title(" Inactive (^X to switch) "),
        );
    }

fn activate_input(textarea: &mut TextArea<'_>) {
    textarea.set_cursor_line_style(Style::default().add_modifier(Modifier::UNDERLINED));
    textarea.set_cursor_style(Style::default().add_modifier(Modifier::REVERSED));
    textarea.set_block(
        Block::default()
            .borders(Borders::ALL)
            .style(Style::default())
            // .title(" Active "),
    );
}
