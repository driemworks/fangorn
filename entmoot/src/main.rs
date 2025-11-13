use color_eyre::Result;

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

use crate::menus::{decryption::{decrypt_screen}, encryption::{encrypt_screen, password_encryption}, key_results_screen};

pub mod menus;

// 1. Enum to manage the active screen/view
#[derive(Debug)]
pub enum CurrentScreen {
    Main,
    KeyResults,
    EncryptScreen,
    PasswordSelection,
    DecryptScreen,
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
    password_input: TextArea<'static>,
    /// the text area for filename input
    /// only used during decryption
    filename_input: TextArea<'static>,

    /// used to toggle between password_input and filename_input
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
            password_input: initialize_password_input(),
            filename_input: initialize_filename_input(),
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
                        CurrentScreen::KeyResults => key_results_screen::handle_input(self, key.code),
                        CurrentScreen::EncryptScreen => encrypt_screen::handle_input(self, key.code, event)?,
                        CurrentScreen::PasswordSelection => password_encryption::handle_input(self, key).await,
                        CurrentScreen::DecryptScreen => decrypt_screen::handle_input(self, key).await,
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
                    key_results_screen::generate_keys(self);
                }
                // inspect keys
                1 => {
                    key_results_screen::inspect_keys(self);
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
            CurrentScreen::KeyResults => key_results_screen::render_key_results_screen(self, frame),
            CurrentScreen::EncryptScreen => encrypt_screen::render_file_explorer_screen(self, frame),
            CurrentScreen::PasswordSelection => password_encryption::render_password_selection(self, frame),
            CurrentScreen::DecryptScreen => {
                App::activate(&mut self.filename_input);
                App::inactivate(&mut self.password_input);
                decrypt_screen::render_decrypt_info(self, frame)
            }, 
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


    pub fn reset_password_input(&mut self) {
        self.password_input = initialize_password_input();        
    }

    pub fn reset_filename_input(&mut self) {
        self.filename_input = initialize_filename_input();
    }

    fn inactivate(textarea: &mut TextArea<'_>) {
        textarea.set_cursor_line_style(Style::default());
        textarea.set_cursor_style(Style::default());
        textarea.set_block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::DarkGray))
                .title(" Inactive (^X to switch) "),
        );
    }

    fn activate(textarea: &mut TextArea<'_>) {
        textarea.set_cursor_line_style(Style::default().add_modifier(Modifier::UNDERLINED));
        textarea.set_cursor_style(Style::default().add_modifier(Modifier::REVERSED));
        textarea.set_block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default())
                .title(" Active "),
        );
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

fn initialize_password_input() -> TextArea<'static> {
    // initialize the password input
    let mut textarea = TextArea::default();
    textarea.set_cursor_line_style(Style::default());
    textarea.set_mask_char('\u{2022}'); //U+2022 BULLET (•)
    textarea.set_placeholder_text("Please enter your password");
    textarea.set_style(Style::default().fg(Color::LightGreen));
    textarea.set_block(Block::default().borders(Borders::ALL).title("Password"));
    textarea
}
fn initialize_filename_input() -> TextArea<'static> {
    let mut filename_text_area = TextArea::default();
    filename_text_area.set_cursor_line_style(Style::default());
    filename_text_area.set_placeholder_text("Please enter the file name");
    filename_text_area.set_style(Style::default().fg(Color::LightGreen));
    filename_text_area.set_block(Block::default().borders(Borders::ALL).title("File Name"));
    filename_text_area
}