use color_eyre::Result;
use crossterm::event::{self, poll, Event, KeyCode, KeyEventKind};
use fangorn::crypto::{
    cipher::{handle_decrypt, handle_encrypt},
    keystore::{Keystore, Sr25519Keystore},
    FANGORN,
};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::Text,
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph},
    DefaultTerminal, Frame,
};
use std::time::Duration;

// 1. New Enum to manage the active screen/view
#[derive(Debug)]
pub enum CurrentScreen {
    Main,
    KeyResults,
}

#[derive(Debug)]
pub struct App {
    menu_state: ListState,
    menu_items: Vec<&'static str>,
    // 2. New State fields
    current_screen: CurrentScreen,
    generated_pubkey: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        let mut state = ListState::default();
        state.select(Some(0));

        Self {
            menu_state: state,
            menu_items: vec!["Generate Keys", "Inspect Keys", "Encrypt", "Decrypt"],
            // Initial screen is Main
            current_screen: CurrentScreen::Main,
            generated_pubkey: None,
        }
    }
}

fn main() -> Result<()> {
    // color_eyre::install()?;
    let mut terminal = ratatui::init();
    let app_result = App::default().run(&mut terminal);
    ratatui::restore();
    app_result
}

impl App {
    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        loop {
            // --- DRAW PHASE ---
            terminal.draw(|frame| {
                self.render(frame);
            })?;

            // --- EVENT HANDLING PHASE ---
            if poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
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
                            KeyCode::Enter => self.select(),
                            _ => {}
                        },
                        CurrentScreen::KeyResults => match key.code {
                            // 5. Input to handle the 'Close' button
                            KeyCode::Esc | KeyCode::Char('c') => {
                                // Close the results screen and return to main
                                self.current_screen = CurrentScreen::Main;
                                self.generated_pubkey = None; // Clear the data
                            }
                            // Add logic for 'Copy' button (e.g., KeyCode::Char('y')) here
                            _ => {}
                        },
                    }
                }
            }
        }
        Ok(())
    }

    // ... (previous() and next() methods are unchanged)

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

    // 4. Implement screen switching logic
    fn select(&mut self) {
        if let Some(selected) = self.menu_state.selected() {
            match selected {
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
                1 => {
                    let keystore = Sr25519Keystore::new("tmp/keystore".into(), FANGORN).unwrap();
                    if let Ok(keys) = keystore.list_keys() {
                        let pubkey = format!("Public: {:?}", keystore.to_ss58(&keys[0]));
                        self.generated_pubkey = Some(pubkey);
                        self.current_screen = CurrentScreen::KeyResults;
                    }
                } // Inspect Keys
                2 => {} // Encrypt
                3 => {} // Decrypt
                _ => {}
            }
        }
    }

    // 6. Use current_screen to choose which view to render
    fn render(&mut self, frame: &mut Frame) {
        match self.current_screen {
            CurrentScreen::Main => self.render_main_screen(frame),
            CurrentScreen::KeyResults => self.render_key_results_screen(frame),
        }

        // Outer border (kept for both screens, but often you'd put this in the main function)
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

    // render the results screen for keys
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
}

// ... (render_title, render_menu, render_footer functions are unchanged)

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
            ListItem::new(format!("  {}  {}", icon, item)).style(Style::default().fg(Color::White))
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
    let footer = Paragraph::new("↑↓/j/k: Navigate  │  Enter: Select  │  Esc/q: Quit")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(footer, area);
}
