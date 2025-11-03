pub mod widgets;

use std::time::Duration;

use color_eyre::Result;
use crossterm::{event::{self, Event, KeyCode, poll}};
use ratatui::{DefaultTerminal, Frame, layout::{Alignment, Constraint, Direction, Layout, Rect}, widgets::{Block, BorderType, Borders, Paragraph}};

use crate::widgets::buttons::{BLUE, Button, GREEN, State};

#[derive(Debug, Default)]
pub struct App {
    menu_id: Menu
}

#[derive(Debug, Default)]
pub enum Menu {
    #[default]
    MainMenu
}

fn main() -> Result<()> {
    color_eyre::install()?;
    // enable_raw_mode()?;
    // execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = ratatui::init();
    // let result = run(terminal);
    let app_result = App::default().run(&mut terminal);
    // execute!(stdout(), DisableMouseCapture, LeaveAlternateScreen)?;
    // disable_raw_mode()?;
    // doing manual cleanup so no need to calll this
    ratatui::restore();
    app_result
}

impl App {

    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        loop {
            terminal.draw(|frame| {
                self.render(frame);       
            })?;
            if poll(Duration::from_millis(100))? {
                // Poll every 100 ms for esc key to quit
                // since event::read is a blocking event
                match event::read()? {
                    Event::Key(key) => {
                        match key.code {
                            KeyCode::Esc => {
                                break;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn render(&mut self, frame: &mut Frame) {

        let vertical_layout = Layout::vertical([
            Constraint::Percentage(40),
            Constraint::Percentage(33),
            Constraint::Percentage(27),
            Constraint::Min(0), // ignore remaining space
        ]);

        let [title_vert, buttons_vert, _, _] = vertical_layout.areas(frame.area());

        match self.menu_id {
            Menu::MainMenu => {
                    render_title(title_vert, frame);
                    render_buttons(buttons_vert, frame);
            }
            // _ => {}
        }
        // Always render box with title
        frame.render_widget(Block::new().borders(Borders::ALL).border_type(BorderType::Double), frame.area());

    }
}

    fn render_buttons(buttons_vert: Rect, frame: &mut Frame) {

        let layout = Layout::horizontal([Constraint::Percentage(20), Constraint::Percentage(20), Constraint::Percentage(20), Constraint::Percentage(20), Constraint::Percentage(20)]);

        let encrypt_button = Button::new("Encrypt", BLUE, State::Active);
        let decrypt_btton = Button::new("Decrypt", GREEN, State::Normal);

        let [_, enc, _, dec, _] = layout.areas(buttons_vert);

        frame.render_widget(encrypt_button, enc);
        frame.render_widget(decrypt_btton, dec);

        

}

fn render_title(title_area: Rect, frame: &mut Frame) {

    let logo = Paragraph::new("  
             _                         _   
            | |                       | |  
   ___ _ __ | |_ _ __ ___   ___   ___ | |_ 
  / _ \\ '_ \\| __| '_ ` _ \\ / _ \\ / _ \\| __|
 |  __/ | | | |_| | | | | | (_) | (_) | |_ 
  \\___|_| |_|\\__|_| |_| |_|\\___/ \\___/ \\__|
                               by Ideal Labs
  ").centered();

frame.render_widget(logo, title_area);

}

