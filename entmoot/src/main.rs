pub mod widgets;

use std::time::Duration;

use color_eyre::Result;
use crossterm::{event::{self, Event, KeyCode, poll}};
use ratatui::{DefaultTerminal, Frame, layout::{Constraint, Direction, Layout, Rect}, widgets::{Block, Borders, Paragraph}};

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

        match self.menu_id {
            Menu::MainMenu => {
                    let main_menu = render_buttons(frame);
                    // frame.render_widget(Paragraph::new("Left Box").block(Block::new().borders(Borders::ALL)), top_area[0]);
                    // frame.render_widget(Paragraph::new("Right Box").block(Block::new().borders(Borders::ALL)), top_area[1]);
                    // frame.render_widget(Paragraph::new("Bottom Box").block(Block::new().borders(Borders::ALL)), bottom_area);
            }
            // _ => {}
        }
        // Always render box with title
        frame.render_widget(Block::new().borders(Borders::ALL).title("Fangorn"), frame.area());

    }
}

    fn render_buttons(frame: &mut Frame) {

        let vertical_layout = Layout::vertical([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Min(0), // ignore remaining space
        ]);

        let [_, buttons_vert, _, _] = vertical_layout.areas(frame.area());

        let layout = Layout::horizontal([Constraint::Percentage(20), Constraint::Percentage(20), Constraint::Percentage(20), Constraint::Percentage(20), Constraint::Percentage(20)]);

        let encrypt_button = Button::new("Encrypt", BLUE, State::Active);
        let decrypt_btton = Button::new("Decrypt", GREEN, State::Normal);

        let [_, enc, _, dec, _] = layout.areas(buttons_vert);

        frame.render_widget(encrypt_button, enc);
        frame.render_widget(decrypt_btton, dec);

        

}

