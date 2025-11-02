pub mod widgets;

use std::time::Duration;

use color_eyre::Result;
use crossterm::{event::{self, Event, KeyCode, poll}};
use ratatui::{DefaultTerminal, Frame, layout::{Constraint, Direction, Layout, Rect}, widgets::{Block, Borders, Paragraph}};

#[derive(Debug, Default)]
pub struct App {}

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

        let (top_area, bottom_area) = calculate_layout(frame.area());

        frame.render_widget(Paragraph::new("Left Box").block(Block::new().borders(Borders::ALL)), top_area[0]);
        frame.render_widget(Paragraph::new("Right Box").block(Block::new().borders(Borders::ALL)), top_area[1]);
        frame.render_widget(Paragraph::new("Bottom Box").block(Block::new().borders(Borders::ALL)), bottom_area);

    }
}

fn calculate_layout(main_area: Rect) -> (Vec<Rect>, Rect) {

        // With layouts, when you specify a split with the direction being vertical
        // it means that the split will be horizontal giving you a vertical layout
        // Split the screen into two equal halves one above the other
        let vertical_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_area);

        let top_area = vertical_layout[0];

        // Take the top half and split it into two equal halves side by side
        let top_rect = Layout::default().constraints(vec![Constraint::Percentage(50)])
        .direction(Direction::Horizontal)
        .constraints(vec![
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(top_area);

        let bottom_area = vertical_layout[1];

        (top_rect.to_vec(), bottom_area)

}