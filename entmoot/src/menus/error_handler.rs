
use ratatui::{Frame, buffer::Buffer, crossterm::style, layout::{Constraint, Layout, Rect}, style::Style, text::Text, widgets::{Block, Borders, Clear, Paragraph, Widget, Wrap}
};
use ratatui::prelude::Color;

#[derive(Debug, Default)]
pub struct Popup {
    // title: Line<'a>,
    content: Text<'static>,
    border_style: Style,
    title_style: Style,
    style: Style,
}

#[derive(Debug, Clone)]
pub enum ErrorType {
    Default,
    SubstrateBackendErr,
    DecryptErr,
    WitnessErr,
    EncryptErr,
}

impl Popup {
    pub fn initialize() -> Self {
        Popup{content: Text::from("None"), ..Default::default()}
    }
    pub fn set_error_type(&mut self, error_type: ErrorType) {
        match error_type {
            ErrorType::Default => {
                self.content = Text::from("Default error message");
            }
            ErrorType::SubstrateBackendErr => {
                self.content = Text::from("There was an issue connecting via the substrate backend. No backend avaialable to use.");
            }
            ErrorType::EncryptErr => {
                self.content = Text::from("There was an error trying to encrypt the data.");
            }
            ErrorType::WitnessErr => {
                self.content = Text::from("There was an error composign the witness");
            }
            ErrorType::DecryptErr => {
                self.content = Text::from("There was an error when trying to decrypt the data.");
            }
        } 

    }

    pub fn render(self, frame: &mut Frame) {
        // ensure that all cells under the popup are cleared to avoid leaking content
        let horizontal  = Layout::horizontal([Constraint::Percentage(33), Constraint::Percentage(33), Constraint::Percentage(33)]);
        let [_, middle_third, _] = horizontal.areas(frame.area());
        let vertical = Layout::vertical([Constraint::Percentage(33), Constraint::Percentage(33), Constraint::Percentage(33)]);
        let [_, error_area, _] = vertical.areas(middle_third);
        let horizontal_footer = Layout::horizontal([Constraint::Percentage(5), Constraint::Percentage(90), Constraint::Percentage(5)]);
        let [_, footer_horizontal, _] = horizontal_footer.areas(error_area);
        let vertical_footer = Layout::vertical([Constraint::Percentage(80), Constraint::Percentage(10), Constraint::Percentage(10)]);
        let [_, footer_area, _] = vertical_footer.areas(footer_horizontal);
        let buf = frame.buffer_mut();
        Clear.render(error_area, buf);
        let block = Block::new()
            .title("Error")
            .title_style(self.title_style)
            .borders(Borders::ALL)
            .border_style(self.border_style)
            .style(Style::default().fg(Color::Red));
        Paragraph::new(self.content)
        .wrap(Wrap { trim: true })
        .style(self.style)
        .block(block.clone())
        .style(Style::default().fg(Color::Red))
        .render(error_area, buf);

        let footer = Paragraph::new("Esc: Close")
            .alignment(ratatui::layout::Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
            // .render(footer_area, buf);
        frame.render_widget(footer, footer_area);
    }
}