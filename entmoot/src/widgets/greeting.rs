use ratatui::{buffer::Buffer, layout::{Position, Rect}, style::Style, widgets::{Block, StatefulWidget, Widget}};

pub struct GreetingWidget {
    name: String,
}

impl GreetingWidget {
    pub fn new(name: String) -> Self {
        Self{name}
    }
}

impl Widget for GreetingWidget {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let greeting = format!("Hello, {}!", self.name);

        // want to have the text be centered itself. Therefore we take the length
        // of the text then divide it by two. We use this to offset the text
        // by the correct number of cells in the x direction at the center.
        let offset = ((greeting.len() as u16) - 1)/2;
        let x = area.width/2 - offset;
        let y = area.height/2;
        buf.set_string(x, y, greeting, Style::default());
    }
}

pub struct TerminalWidget;

impl TerminalWidget {
    pub fn new() -> Self {
        Self{}  
    }
}

impl Widget for TerminalWidget {

    fn render(self, area: Rect, buf: &mut Buffer) {

        // let block = Block:

    }

}