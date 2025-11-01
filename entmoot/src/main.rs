pub mod widgets;

use std::{io::{BufRead, BufReader, stdout}, process::{Command, Stdio}, sync::mpsc::{self, Receiver, Sender}, thread, time::Duration};

use color_eyre::Result;
use crossterm::{event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseEvent, MouseEventKind, poll}, execute, terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode}};
use ratatui::{DefaultTerminal, Frame, layout::{Constraint, Direction, Layout, Rect}, widgets::{Block, Borders, Paragraph, Wrap}};

#[derive(Debug, Default)]
pub struct App {
    log_lines: Vec<String>,
    scroll_offset: usize
}

fn main() -> Result<()> {
    color_eyre::install()?;
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = ratatui::init();
    // let result = run(terminal);
    let app_result = App::default().run(&mut terminal);
    execute!(stdout(), DisableMouseCapture, LeaveAlternateScreen)?;
    disable_raw_mode()?;
    // doing manual cleanup so no need to calll this
    // ratatui::restore();
    app_result
}

impl App {

    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {

        let server_handle = start_server();
        let mut auto_scroll = true;
        self.log_lines.push(String::from("Starting Server"));
        loop {
            if let Ok(log_lines) = server_handle.logs.try_recv() {
                self.log_lines.push(log_lines);
                if auto_scroll {
                    self.scroll_offset = self.log_lines.len().saturating_sub(1);
                }
            }
            if self.log_lines.len() > 1000 {
                self.log_lines.remove(0);
            }
            terminal.draw(|frame| {
                self.render(frame);       
            })?;
            if poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(key) => {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                break;
                            }
                            KeyCode::Up => {
                                auto_scroll = false;
                                self.scroll_offset = self.scroll_offset.saturating_sub(1);
                            }
                            KeyCode::Down => {
                                self.scroll_offset = self.scroll_offset.saturating_add(1);
                                if self.scroll_offset >= self.log_lines.len().saturating_sub(1) {
                                    auto_scroll = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    Event::Mouse(mouse) => {
                        self.handle_mouse_event(mouse);
                        // Disable auto-scroll when user scrolls with mouse
                        if matches!(mouse.kind, MouseEventKind::ScrollUp | MouseEventKind::ScrollDown) {
                            auto_scroll = false;
                        }
                    }
                    _ => {}
                }
            }
        }
        server_handle.shutdown();
        Ok(())
    }

    fn render(&mut self, frame: &mut Frame) {

        let (top_area, bottom_area) = calculate_layout(frame.area());

        // Join all log lines with newlines
        let log_text = self.log_lines.join("\n");
        
        let paragraph = Paragraph::new(log_text)
            .block(Block::new().borders(Borders::ALL).title("Fangorn Bootnode Logs"))
            .wrap(Wrap { trim: false })  // Enable word wrapping
            .scroll((self.scroll_offset as u16, 0));  // Scroll vertically

        frame.render_widget(paragraph, top_area[0]);
        frame.render_widget(Paragraph::new("Right Box").block(Block::new().borders(Borders::ALL)), top_area[1]);
        frame.render_widget(Paragraph::new("Bottom Box").block(Block::new().borders(Borders::ALL)), bottom_area);

    }

    fn handle_mouse_event(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                // Check if mouse is over the log box (top-left area)
                // You'll need to track the log box area from your render function
                self.scroll_offset = self.scroll_offset.saturating_sub(3);
            }
            MouseEventKind::ScrollDown => {
                self.scroll_offset = self.scroll_offset.saturating_add(3);
            }
            _ => {}
        }
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

enum ServerCommand {
    Kill,
}

fn start_server() -> ServerHandle {
    let (log_tx, log_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel();
    
    let thread_handle = thread::spawn(move || {
        let mut child = Command::new("../target/debug/fangorn")
            .args(&[
                "run",
                "--bind-port", "9944",
                "--rpc-port", "30333",
                "--is-bootstrap",
                "--index", "0"
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start server");
        
        let stdout = child.stdout.take().expect("Failed to capture stdout");
        let stderr = child.stderr.take().expect("Failed to capture stderr");
        
        // Spawn threads to read output
        let tx_stdout = log_tx.clone();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    let _ = tx_stdout.send(format!("{}", line));
                }
            }
        });
        
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    let _ = log_tx.send(format!("[ERR] {}", line));
                }
            }
        });
        
        // Wait for kill command or child to exit
        loop {
            if let Ok(ServerCommand::Kill) = cmd_rx.try_recv() {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            
            // Check if child has exited
            match child.try_wait() {
                Ok(Some(_status)) => break, // Process exited
                Ok(None) => thread::sleep(std::time::Duration::from_millis(100)),
                Err(_) => break,
            }
        }
    });
    
    ServerHandle {
        logs: log_rx,
        command_tx: cmd_tx,
        thread_handle: Some(thread_handle),
    }
}

struct ServerHandle {
    logs: Receiver<String>,
    command_tx: Sender<ServerCommand>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl ServerHandle {
    fn shutdown(mut self) {
        let _ = self.command_tx.send(ServerCommand::Kill);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.command_tx.send(ServerCommand::Kill);
        // Note: Can't join here because we'd need to move the handle
    }
}

