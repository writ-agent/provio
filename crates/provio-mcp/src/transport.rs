//! Transport abstraction for MCP framing (spec §11). Tests use in-memory
//! scriptable transports; production uses stdio pipes to the agent and to
//! downstream server child processes.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};

use provio_core::Result;

use crate::jsonrpc::{read_frame, write_frame, JsonRpcMessage};

/// One direction-agnostic JSON-RPC endpoint.
pub trait Transport {
    fn send(&mut self, msg: &JsonRpcMessage) -> Result<()>;
    /// Ok(None) = clean EOF (peer closed).
    fn recv(&mut self) -> Result<Option<JsonRpcMessage>>;
}

/// Newline-framed transport over any reader/writer pair (stdio, pipes).
pub struct StreamTransport<R: BufRead, W: Write> {
    reader: R,
    writer: W,
}

impl<R: BufRead, W: Write> StreamTransport<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        StreamTransport { reader, writer }
    }
}

impl<R: BufRead, W: Write> Transport for StreamTransport<R, W> {
    fn send(&mut self, msg: &JsonRpcMessage) -> Result<()> {
        write_frame(&mut self.writer, msg)?;
        self.writer.flush()?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<JsonRpcMessage>> {
        read_frame(&mut self.reader)
    }
}

/// Convenience constructor for the process's own stdin/stdout.
pub fn stdio_transport() -> StreamTransport<BufReader<std::io::Stdin>, std::io::Stdout> {
    StreamTransport::new(BufReader::new(std::io::stdin()), std::io::stdout())
}

/// In-memory transport for tests: preloaded inbox, recorded outbox.
#[derive(Default)]
pub struct MemoryTransport {
    pub incoming: VecDeque<JsonRpcMessage>,
    pub sent: Vec<JsonRpcMessage>,
}

impl Transport for MemoryTransport {
    fn send(&mut self, msg: &JsonRpcMessage) -> Result<()> {
        self.sent.push(msg.clone());
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<JsonRpcMessage>> {
        Ok(self.incoming.pop_front())
    }
}
