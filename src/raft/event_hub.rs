//! Event hub: distributes state machine changes to connected clients.
//!
//! The state machine sends an [`AppliedEvent`] to this hub after every applied
//! mutation. Event ids are raft log indexes, which are monotonic per node and
//! stable across leader changes, so `get_events(start_event)` can resume from
//! the last index a client saw.

use std::collections::HashMap;
use std::pin::Pin;

use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tonic::Status;

use super::entry::AppliedChange;
use super::entry::AppliedEvent;
use crate::protocol::Event;
use crate::protocol::EventType;

const EVENT_BUFFER: usize = 1000;

type EventStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<Event, Status>> + Send + Sync>>;

/// Distributes applied events to per-peer listeners and keeps a small history
/// for resume.
pub struct EventHub {
    /// Events indexed by raft log index, ascending. Trimmed to EVENT_BUFFER.
    history: RwLock<Vec<AppliedEvent>>,
    listeners: RwLock<HashMap<i64, mpsc::Sender<Result<Event, Status>>>>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    pub fn new() -> Self {
        Self {
            history: RwLock::new(Vec::new()),
            listeners: RwLock::new(HashMap::new()),
        }
    }

    /// Connect the state machine's applied-event stream to this hub.
    pub fn spawn_pump(self: &std::sync::Arc<Self>) -> mpsc::UnboundedSender<AppliedEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        let hub = self.clone();
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(event) = rx.recv().await {
                hub.record(event).await;
            }
        });
        tx
    }

    async fn record(&self, event: AppliedEvent) {
        // record in history
        {
            let mut history = self.history.write().await;
            let pos = history
                .binary_search_by_key(&event.index, |e| e.index)
                .unwrap_or_else(|p| p);
            history.insert(pos, event.clone());
            let excess = history.len().saturating_sub(EVENT_BUFFER);
            history.drain(0..excess);
        }
        // build proto event
        let event_type = match &event.change {
            AppliedChange::PeerNew(..) => EventType::New,
            AppliedChange::RouteAdded(_) => EventType::New,
            _ => EventType::Changed,
        };
        let proto_event = match &event.change {
            AppliedChange::PeerNew(_, peer) | AppliedChange::PeerChanged(peer) => {
                Event::from_peer(event.index, event_type, peer.clone())
            }
            AppliedChange::PeerDeleted(_, peer) => {
                Event::from_peer(event.index, EventType::Deleted, peer.clone())
            }
            AppliedChange::RouteAdded(route) | AppliedChange::RouteDeleted(route) => {
                let t = match &event.change {
                    AppliedChange::RouteDeleted(_) => EventType::Deleted,
                    _ => event_type,
                };
                Event::from_route(event.index, t, route.clone())
            }
        };
        // fan out
        let listeners = self.listeners.read().await;
        for sender in listeners.values() {
            let _ = sender.send(Ok(proto_event.clone())).await;
        }
    }

    /// Register a listener for a peer. Returns the event stream.
    pub async fn register(
        &self,
        peerid: i64,
        start_event: u64,
        initial_events: Vec<Event>,
    ) -> EventStream {
        let (tx, rx) = mpsc::channel::<Result<Event, Status>>(EVENT_BUFFER);
        self.listeners.write().await.insert(peerid, tx.clone());

        // Fill the stream: history after start_event, else initial events.
        let history = self.history.read().await;
        let resume: Vec<Event> = if history.first().is_some_and(|e| e.index <= start_event) {
            history
                .iter()
                .filter(|e| e.index > start_event)
                .map(|e| match &e.change {
                    AppliedChange::PeerNew(_, peer) => {
                        Event::from_peer(e.index, EventType::New, peer.clone())
                    }
                    AppliedChange::PeerChanged(peer) => {
                        Event::from_peer(e.index, EventType::Changed, peer.clone())
                    }
                    AppliedChange::PeerDeleted(_, peer) => {
                        Event::from_peer(e.index, EventType::Deleted, peer.clone())
                    }
                    AppliedChange::RouteAdded(route) => {
                        Event::from_route(e.index, EventType::New, route.clone())
                    }
                    AppliedChange::RouteDeleted(route) => {
                        Event::from_route(e.index, EventType::Deleted, route.clone())
                    }
                })
                .collect()
        } else {
            initial_events
        };
        drop(history);

        for event in resume {
            let _ = tx.send(Ok(event)).await;
        }
        Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
    }

    /// Remove a listener (peer disconnected or deleted).
    pub async fn remove(&self, peerid: i64) {
        self.listeners.write().await.remove(&peerid);
    }
}
