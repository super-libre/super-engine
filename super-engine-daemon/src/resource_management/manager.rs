// SPDX-License-Identifier: GPL-3.0-only
use super::connection::ConnectionInfo;
use super::{ResourceError, ResourceLimits};
use chrono::Utc;
use log::{debug, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};

/// Resource manager for tracking connections and enforcing limits
#[derive(Debug)]
pub struct ResourceManager {
    /// Resource limits configuration
    limits: ResourceLimits,
    /// One permit per connection that may be open at once. A connection holds
    /// its [`ConnectionSlot`] until it closes.
    slots: Arc<Semaphore>,
    /// Each client's rate-limit window, keyed by client id. An entry outlives
    /// the client's connections and is pruned once it has been idle for
    /// `connection_timeout_seconds`, so it says nothing about how many
    /// connections are open.
    connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,
    /// Background cleanup task handle
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ResourceManager {
    /// Create a new resource manager with default limits
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(ResourceLimits::default())
    }

    /// Create a new resource manager with custom limits
    #[must_use]
    pub fn with_limits(limits: ResourceLimits) -> Self {
        let connections = Arc::new(RwLock::new(HashMap::new()));

        // Start background cleanup task
        let cleanup_connections = Arc::clone(&connections);
        let cleanup_limits = limits.clone();
        let cleanup_handle = tokio::spawn(async move {
            Self::cleanup_task(cleanup_connections, cleanup_limits).await;
        });

        Self {
            slots: Arc::new(Semaphore::new(limits.max_connections)),
            limits,
            connections,
            cleanup_handle: Some(cleanup_handle),
        }
    }

    /// Create a resource manager suitable for development
    #[must_use]
    pub fn development() -> Self {
        Self::with_limits(ResourceLimits::development())
    }

    /// Create a resource manager suitable for production
    #[must_use]
    pub fn production() -> Self {
        Self::with_limits(ResourceLimits::production())
    }

    /// Take one of the `max_connections` slots for a connection that has just
    /// been accepted. The connection holds the slot until it closes, and
    /// dropping the slot frees it.
    ///
    /// This, not [`register_connection`](Self::register_connection), is the
    /// connection cap. The cap counted clients once: a client's entry stays
    /// until it has been idle for `connection_timeout_seconds`, so every
    /// process that had made one request in that window held a place, open
    /// connection or not, and forty one-shot commands locked every new
    /// client out for minutes.
    ///
    /// # Errors
    /// [`ResourceError::ConnectionLimitExceeded`] when `max_connections`
    /// connections are already open.
    pub fn open_connection(&self) -> Result<ConnectionSlot, ResourceError> {
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .map(|permit| ConnectionSlot { _permit: permit })
            .map_err(|_| ResourceError::ConnectionLimitExceeded {
                current: self.open_connections(),
                max: self.limits.max_connections,
            })
    }

    /// How many connections hold a slot right now.
    #[must_use]
    pub fn open_connections(&self) -> usize {
        self.limits
            .max_connections
            .saturating_sub(self.slots.available_permits())
    }

    /// Start tracking `client_id`'s requests, if it is not tracked already.
    ///
    /// **Idempotent per `client_id`.** A client (keyed by `uid:pid`) may
    /// open several connections over its lifetime — a long-lived
    /// `/v1/events` stream alongside short `/v1/ping` calls, or simply a
    /// fresh connection per request. Re-registering an existing client is a
    /// no-op: its [`ConnectionInfo`] — and crucially its rolling
    /// `request_history` — is preserved, so the rate-limit window spans all
    /// of that client's connections rather than being reset by each new one.
    ///
    /// Never refused: how many connections may be open is
    /// [`open_connection`](Self::open_connection)'s to decide.
    pub async fn register_connection(&self, client_id: String, client_addr: Option<SocketAddr>) {
        self.connections
            .write()
            .await
            .entry(client_id.clone())
            .or_insert_with(|| ConnectionInfo::new(client_id, client_addr));
    }

    /// Unregister a connection
    pub async fn unregister_connection(&self, client_id: &str) {
        let mut connections = self.connections.write().await;
        let _ = connections.remove(client_id).is_some();
    }

    /// Record a request and check rate limits
    ///
    /// # Errors
    /// Returns an error if the client is unregistered or any rate limit is exceeded.
    pub async fn record_request(&self, client_id: &str) -> Result<(), ResourceError> {
        let mut connections = self.connections.write().await;

        if let Some(conn_info) = connections.get_mut(client_id) {
            conn_info.add_request_and_check_limits(&self.limits)
        } else {
            warn!("Request from unregistered client: {client_id}");
            Err(ResourceError::ResourceUnavailable)
        }
    }

    /// How many clients have a rate-limit window, idle or not.
    pub async fn client_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Get resource usage statistics
    pub async fn get_stats(&self) -> ResourceStats {
        let connections = self.connections.read().await;
        let now = Utc::now();

        let mut total_requests_last_minute = 0;
        let mut total_requests_last_hour = 0;
        let mut active_clients = 0;

        for conn in connections.values() {
            if !conn.is_timed_out(self.limits.connection_timeout_seconds) {
                active_clients += 1;
                total_requests_last_minute +=
                    conn.request_history.count_requests_in_window(now, 60);
                total_requests_last_hour +=
                    conn.request_history.count_requests_in_window(now, 3600);
            }
        }

        ResourceStats {
            open_connections: self.open_connections(),
            clients: connections.len(),
            active_clients,
            total_requests_last_minute,
            total_requests_last_hour,
            max_connections: self.limits.max_connections,
            max_requests_per_minute: self.limits.max_requests_per_minute,
            max_requests_per_hour: self.limits.max_requests_per_hour,
        }
    }

    /// Background task to clean up timed-out connections
    async fn cleanup_task(
        connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,
        limits: ResourceLimits,
    ) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

        loop {
            interval.tick().await;

            let mut connections_guard = connections.write().await;
            let initial_count = connections_guard.len();

            // Remove timed-out connections
            connections_guard.retain(|client_id, conn_info| {
                if conn_info.is_timed_out(limits.connection_timeout_seconds) {
                    debug!("Cleaned up timed-out connection: {client_id}");
                    false
                } else {
                    true
                }
            });

            let removed_count = initial_count - connections_guard.len();
            if removed_count > 0 {
                debug!("Cleaned up {removed_count} timed-out connections");
            }
        }
    }
}

impl Default for ResourceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ResourceManager {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
    }
}

/// A place among the `max_connections` that may be open at once, from
/// [`ResourceManager::open_connection`]. Held for the connection's life;
/// dropping it frees the place.
#[derive(Debug)]
pub struct ConnectionSlot {
    _permit: OwnedSemaphorePermit,
}

/// Resource usage statistics
#[derive(Debug, Clone)]
pub struct ResourceStats {
    /// Connections open right now.
    pub open_connections: usize,
    /// Clients with a rate-limit window, idle or not.
    pub clients: usize,
    /// Clients that made a request within `connection_timeout_seconds`.
    pub active_clients: usize,
    pub total_requests_last_minute: u32,
    pub total_requests_last_hour: u32,
    pub max_connections: usize,
    pub max_requests_per_minute: u32,
    pub max_requests_per_hour: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration as TokioDuration, sleep};

    /// The cap is on connections open at once: a slot is held while its
    /// connection is open and freed when it closes.
    #[tokio::test]
    async fn the_cap_counts_open_connections() {
        let manager = ResourceManager::with_limits(ResourceLimits {
            max_connections: 2,
            ..Default::default()
        });

        let first = manager.open_connection().expect("first slot");
        let _second = manager.open_connection().expect("second slot");
        assert_eq!(manager.open_connections(), 2);
        assert!(
            matches!(
                manager.open_connection(),
                Err(ResourceError::ConnectionLimitExceeded { current: 2, max: 2 })
            ),
            "a third connection while two are open is refused"
        );

        drop(first);

        assert_eq!(manager.open_connections(), 1);
        assert!(
            manager.open_connection().is_ok(),
            "a closed connection frees its slot"
        );
    }

    /// The bug the slots fix: the cap counted clients, and a client stayed
    /// counted until it had been idle for `connection_timeout_seconds`. So a
    /// burst of one-shot commands, each its own process and each long gone,
    /// filled the table and every new client was refused for minutes.
    #[tokio::test]
    async fn clients_that_have_closed_their_connections_hold_no_slot() {
        let manager = ResourceManager::with_limits(ResourceLimits {
            max_connections: 2,
            ..Default::default()
        });

        for pid in 0..10 {
            let slot = manager.open_connection().expect("a slot for each command");
            manager
                .register_connection(format!("1000:{pid}"), None)
                .await;
            drop(slot);
        }

        assert_eq!(manager.client_count().await, 10);
        assert_eq!(manager.open_connections(), 0);
        assert!(manager.open_connection().is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let limits = ResourceLimits {
            max_requests_per_minute: 3,
            max_requests_per_hour: 10,
            ..Default::default()
        };
        let manager = ResourceManager::with_limits(limits);

        // Register a connection
        manager
            .register_connection("client1".to_string(), None)
            .await;

        // First 3 requests should succeed
        for _ in 0..3 {
            assert!(manager.record_request("client1").await.is_ok());
        }

        // Fourth request should fail (rate limit exceeded)
        assert!(manager.record_request("client1").await.is_err());
    }

    /// Re-registering an existing client (e.g. it opened a second
    /// connection, or reconnected for the next request) must NOT reset its
    /// rolling request window. Regression guard: when `register_connection`
    /// overwrote the entry, a client could defeat the rate limit entirely by
    /// reconnecting between requests, and a sibling connection would wipe the
    /// accumulated history of an open one.
    #[tokio::test]
    async fn reregistering_a_client_preserves_its_rate_window() {
        let limits = ResourceLimits {
            max_requests_per_minute: 3,
            max_requests_per_hour: 10,
            ..Default::default()
        };
        let manager = ResourceManager::with_limits(limits);

        manager
            .register_connection("client1".to_string(), None)
            .await;

        // Consume the whole per-minute budget on the first connection.
        for _ in 0..3 {
            assert!(manager.record_request("client1").await.is_ok());
        }

        // A second connection for the same client_id (re-registration) must
        // be a no-op that keeps the existing window — not a fresh start.
        manager
            .register_connection("client1".to_string(), None)
            .await;

        // So the next request is still over quota. Before the fix this
        // reset the count and erroneously returned Ok.
        assert!(
            manager.record_request("client1").await.is_err(),
            "re-registration must not hand the client a fresh rate-limit budget"
        );
    }

    #[tokio::test]
    async fn test_connection_timeout() {
        let limits = ResourceLimits {
            connection_timeout_seconds: 1, // 1 second timeout for testing
            ..Default::default()
        };
        let manager = ResourceManager::with_limits(limits);

        // Register a connection
        manager
            .register_connection("client1".to_string(), None)
            .await;
        assert_eq!(manager.client_count().await, 1);

        // Wait for timeout + cleanup interval
        sleep(TokioDuration::from_secs(2)).await;

        // Connection should be cleaned up
        // Note: In real usage, the cleanup task runs every 30 seconds
        // For testing, we'll manually check the connection timeout
        let connections = manager.connections.read().await;
        if let Some(conn) = connections.get("client1") {
            assert!(conn.is_timed_out(1));
        }
    }

    #[tokio::test]
    async fn test_resource_stats() {
        let manager = ResourceManager::new();

        // Register some connections and make requests
        manager
            .register_connection("client1".to_string(), None)
            .await;
        manager
            .register_connection("client2".to_string(), None)
            .await;

        manager.record_request("client1").await.unwrap();
        manager.record_request("client2").await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.clients, 2);
        assert_eq!(stats.active_clients, 2);
        assert_eq!(stats.open_connections, 0);
        assert_eq!(stats.total_requests_last_minute, 2);
    }
}
