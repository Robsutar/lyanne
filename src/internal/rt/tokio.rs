pub use tokio::net::UdpSocket;
pub use tokio::runtime::Handle as Runtime;
pub use tokio::sync::Mutex;
pub use tokio::sync::RwLock as AsyncRwLock;
pub use tokio::task::JoinHandle as TaskHandle;

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
mod tls_based {
    pub use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(feature = "server")]
    pub use tokio::net::TcpListener;
    pub use tokio::net::TcpStream;
}

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
pub use tls_based::*;

pub struct TaskRunner {
    pub runtime: Runtime,
}

impl TaskRunner {
    pub fn spawn<T>(
        &self,
        future: impl std::future::Future<Output = T> + Send + 'static,
    ) -> TaskHandle<T>
    where
        T: Send + 'static,
    {
        self.runtime.spawn(future)
    }

    pub async fn cancel<T>(&self, handle: TaskHandle<T>) -> Result<T, tokio::task::JoinError> {
        handle.abort();
        handle.await
    }
}

pub async fn timeout<F>(
    duration: std::time::Duration,
    future: F,
) -> Result<<F as std::future::Future>::Output, ()>
where
    F: std::future::Future,
{
    match tokio::time::timeout(duration, future).await {
        Ok(v) => Ok(v),
        Err(_) => Err(()),
    }
}

pub async fn select<L, R>(
    future_left: L,
    future_right: R,
) -> super::SelectArm<<L as std::future::Future>::Output, <R as std::future::Future>::Output>
where
    L: std::future::Future,
    R: std::future::Future,
{
    tokio::select! {
        v = future_left => super::SelectArm::Left(v),
        v = future_right => super::SelectArm::Right(v),
    }
}

pub fn try_lock<T>(mutex: &Mutex<T>) -> Option<tokio::sync::MutexGuard<'_, T>> {
    match mutex.try_lock() {
        Ok(v) => Some(v),
        Err(_) => None,
    }
}

pub fn try_read<T>(rw_lock: &AsyncRwLock<T>) -> Option<tokio::sync::RwLockReadGuard<'_, T>> {
    match rw_lock.try_read() {
        Ok(read) => Some(read),
        Err(_) => None,
    }
}
