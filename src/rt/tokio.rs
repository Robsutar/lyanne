pub use tokio::net::UdpSocket;
pub use tokio::runtime::Handle as Runtime;
pub use tokio::sync::Mutex;
pub use tokio::task::JoinHandle as TaskHandle;

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
mod tls_based {
    pub use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

pub fn try_lock<T>(mutex: &Mutex<T>) -> Option<tokio::sync::MutexGuard<'_, T>> {
    match mutex.try_lock() {
        Ok(v) => Some(v),
        Err(_) => None,
    }
}
