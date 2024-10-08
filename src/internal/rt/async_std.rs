pub use async_std::net::UdpSocket;
pub use async_std::sync::Mutex;
pub use async_std::sync::RwLock as AsyncRwLock;
pub use async_std::task::JoinHandle as TaskHandle;

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
mod tls_based {
    #[cfg(feature = "server")]
    pub use async_std::net::TcpListener;
    pub use async_std::net::TcpStream;
    pub use futures::io::{AsyncReadExt, AsyncWriteExt};
}

#[cfg(any(feature = "auth_tcp", feature = "auth_tls"))]
pub use tls_based::*;

pub struct TaskRunner;

impl TaskRunner {
    pub fn spawn<T>(
        &self,
        future: impl std::future::Future<Output = T> + Send + 'static,
    ) -> TaskHandle<T>
    where
        T: Send + 'static,
    {
        async_std::task::spawn(future)
    }

    pub async fn cancel<T>(&self, handle: TaskHandle<T>) -> () {
        handle.cancel().await;
    }
}

pub async fn timeout<F>(
    duration: std::time::Duration,
    future: F,
) -> Result<<F as std::future::Future>::Output, ()>
where
    F: std::future::Future,
{
    let timeout_future = futures_timer::Delay::new(duration);

    futures::pin_mut!(future);

    match futures::future::select(future, timeout_future).await {
        futures::future::Either::Left((v, _)) => Ok(v),
        futures::future::Either::Right((_, _)) => Err(()),
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
    futures::pin_mut!(future_left);
    futures::pin_mut!(future_right);

    match futures::future::select(future_left, future_right).await {
        futures::future::Either::Left((v, _)) => super::SelectArm::Left(v),
        futures::future::Either::Right((v, _)) => super::SelectArm::Right(v),
    }
}

pub fn try_lock<T>(mutex: &Mutex<T>) -> Option<async_std::sync::MutexGuard<'_, T>> {
    mutex.try_lock()
}

pub fn try_read<T>(rw_lock: &AsyncRwLock<T>) -> Option<async_std::sync::RwLockReadGuard<'_, T>> {
    rw_lock.try_read()
}
