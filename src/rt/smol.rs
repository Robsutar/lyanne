pub use async_executor::Task as TaskHandle;
pub use async_lock::Mutex;
pub use async_net::TcpListener;
pub use async_net::TcpStream;
pub use async_net::UdpSocket;
pub use futures::{AsyncReadExt, AsyncWriteExt};

pub struct TaskRunner;

impl TaskRunner {
    pub fn spawn<T>(
        &self,
        future: impl std::future::Future<Output = T> + Send + 'static,
    ) -> TaskHandle<T>
    where
        T: Send + 'static,
    {
        smol::spawn(future)
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

pub fn try_lock<T>(mutex: &Mutex<T>) -> Option<async_lock::MutexGuard<'_, T>> {
    mutex.try_lock()
}
