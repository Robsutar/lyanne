macro_rules! cfg_rt_tokio {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "rt_tokio")]
            $item
        )*
    }
}

macro_rules! cfg_rt_bevy {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "rt_bevy")]
            $item
        )*
    }
}

macro_rules! cfg_rt_smol {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "rt_smol")]
            $item
        )*
    }
}

macro_rules! cfg_rt_async_executor {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "rt_async_executor")]
            $item
        )*
    }
}

macro_rules! cfg_rt_async_std {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "rt_async_std")]
            $item
        )*
    }
}

pub(crate) use cfg_rt_bevy;
pub(crate) use cfg_rt_smol;
pub(crate) use cfg_rt_tokio;

cfg_rt_tokio! {
    pub use tokio::runtime::Handle as Runtime;
    pub use tokio::net::UdpSocket;
    pub use tokio::net::TcpListener;
    pub use tokio::task::JoinHandle as TaskHandle;
    pub use tokio::sync::Mutex;
    pub use tokio::io::{AsyncReadExt, AsyncWriteExt};
    pub use tokio::net::TcpStream;

    pub struct TaskRunner {
        pub runtime: Runtime
    }

    impl TaskRunner {
        pub fn spawn<T>(&self, future: impl std::future::Future<Output = T> + Send + 'static) -> TaskHandle<T>
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
}

cfg_rt_bevy! {
    pub use async_net::UdpSocket;
    pub use async_net::TcpListener;
    pub use bevy_tasks::Task as TaskHandle;
    pub use async_lock::Mutex;
    pub use async_net::TcpStream;
    pub use futures::{AsyncReadExt, AsyncWriteExt};

    pub struct TaskRunner;

    impl TaskRunner {
        pub fn spawn<T>(&self, future: impl std::future::Future<Output = T> + Send + 'static) -> TaskHandle<T>
        where
            T: Send + 'static,
        {
            bevy_tasks::AsyncComputeTaskPool::get().spawn(future)
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
            futures::future::Either::Left((v, _)) => {
                Ok(v)
            }
            futures::future::Either::Right((_, _)) => {
                Err(())
            }
        }
    }

    pub fn try_lock<T>(mutex: & Mutex<T>) -> Option<async_lock::MutexGuard<'_, T>> {
        mutex.try_lock()
    }
}

cfg_rt_smol! {
    pub use async_net::UdpSocket;
    pub use async_net::TcpListener;
    pub use async_executor::Task as TaskHandle;
    pub use async_lock::Mutex;
    pub use async_net::TcpStream;
    pub use futures::{AsyncReadExt, AsyncWriteExt};

    pub struct TaskRunner;

    impl TaskRunner {
        pub fn spawn<T>(&self, future: impl std::future::Future<Output = T> + Send + 'static) -> TaskHandle<T>
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
            futures::future::Either::Left((v, _)) => {
                Ok(v)
            }
            futures::future::Either::Right((_, _)) => {
                Err(())
            }
        }
    }

    pub fn try_lock<T>(mutex: & Mutex<T>) -> Option<async_lock::MutexGuard<'_, T>> {
        mutex.try_lock()
    }
}

cfg_rt_async_executor! {
    pub use async_net::UdpSocket;
    pub use async_net::TcpListener;
    pub use async_executor::Task as TaskHandle;
    pub use async_lock::Mutex;
    pub use async_net::TcpStream;
    pub use futures::{AsyncReadExt, AsyncWriteExt};

    pub type Runtime = std::sync::Arc<async_executor::Executor<'static>>;

    pub struct TaskRunner {
        pub runtime: Runtime
    }

    impl TaskRunner {
        pub fn spawn<T>(&self, future: impl std::future::Future<Output = T> + Send + 'static) -> TaskHandle<T>
        where
            T: Send + 'static,
        {
            self.runtime.spawn(future)
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
            futures::future::Either::Left((v, _)) => {
                Ok(v)
            }
            futures::future::Either::Right((_, _)) => {
                Err(())
            }
        }
    }

    pub fn try_lock<T>(mutex: & Mutex<T>) -> Option<async_lock::MutexGuard<'_, T>> {
        mutex.try_lock()
    }
}

cfg_rt_async_std! {
    pub use async_std::net::TcpListener;
    pub use async_std::net::TcpStream;
    pub use async_std::net::UdpSocket;
    pub use futures::io::{AsyncReadExt, AsyncWriteExt};
    pub use async_std::sync::Mutex;
    pub use async_std::task::JoinHandle as TaskHandle;

    pub struct TaskRunner;

    impl TaskRunner {
        pub fn spawn<T>(&self, future: impl std::future::Future<Output = T> + Send + 'static) -> TaskHandle<T>
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
            futures::future::Either::Left((v, _)) => {
                Ok(v)
            }
            futures::future::Either::Right((_, _)) => {
                Err(())
            }
        }
    }

    pub fn try_lock<T>(mutex: & Mutex<T>) -> Option<async_std::sync::MutexGuard<'_, T>> {
        mutex.try_lock()
    }
}
