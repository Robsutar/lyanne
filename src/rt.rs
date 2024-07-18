macro_rules! cfg_rt_tokio {
    ($($item:item)*) => {
        $(
            #[cfg(all(
                feature = "rt-tokio",
                not(feature = "rt-bevy")
            ))]
            $item
        )*
    }
}

macro_rules! cfg_rt_bevy {
    ($($item:item)*) => {
        $(
            #[cfg(all(
                feature = "rt-bevy",
                not(feature = "rt-tokio")
            ))]
            $item
        )*
    }
}

pub(crate) use cfg_rt_bevy;
pub(crate) use cfg_rt_tokio;

cfg_rt_tokio! {
    pub type Runtime = tokio::runtime::Handle;
    pub type UdpSocket = tokio::net::UdpSocket;
    pub type TaskHandle<T> = tokio::task::JoinHandle<T>;
    pub type Mutex<T> = tokio::sync::Mutex<T>;

    pub fn spawn<T>(runtime: &Runtime, future: impl std::future::Future<Output = T> + Send + 'static) -> TaskHandle<T>
    where
        T: Send + 'static,
    {
        runtime.spawn(future)
    }

    pub async fn cancel<T>(handle: TaskHandle<T>) -> Result<T, tokio::task::JoinError> {
        handle.abort();
        handle.await
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
    pub type UdpSocket = async_net::UdpSocket;
    pub type TaskHandle<T> = bevy_tasks::Task<T>;
    pub type Mutex<T> = async_lock::Mutex<T>;

    pub fn spawn<T>(future: impl std::future::Future<Output = T> + Send + 'static) -> TaskHandle<T>
    where
        T: Send + 'static,
    {
        bevy_tasks::AsyncComputeTaskPool::get().spawn(future)
    }

    pub async fn cancel<T>(handle: TaskHandle<T>) -> () {
        handle.cancel().await;
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

    pub fn try_lock<T>(mutex: &Mutex<T>) -> Option<async_lock::MutexGuard<'_, T>> {
        mutex.try_lock()
    }
}