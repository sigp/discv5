///! A simple trait to allow generic executors or wrappers for spawning the discv5 tasks.
use std::future::Future;
use std::pin::Pin;

pub trait Executor: ExecutorClone {
    /// Run the given future in the background until it ends.
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>);
}

pub trait ExecutorClone {
    fn clone_box(&self) -> Box<dyn Executor>;
}

impl<T> ExecutorClone for T
where
    T: 'static + Executor + Clone,
{
    fn clone_box(&self) -> Box<dyn Executor> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn Executor> {
    fn clone(&self) -> Box<dyn Executor> {
        self.clone_box()
    }
}

#[derive(Clone)]
pub struct TokioExecutor(tokio::runtime::Handle);

impl Executor for TokioExecutor {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.0.spawn(future);
    }
}

impl TokioExecutor {
    pub fn new() -> (Self, tokio::runtime::Runtime) {
        let runtime = tokio::runtime::Builder::new()
            .threaded_scheduler()
            .enable_all()
            .build()
            .expect("Could not initialize runtime");
        (TokioExecutor(runtime.handle().clone()), runtime)
    }
}
