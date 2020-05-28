///! A simple trait to allow generic executors or wrappers for spawning the discv5 tasks.

pub trait Executor {
    /// Run the given future in the background until it ends.
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>);
}
