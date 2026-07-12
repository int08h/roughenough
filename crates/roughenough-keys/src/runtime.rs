//! Drives this crate's futures to completion without imposing an async
//! runtime on builds that don't need one.
//!
//! The cloud backends (`longterm-*` features) are the only code paths that
//! genuinely await; they enable the optional tokio dependency. Every other
//! configuration compiles async fns that never suspend, so a single poll
//! with a no-op waker is sufficient.

use std::future::Future;

#[cfg(feature = "tokio")]
pub fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(future)
}

#[cfg(not(feature = "tokio"))]
pub fn block_on<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};

    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());

    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => unreachable!("futures cannot suspend without a cloud backend enabled"),
    }
}
