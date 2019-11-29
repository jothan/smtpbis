use std::sync::{Arc, RwLock};

use futures::stream::futures_unordered::FuturesUnordered;
use futures::Future;
use futures::future::{Either};
use futures_util::stream::StreamExt;

pub async fn join_tasks<Fut, Fut2, FutO, Task>(fut: Fut) -> FutO
where Fut: FnOnce(Arc<RwLock<FuturesUnordered<Task>>>) -> Fut2,
      Fut2: Future<Output=FutO> + Unpin,
      FutO: Sized,
      Task: Future,
{
    let fo = Arc::new(RwLock::new(FuturesUnordered::new()));
    let output;

    let mut task = fut(fo.clone());

    loop {
        match futures::future::select(&mut task, fo.write().unwrap().next()).await {
            Either::Left((spawn_output, _fo_next)) => {
                output = spawn_output;
                eprintln!("spawner ended");
                break;
            },
            Either::Right((_task_output, _task)) => {
                eprintln!("task awaited (spawner alive)");
            }
        }
    }

    let mut fo = fo.write().unwrap();

    eprintln!("waiting for remaining tasks");
    while !fo.is_empty() {
        fo.next().await;
        eprintln!("task awaited (join)");
    }
    eprintln!("done");
    output
}
