use std::{collections::BTreeMap, future::Future};

use crate::{ReconcilableResource, ReconcilableResourceEvent, Status};

// Mods

pub mod db;
pub mod dep;

// Consts

const FINALIZER: &str = "simpaas.gleroy.dev/finalizer";

// Types

pub type Result<EVENT, STATUS, VALUE = ()> =
    std::result::Result<VALUE, Box<dyn Error<EVENT, STATUS>>>;

// Error

pub trait Error<EVENT: ReconcilableResourceEvent, STATUS: Status>:
    std::error::Error + Send + Sync
{
    fn state(self: Box<Self>) -> State<EVENT, STATUS>;
}

#[cfg(test)]
#[derive(Debug, Default, thiserror::Error)]
#[error("mock error")]
pub struct MockError {
    pub state: dep::State,
}

#[cfg(test)]
impl MockError {
    pub fn new_boxed(
        state: dep::State,
    ) -> Box<dyn Error<crate::DeployableEvent, simpaas_core::DeployableStatus>> {
        Box::new(Self { state })
    }
}

#[cfg(test)]
impl Error<crate::DeployableEvent, simpaas_core::DeployableStatus> for MockError {
    fn state(self: Box<Self>) -> dep::State {
        self.state
    }
}

// Data structs

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State<EVENT: ReconcilableResourceEvent, STATUS: Status> {
    pub annotations: Option<BTreeMap<String, String>>,
    pub event: Option<EVENT>,
    pub finalizers: Option<Vec<String>>,
    pub should_requeue: bool,
    pub status: Option<STATUS>,
}

impl<EVENT: ReconcilableResourceEvent, STATUS: Status> Default for State<EVENT, STATUS> {
    fn default() -> Self {
        Self {
            annotations: None,
            event: None,
            finalizers: None,
            should_requeue: false,
            status: None,
        }
    }
}

// Traits

#[cfg_attr(test, mockall::automock)]
pub trait Reconciler<
    EVENT: ReconcilableResourceEvent,
    RESOURCE: ReconcilableResource<STATUS>,
    STATUS: Status,
>: Send + Sync
{
    fn reconcile(
        &self,
        ns: &str,
        name: &str,
        res: &RESOURCE,
    ) -> impl Future<Output = Result<EVENT, STATUS, State<EVENT, STATUS>>> + Send;
}
