// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

/// Simple abstraction of a state machine.
///
/// `StateMachine<T>` is a wrapper over `T` that also encodes state information for `T`.
///
/// Each state for `T` is represented by a `StateFn<T>` which is a function that acts as
/// the state handler for that particular state of `T`.
///
/// `StateFn<T>` returns exactly one other `StateMachine<T>` thus each state gets clearly
/// defined transitions to other states.
pub struct StateMachine<T> {
    function: Option<StateFn<T>>,
}
impl<T> Debug for StateMachine<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateMachine")
            .field("function", &self.function.map(|f| f as usize))
            .finish()
    }
}

/// Type representing a state handler of a `StateMachine<T>` machine. Each state handler
/// is a function from `T` that handles a specific state of `T`.
type StateFn<T> = fn(&mut T) -> StateMachine<T>;

impl<T: Debug> StateMachine<T> {
    /// Creates a new state wrapper.
    ///
    /// # Arguments
    ///
    /// `function` - the state handler for this state.
    pub fn new(function: Option<StateFn<T>>) -> StateMachine<T> {
        StateMachine { function }
    }

    /// Creates a new state wrapper that has further possible transitions.
    ///
    /// # Arguments
    ///
    /// `function` - the state handler for this state.
    pub fn next(function: StateFn<T>) -> StateMachine<T> {
        StateMachine::new(Some(function))
    }

    /// Creates a new state wrapper that has no further transitions. The state machine
    /// will finish after running this handler.
    ///
    /// # Arguments
    ///
    /// `function` - the state handler for this last state.
    pub fn finish() -> StateMachine<T> {
        StateMachine::new(None)
    }

    /// Runs a state machine for `T` starting from the provided state.
    ///
    /// # Arguments
    ///
    /// `machine` - a mutable reference to the object running through the various states.
    /// `starting_state_fn` - a `fn(&mut T) -> StateMachine<T>` that should be the handler for
    ///                       the initial state.
    pub fn run(machine: &mut T, starting_state_fn: StateFn<T>) {
        // Start off in the `starting_state` state.
        let mut state_machine = StateMachine::new(Some(starting_state_fn));
        // While current state is not a final/end state, keep churning.
        while let Some(state_fn) = state_machine.function {
            // Run the current state handler, and get the next one.
            state_machine = state_fn(machine);
        }
    }
}
