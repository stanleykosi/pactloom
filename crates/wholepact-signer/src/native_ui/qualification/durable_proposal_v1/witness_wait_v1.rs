//! Private fixture sequencing only. This leaf owns no authority or successful
//! validation token; every supplied operation runs at its actual call site.

pub(super) fn run<S, E>(
    state: &mut S,
    full_entry: impl FnOnce(&mut S) -> std::result::Result<(), E>,
    mut live_pending: impl FnMut(&mut S) -> std::result::Result<(), E>,
    mut poll_done: impl FnMut(&mut S) -> bool,
    full_exit: impl FnOnce(&mut S) -> std::result::Result<(), E>,
    mut sleep: impl FnMut(&mut S),
) -> std::result::Result<(), E> {
    full_entry(state)?;
    loop {
        live_pending(state)?;
        if poll_done(state) {
            break;
        }
        sleep(state);
    }
    full_exit(state)
}

/// Inert sequencing state, not a validated-source token. The private borrowed
/// callers retain exclusive custody of their fixed operation and parameters.
pub(super) struct PollState {
    terminal: bool,
}

pub(super) fn begin<S, T, E>(
    state: &mut S,
    full_entry: impl FnOnce(&mut S) -> std::result::Result<T, E>,
) -> std::result::Result<(PollState, T), E> {
    let original = full_entry(state)?;
    Ok((PollState { terminal: false }, original))
}

impl PollState {
    pub(super) fn poll<S, E>(
        &mut self,
        state: &mut S,
        repeated_error: impl FnOnce() -> E,
        live_pending: impl FnOnce(&mut S) -> std::result::Result<(), E>,
        poll_done: impl FnOnce(&mut S) -> std::result::Result<bool, E>,
        full_exit: impl FnOnce(&mut S) -> std::result::Result<(), E>,
    ) -> std::result::Result<bool, E> {
        if self.terminal {
            return Err(repeated_error());
        }
        let original = (|| {
            live_pending(state)?;
            if !poll_done(state)? {
                return Ok(false);
            }
            full_exit(state)?;
            Ok(true)
        })();
        if !matches!(&original, Ok(false)) {
            self.terminal = true;
        }
        original
    }
}

pub(super) fn before_approval<S, T, E>(
    state: &mut S,
    full_before: impl FnOnce(&mut S) -> std::result::Result<(), E>,
    approve: impl FnOnce(&mut S) -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    full_before(state)?;
    approve(state)
}

#[cfg(test)]
mod tests {
    use super::{before_approval, begin, run};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        FullEntry,
        Live,
        Poll,
        FullExit,
        Sleep,
    }

    // Deliberately not Clone. Refusals must return their actual owned value,
    // not a reconstructed error or a memoized successful validation result.
    #[derive(Debug)]
    struct Refusal(Box<u8>);

    #[derive(Default)]
    struct State {
        events: Vec<Event>,
        polls: usize,
        live_checks: usize,
    }

    #[test]
    fn full_gates_surround_every_live_poll_and_only_pending_polls_sleep() {
        let mut state = State::default();
        let result: Result<(), Refusal> = run(
            &mut state,
            |state| {
                state.events.push(Event::FullEntry);
                Ok(())
            },
            |state| {
                state.events.push(Event::Live);
                state.live_checks += 1;
                Ok(())
            },
            |state| {
                state.events.push(Event::Poll);
                state.polls += 1;
                state.polls == 3
            },
            |state| {
                state.events.push(Event::FullExit);
                Ok(())
            },
            |state| state.events.push(Event::Sleep),
        );
        assert!(result.is_ok());
        assert_eq!(state.live_checks, 3);
        assert_eq!(state.polls, 3);
        assert_eq!(
            state.events,
            [
                Event::FullEntry,
                Event::Live,
                Event::Poll,
                Event::Sleep,
                Event::Live,
                Event::Poll,
                Event::Sleep,
                Event::Live,
                Event::Poll,
                Event::FullExit,
            ]
        );
    }

    #[test]
    fn full_entry_refusal_is_owned_and_prevents_every_later_operation() {
        let mut state = State::default();
        let refusal = Refusal(Box::new(7));
        let original = &*refusal.0 as *const u8;
        let result = run(
            &mut state,
            |state| {
                state.events.push(Event::FullEntry);
                Err(refusal)
            },
            |_| panic!("entry refusal must prevent live check"),
            |_| panic!("entry refusal must prevent polling"),
            |_| panic!("entry refusal must prevent exit check"),
            |_| panic!("entry refusal must prevent sleep"),
        );
        let Err(returned) = result else {
            panic!("entry refusal must be preserved");
        };
        assert!(std::ptr::eq(&*returned.0, original));
        assert_eq!(state.events, [Event::FullEntry]);
    }

    #[test]
    fn a_live_refusal_before_any_poll_returns_the_original_error() {
        for refused_check in 1..=3 {
            let mut state = State::default();
            let refusal = Refusal(Box::new(9));
            let original = &*refusal.0 as *const u8;
            let mut refusal = Some(refusal);
            let result = run(
                &mut state,
                |state| {
                    state.events.push(Event::FullEntry);
                    Ok(())
                },
                |state| {
                    state.events.push(Event::Live);
                    state.live_checks += 1;
                    if state.live_checks == refused_check {
                        Err(refusal.take().expect("only the actual refusal is returned"))
                    } else {
                        Ok(())
                    }
                },
                |state| {
                    state.events.push(Event::Poll);
                    state.polls += 1;
                    false
                },
                |_| panic!("live refusal must prevent exit check"),
                |state| state.events.push(Event::Sleep),
            );
            let Err(returned) = result else {
                panic!("live refusal must be preserved");
            };
            assert!(std::ptr::eq(&*returned.0, original));
            assert_eq!(state.live_checks, refused_check);
            assert_eq!(state.polls, refused_check - 1);
            assert_eq!(state.events.last(), Some(&Event::Live));
            assert_eq!(
                state
                    .events
                    .iter()
                    .filter(|&&event| event == Event::Sleep)
                    .count(),
                refused_check - 1
            );
        }
    }

    #[test]
    fn final_full_refusal_is_not_hidden_by_a_completed_poll() {
        let mut state = State::default();
        let refusal = Refusal(Box::new(11));
        let original = &*refusal.0 as *const u8;
        let result = run(
            &mut state,
            |state| {
                state.events.push(Event::FullEntry);
                Ok(())
            },
            |state| {
                state.events.push(Event::Live);
                Ok(())
            },
            |state| {
                state.events.push(Event::Poll);
                true
            },
            |state| {
                state.events.push(Event::FullExit);
                Err(refusal)
            },
            |_| panic!("a completed poll must not sleep"),
        );
        let Err(returned) = result else {
            panic!("final full refusal must be preserved");
        };
        assert!(std::ptr::eq(&*returned.0, original));
        assert_eq!(
            state.events,
            [Event::FullEntry, Event::Live, Event::Poll, Event::FullExit]
        );
    }

    #[test]
    fn incremental_wait_keeps_entry_and_each_pending_poll_separate_from_final_gate() {
        let mut state = State::default();
        let (mut wait, original) = begin(&mut state, |state| {
            state.events.push(Event::FullEntry);
            Ok::<_, Refusal>(Box::new(41))
        })
        .unwrap();
        assert_eq!(*original, 41);
        for done in [false, false, true] {
            assert_eq!(
                wait.poll(
                    &mut state,
                    || panic!("first terminal result is not a repeated poll"),
                    |state| {
                        state.events.push(Event::Live);
                        Ok::<_, Refusal>(())
                    },
                    |state| {
                        state.events.push(Event::Poll);
                        Ok(done)
                    },
                    |state| {
                        state.events.push(Event::FullExit);
                        Ok(())
                    },
                )
                .unwrap(),
                done
            );
        }
        assert_eq!(
            state.events,
            [
                Event::FullEntry,
                Event::Live,
                Event::Poll,
                Event::Live,
                Event::Poll,
                Event::Live,
                Event::Poll,
                Event::FullExit
            ]
        );
        let repeated = Refusal(Box::new(42));
        let original = &*repeated.0 as *const u8;
        let Err(returned) = wait.poll(
            &mut state,
            || repeated,
            |_| panic!("completed waiter must not revalidate"),
            |_| panic!("completed waiter must not poll or approve"),
            |_| panic!("completed waiter must not return cached success"),
        ) else {
            panic!("repeated polling must be refused");
        };
        assert!(std::ptr::eq(&*returned.0, original));
    }

    #[test]
    fn incremental_refusals_preserve_nonclone_errors_and_poison_the_same_waiter() {
        for refused in 0..3 {
            let mut state = State::default();
            let (mut wait, ()) = begin(&mut state, |_| Ok::<_, Refusal>(())).unwrap();
            let refusal = Refusal(Box::new(43));
            let original = &*refusal.0 as *const u8;
            // A shared slot only models ownership transfer of this one error,
            // never native, peer or source authority.
            let refusal = std::cell::RefCell::new(Some(refusal));
            let result = wait.poll(
                &mut state,
                || panic!("first refusal must not use repeated-error fallback"),
                |state| {
                    state.events.push(Event::Live);
                    if refused == 0 {
                        Err(refusal.borrow_mut().take().unwrap())
                    } else {
                        Ok(())
                    }
                },
                |state| {
                    assert_ne!(refused, 0);
                    state.events.push(Event::Poll);
                    if refused == 1 {
                        Err(refusal.borrow_mut().take().unwrap())
                    } else {
                        Ok(true)
                    }
                },
                |state| {
                    assert_eq!(refused, 2);
                    state.events.push(Event::FullExit);
                    Err(refusal.borrow_mut().take().unwrap())
                },
            );
            let Err(returned) = result else {
                panic!("actual refusal must return");
            };
            assert!(std::ptr::eq(&*returned.0, original));
            assert_eq!(state.events.len(), refused + 1);
            assert!(wait
                .poll(
                    &mut state,
                    || Refusal(Box::new(44)),
                    |_| panic!("refused waiter must not revalidate"),
                    |_| panic!("refused waiter must not retry an operation"),
                    |_| panic!("refused waiter must not claim success"),
                )
                .is_err());
        }
    }

    #[test]
    fn incremental_entry_refusal_prevents_constructing_a_waiter() {
        let mut calls = 0;
        let refusal = Refusal(Box::new(45));
        let original = &*refusal.0 as *const u8;
        let result = begin(&mut calls, |calls| {
            *calls += 1;
            Err::<(), _>(refusal)
        });
        let Err(returned) = result else {
            panic!("entry refusal cannot create waiter");
        };
        assert_eq!(calls, 1);
        assert!(std::ptr::eq(&*returned.0, original));
    }

    #[test]
    fn disclosure_full_preapproval_refusal_prevents_effect_and_terminal_success() {
        let mut state = State::default();
        let (mut wait, ()) = begin(&mut state, |state| {
            state.events.push(Event::FullEntry);
            Ok::<_, Refusal>(())
        })
        .unwrap();
        let refusal = Refusal(Box::new(46));
        let original = &*refusal.0 as *const u8;
        let result = wait.poll(
            &mut state,
            || panic!("not a repeated poll"),
            |state| {
                state.events.push(Event::Live);
                Ok(())
            },
            |state| {
                state.events.push(Event::Poll);
                before_approval(
                    state,
                    |state| {
                        state.events.push(Event::FullEntry);
                        Err(refusal)
                    },
                    |_| panic!("preapproval refusal must prevent comparison and approval"),
                )
            },
            |_| panic!("preapproval refusal must prevent successful final validation"),
        );
        let Err(returned) = result else {
            panic!("preapproval refusal must return");
        };
        assert!(std::ptr::eq(&*returned.0, original));
        assert_eq!(
            state.events,
            [Event::FullEntry, Event::Live, Event::Poll, Event::FullEntry]
        );
    }

    #[test]
    fn cancellation_drop_does_not_validate_or_claim_completion() {
        let mut state = State::default();
        let (mut wait, ()) = begin(&mut state, |state| {
            state.events.push(Event::FullEntry);
            Ok::<_, Refusal>(())
        })
        .unwrap();
        assert!(!wait
            .poll(
                &mut state,
                || panic!("not repeated"),
                |state| {
                    state.events.push(Event::Live);
                    Ok(())
                },
                |state| {
                    state.events.push(Event::Poll);
                    Ok(false)
                },
                |_| panic!("pending poll must not execute terminal gate"),
            )
            .unwrap());
        drop(wait);
        assert_eq!(state.events, [Event::FullEntry, Event::Live, Event::Poll]);
    }
}
