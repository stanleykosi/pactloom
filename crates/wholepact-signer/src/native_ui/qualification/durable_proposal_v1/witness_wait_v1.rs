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

#[cfg(test)]
mod tests {
    use super::run;

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
}
