#![cfg_attr(not(test), no_std)]

use core::ptr;

mod capability;
mod hosting;

// ABI v4 adds bounded hosting management and narrow RPC operation rights.
pub const Z_ABI_VERSION: u32 = 4;
pub const Z_OPERATION_MAX: u32 = 22;
pub const Z_RIGHT_OPERATIONS: u32 = 4194303;
pub const Z_FILE_LIST: u32 = 21;
pub const Z_FILE_TRUNCATE: u32 = 22;

#[repr(C)]
pub struct FileEntryReply {
    pub request: u64,
    pub index: u32,
    pub metadata: i32,
    pub name: [u8; 16],
}
pub const Z_SLEEP: u64 = 11;
pub const Z_RECV_WAIT: u64 = 12;
pub const Z_TIMEOUT: i64 = -8;
pub const Z_WAIT_MAX_TICKS: u64 = 1000;

const CELLS: u32 = 8;
const RESTART_LIMIT: u32 = 3;
const GENERATION_MAX: u64 = (i64::MAX as u64) >> 8;
const BACKOFF_BASE: u64 = 4;
const BACKOFF_MAX: u64 = 64;

const DORMANT: u32 = 0;
const READY: u32 = 1;
const BACKOFF: u32 = 2;
const QUARANTINED: u32 = 3;
const STOPPED: u32 = 4;

const INVALID: i32 = -1;
const STALE: i32 = -2;
const UNAVAILABLE: i32 = -3;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub generation: u64,
    pub deadline: u64,
    pub faults: u32,
    pub restarts: u32,
    pub phase: u32,
    pub reserved: u32,
}

impl State {
    const fn initial() -> Self {
        Self {
            generation: 1,
            deadline: 0,
            faults: 0,
            restarts: 0,
            phase: READY,
            reserved: 0,
        }
    }

    fn valid(&self) -> bool {
        if self.reserved != 0 || self.restarts > RESTART_LIMIT {
            return false;
        }
        if self.phase == DORMANT {
            return self.generation <= GENERATION_MAX
                && self.deadline == 0
                && self.faults == 0
                && self.restarts == 0;
        }
        if self.generation == 0 || self.generation > GENERATION_MAX {
            return false;
        }
        if self.faults < self.restarts {
            return false;
        }
        match self.phase {
            READY => self.deadline == 0,
            BACKOFF => {
                self.restarts < RESTART_LIMIT
                    && self.faults > self.restarts
                    && self.generation < GENERATION_MAX
                    && self.deadline != 0
            }
            QUARANTINED => self.deadline == 0 && self.faults != 0,
            STOPPED => self.deadline == 0,
            _ => false,
        }
    }

    fn quarantine(&mut self) {
        self.phase = QUARANTINED;
        self.deadline = 0;
    }

    fn fault(&mut self, now: u64) {
        if !self.valid() || self.phase == DORMANT || self.phase == STOPPED {
            return;
        }
        self.faults = self.faults.saturating_add(1);
        if self.phase != READY {
            return;
        }
        if self.restarts == RESTART_LIMIT || self.generation == GENERATION_MAX {
            self.quarantine();
            return;
        }
        let delay = (BACKOFF_BASE << self.restarts).min(BACKOFF_MAX);
        match now.checked_add(delay) {
            Some(deadline) => {
                self.deadline = deadline;
                self.phase = BACKOFF;
            }
            None => self.quarantine(),
        }
    }

    fn poll(&mut self, now: u64) -> bool {
        if !self.valid() || self.phase != BACKOFF || now < self.deadline {
            return false;
        }
        self.generation += 1;
        self.restarts += 1;
        self.deadline = 0;
        self.phase = READY;
        true
    }

    fn stop(&mut self) {
        if self.valid() && self.phase != DORMANT {
            self.phase = STOPPED;
            self.deadline = 0;
        }
    }

    fn handle(&self, slot: u32) -> u64 {
        if !self.valid() || self.phase != READY || slot >= CELLS {
            return 0;
        }
        (self.generation << 8) | u64::from(slot + 1)
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_policy_init(state: *mut State, _now: u64) {
    if !state.is_null() {
        ptr::write(state, State::initial());
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_policy_fault(state: *mut State, now: u64) {
    if let Some(state) = state.as_mut() {
        state.fault(now);
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_policy_stop(state: *mut State) {
    if let Some(state) = state.as_mut() {
        state.stop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_policy_poll(state: *mut State, now: u64) -> i32 {
    match state.as_mut() {
        Some(state) => i32::from(state.poll(now)),
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_policy_handle(state: *const State, slot: u32) -> u64 {
    match state.as_ref() {
        Some(state) => state.handle(slot),
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_policy_resolve(
    states: *const State,
    length: u32,
    handle: u64,
) -> i32 {
    let encoded_slot = (handle & 0xff) as u32;
    let generation = handle >> 8;
    if states.is_null()
        || length > CELLS
        || encoded_slot == 0
        || encoded_slot > length
        || generation == 0
        || generation > GENERATION_MAX
    {
        return INVALID;
    }
    let slot = encoded_slot - 1;
    let state = &*states.add(slot as usize);
    if !state.valid() || state.phase == DORMANT {
        return INVALID;
    }
    if state.generation != generation {
        return STALE;
    }
    if state.phase != READY {
        return UNAVAILABLE;
    }
    slot as i32
}

#[no_mangle]
pub unsafe extern "C" fn z_policy_check(state: *const State) -> i32 {
    match state.as_ref() {
        Some(state) => i32::from(state.valid()),
        None => 0,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn, nomem, nostack)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    fn dormant() -> State {
        State {
            generation: 0,
            deadline: 0,
            faults: 0,
            restarts: 0,
            phase: DORMANT,
            reserved: 0,
        }
    }

    fn resolve(states: &[State], handle: u64) -> i32 {
        unsafe { z_policy_resolve(states.as_ptr(), states.len() as u32, handle) }
    }

    fn initialized(now: u64) -> State {
        let mut state = dormant();
        unsafe { z_policy_init(&mut state, now) };
        state
    }

    #[test]
    fn c_abi_layout_is_fixed() {
        assert_eq!((Z_ABI_VERSION, Z_SLEEP, Z_RECV_WAIT, Z_TIMEOUT, Z_WAIT_MAX_TICKS),
                   (4, 11, 12, -8, 1000));
        assert_eq!(Z_RIGHT_OPERATIONS, (1 << Z_OPERATION_MAX) - 1);
        assert_eq!((Z_FILE_LIST, Z_FILE_TRUNCATE), (21, 22));
        assert_eq!(size_of::<FileEntryReply>(), 32);
        assert_eq!(align_of::<FileEntryReply>(), 8);
        assert_eq!(offset_of!(FileEntryReply, request), 0);
        assert_eq!(offset_of!(FileEntryReply, index), 8);
        assert_eq!(offset_of!(FileEntryReply, metadata), 12);
        assert_eq!(offset_of!(FileEntryReply, name), 16);
        assert_eq!(size_of::<State>(), 32);
        assert_eq!(align_of::<State>(), 8);
        assert_eq!(offset_of!(State, generation), 0);
        assert_eq!(offset_of!(State, deadline), 8);
        assert_eq!(offset_of!(State, faults), 16);
        assert_eq!(offset_of!(State, restarts), 20);
        assert_eq!(offset_of!(State, phase), 24);
        assert_eq!(offset_of!(State, reserved), 28);
    }

    #[test]
    fn cold_boot_uses_generation_one_at_every_tick() {
        for now in [0, 1, 1024, u64::MAX - 1, u64::MAX] {
            let state = initialized(now);
            assert_eq!(state.generation, 1);
            assert_eq!(state.phase, READY);
            assert_eq!(state.deadline, 0);
            assert_eq!(state.faults, 0);
            assert_eq!(state.restarts, 0);
            assert!(state.valid());
        }
    }

    #[test]
    fn fault_revokes_the_endpoint_before_recovery() {
        let mut states = [initialized(100); 4];
        let endpoint = states[0].handle(0);
        assert_eq!(resolve(&states, endpoint), 0);
        unsafe { z_policy_fault(&mut states[0], 100) };
        assert_eq!(states[0].phase, BACKOFF);
        assert_eq!(states[0].deadline, 104);
        assert_eq!(states[0].handle(0), 0);
        assert_eq!(resolve(&states, endpoint), UNAVAILABLE);
        assert_eq!(states[1], initialized(100));
        assert_eq!(states[2], initialized(100));
        assert_eq!(states[3], initialized(100));
    }

    #[test]
    fn restart_is_due_once_at_the_deadline() {
        let mut state = initialized(10);
        state.fault(10);
        for now in [0, 10, 11, 12, 13] {
            let before = state;
            assert!(!state.poll(now));
            assert_eq!(state, before);
        }
        assert!(state.poll(14));
        assert_eq!(state.phase, READY);
        assert_eq!(state.generation, 2);
        assert_eq!(state.restarts, 1);
        assert_eq!(state.deadline, 0);
        let after = state;
        for now in [14, 15, u64::MAX] {
            assert!(!state.poll(now));
            assert_eq!(state, after);
        }
    }

    #[test]
    fn old_handles_never_revive_after_reboot() {
        let mut states = [initialized(0); 4];
        let mut retired = Vec::new();
        for (now, delay) in [(0, 4), (4, 8), (12, 16)] {
            let current = states[0].handle(0);
            retired.push(current);
            assert_eq!(resolve(&states, current), 0);
            states[0].fault(now);
            assert_eq!(resolve(&states, current), UNAVAILABLE);
            assert!(states[0].poll(now + delay));
            for old in &retired {
                assert_eq!(resolve(&states, *old), STALE);
            }
            assert_eq!(resolve(&states, states[0].handle(0)), 0);
        }
        states[0].fault(28);
        assert_eq!(states[0].phase, QUARANTINED);
        for old in &retired {
            assert_eq!(resolve(&states, *old), STALE);
        }
        assert_eq!(resolve(&states, (4 << 8) | 1), UNAVAILABLE);
    }

    #[test]
    fn restart_budget_survives_a_long_healthy_interval() {
        let mut state = initialized(0);
        for (fault_tick, restart_tick) in [(0, 4), (1_000_000, 1_000_008),
                                          (2_000_000, 2_000_016)] {
            state.fault(fault_tick);
            assert!(state.poll(restart_tick));
            assert!(state.valid());
        }
        let generation = state.generation;
        state.fault(9_000_000);
        assert_eq!(state.phase, QUARANTINED);
        assert!(!state.poll(u64::MAX));
        assert_eq!(state.generation, generation);
        assert_eq!(state.restarts, 3);
        assert_eq!(state.faults, 4);
    }

    #[test]
    fn fault_storms_do_not_postpone_or_accelerate_recovery() {
        let mut state = initialized(50);
        state.fault(50);
        for now in 0..1_000 {
            state.fault(now);
            assert_eq!(state.deadline, 54);
            assert_eq!(state.phase, BACKOFF);
            assert_eq!(state.generation, 1);
            assert_eq!(state.restarts, 0);
        }
        assert_eq!(state.faults, 1_001);
        assert!(!state.poll(53));
        assert!(state.poll(54));
        assert_eq!(state.restarts, 1);
        assert_eq!(state.generation, 2);
    }

    #[test]
    fn fault_counter_saturates_without_changing_budget() {
        for phase in [READY, BACKOFF, QUARANTINED] {
            let mut state = initialized(0);
            state.faults = u32::MAX - 1;
            if phase == BACKOFF {
                state.fault(0);
            } else if phase == QUARANTINED {
                state.phase = QUARANTINED;
            }
            assert!(state.valid());
            state.fault(100);
            state.fault(101);
            assert_eq!(state.faults, u32::MAX);
            assert_eq!(state.restarts, 0);
            assert!(state.valid());
        }
    }

    #[test]
    fn generation_exhaustion_is_terminal() {
        let mut states = [initialized(0); 4];
        states[0].generation = GENERATION_MAX - 1;
        let previous = states[0].handle(0);
        states[0].fault(0);
        assert!(states[0].poll(4));
        assert_eq!(states[0].generation, GENERATION_MAX);
        let last = states[0].handle(0);
        assert_eq!(last, i64::MAX as u64 - 254);
        assert_eq!(resolve(&states, last), 0);
        assert_eq!(resolve(&states, previous), STALE);
        states[0].fault(4);
        assert_eq!(states[0].phase, QUARANTINED);
        assert!(!states[0].poll(u64::MAX));
        assert_eq!(states[0].generation, GENERATION_MAX);
        assert_eq!(resolve(&states, last), UNAVAILABLE);
        assert!(states[0].valid());
    }

    #[test]
    fn tick_exhaustion_cannot_create_an_early_reboot() {
        for restarts in 0..RESTART_LIMIT {
            let mut state = initialized(0);
            state.restarts = restarts;
            state.faults = restarts;
            let delay = 4u64 << restarts;
            let last_schedulable = u64::MAX - delay;
            state.fault(last_schedulable);
            assert_eq!(state.phase, BACKOFF);
            assert_eq!(state.deadline, u64::MAX);
            assert!(!state.poll(u64::MAX - 1));
            assert!(state.poll(u64::MAX));
            let generation = state.generation;
            state.fault(u64::MAX);
            assert_eq!(state.phase, QUARANTINED);
            assert_eq!(state.generation, generation);
        }
    }

    #[test]
    fn all_overflowing_deadlines_quarantine() {
        for restarts in 0..RESTART_LIMIT {
            let delay = 4u64 << restarts;
            for distance in 0..delay {
                let mut state = initialized(0);
                state.restarts = restarts;
                state.faults = restarts;
                state.fault(u64::MAX - distance);
                assert_eq!(state.phase, QUARANTINED);
                assert_eq!(state.deadline, 0);
                assert_eq!(state.generation, 1);
                assert!(!state.poll(u64::MAX));
                assert!(state.valid());
            }
        }
    }

    #[test]
    fn quarantine_stays_terminal_under_fault_storms() {
        let mut state = initialized(0);
        state.restarts = 3;
        state.faults = 3;
        state.fault(0);
        let generation = state.generation;
        for tick in 0..10_000 {
            state.fault(tick);
            assert!(!state.poll(tick));
            assert_eq!(state.handle(0), 0);
            assert_eq!(state.phase, QUARANTINED);
            assert_eq!(state.generation, generation);
            assert_eq!(state.deadline, 0);
            assert_eq!(state.restarts, 3);
        }
    }

    #[test]
    fn dormant_state_never_exports_or_reboots() {
        let mut states = [dormant(); 4];
        for now in [0, 1, 4, u64::MAX] {
            states[0].fault(now);
            assert!(!states[0].poll(now));
            assert_eq!(states[0].handle(0), 0);
            assert_eq!(resolve(&states, 257), INVALID);
            assert_eq!(states[0], dormant());
        }
        assert!(states[0].valid());
    }

    #[test]
    fn all_cells_have_distinct_capability_encodings() {
        let states = [initialized(0); 4];
        let mut handles = Vec::new();
        for slot in 0..4 {
            let handle = states[slot as usize].handle(slot);
            assert_ne!(handle, 0);
            assert_eq!(handle & 0xff, u64::from(slot + 1));
            assert_eq!(handle >> 8, 1);
            assert_eq!(resolve(&states, handle), slot as i32);
            assert!(!handles.contains(&handle));
            handles.push(handle);
        }
    }

    #[test]
    fn handles_reject_unassigned_slots() {
        let state = initialized(0);
        for slot in [8, 9, 254, 255, 256, u32::MAX] {
            assert_eq!(state.handle(slot), 0);
        }
        let states = [state; 4];
        for generation in [0, 1, 2, GENERATION_MAX] {
            for low in 0..256 {
                let handle = (generation << 8) | low;
                let status = resolve(&states, handle);
                if generation == 0 || low == 0 || low > 4 {
                    assert_eq!(status, INVALID);
                } else if generation != 1 {
                    assert_eq!(status, STALE);
                } else {
                    assert_eq!(status, low as i32 - 1);
                }
            }
        }
    }

    #[test]
    fn a_short_state_table_cannot_resolve_outside_itself() {
        let states = [initialized(0); 4];
        for length in 0..=4 {
            for slot in 0..4 {
                let handle = states[slot].handle(slot as u32);
                let status = resolve(&states[..length], handle);
                assert_eq!(status, if slot < length { slot as i32 } else { INVALID });
            }
        }
        unsafe {
            assert_eq!(z_policy_resolve(states.as_ptr(), 9, 257), INVALID);
            assert_eq!(z_policy_resolve(states.as_ptr(), u32::MAX, 257), INVALID);
        }
    }

    #[test]
    fn null_ffi_arguments_fail_closed() {
        unsafe {
            z_policy_init(ptr::null_mut(), 0);
            z_policy_fault(ptr::null_mut(), u64::MAX);
            z_policy_stop(ptr::null_mut());
            assert_eq!(z_policy_poll(ptr::null_mut(), u64::MAX), 0);
            assert_eq!(z_policy_handle(ptr::null(), 0), 0);
            assert_eq!(z_policy_check(ptr::null()), 0);
            assert_eq!(z_policy_resolve(ptr::null(), 4, 257), INVALID);
        }
    }

    #[test]
    fn malformed_state_is_rejected_without_mutation() {
        let ready = initialized(0);
        let mut malformed = Vec::new();
        for generation in [0, GENERATION_MAX + 1, u64::MAX] {
            malformed.push(State { generation, ..ready });
        }
        for phase in [5, 255, u32::MAX] {
            malformed.push(State { phase, ..ready });
        }
        malformed.push(State { reserved: 1, ..ready });
        malformed.push(State { deadline: 1, ..ready });
        malformed.push(State { restarts: 4, faults: 4, ..ready });
        malformed.push(State { restarts: 1, ..ready });
        malformed.push(State { phase: BACKOFF, faults: 1, ..ready });
        malformed.push(State { phase: QUARANTINED, ..ready });
        malformed.push(State { phase: DORMANT, faults: 1, ..ready });
        malformed.push(State { phase: BACKOFF, generation: GENERATION_MAX,
                               deadline: 4, faults: 1, ..ready });
        for original in malformed {
            let mut state = original;
            assert!(!state.valid(), "{state:?}");
            state.fault(0);
            state.stop();
            assert!(!state.poll(u64::MAX));
            assert_eq!(state.handle(0), 0);
            assert_eq!(resolve(&[state], 257), INVALID);
            assert_eq!(state, original);
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Action {
        Fault(u64),
        Poll(u64),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ModelPhase {
        Live,
        Waiting(u64),
        Dead,
    }

    #[derive(Clone, Copy, Debug)]
    struct Model {
        epoch: u64,
        attempts: u32,
        reports: u32,
        phase: ModelPhase,
    }

    impl Model {
        fn new() -> Self {
            Self { epoch: 1, attempts: 0, reports: 0, phase: ModelPhase::Live }
        }

        fn step(&mut self, action: Action) -> bool {
            match action {
                Action::Fault(now) => {
                    if self.reports != u32::MAX {
                        self.reports += 1;
                    }
                    if self.phase != ModelPhase::Live {
                        return false;
                    }
                    if self.attempts >= 3 || self.epoch == GENERATION_MAX {
                        self.phase = ModelPhase::Dead;
                    } else {
                        let wait = [4, 8, 16][self.attempts as usize];
                        self.phase = if u128::from(now) + u128::from(wait) > u128::from(u64::MAX) {
                            ModelPhase::Dead
                        } else {
                            ModelPhase::Waiting(now + wait)
                        };
                    }
                    false
                }
                Action::Poll(now) => match self.phase {
                    ModelPhase::Waiting(deadline) if now >= deadline => {
                        self.epoch += 1;
                        self.attempts += 1;
                        self.phase = ModelPhase::Live;
                        true
                    }
                    _ => false,
                },
            }
        }

        fn compare(&self, state: &State) {
            assert_eq!(state.generation, self.epoch);
            assert_eq!(state.restarts, self.attempts);
            assert_eq!(state.faults, self.reports);
            match self.phase {
                ModelPhase::Live => {
                    assert_eq!(state.phase, READY);
                    assert_eq!(state.deadline, 0);
                }
                ModelPhase::Waiting(deadline) => {
                    assert_eq!(state.phase, BACKOFF);
                    assert_eq!(state.deadline, deadline);
                }
                ModelPhase::Dead => {
                    assert_eq!(state.phase, QUARANTINED);
                    assert_eq!(state.deadline, 0);
                }
            }
            assert!(state.valid());
        }
    }

    fn advance(state: &mut State, model: &mut Model, action: Action) {
        let expected_reboot = model.step(action);
        let actual_reboot = match action {
            Action::Fault(now) => {
                state.fault(now);
                false
            }
            Action::Poll(now) => state.poll(now),
        };
        assert_eq!(actual_reboot, expected_reboot, "{action:?}");
        model.compare(state);
    }

    fn explore(state: State, model: Model, depth: u32, nodes: &mut u64) {
        *nodes += 1;
        model.compare(&state);
        if depth == 0 {
            return;
        }
        let boundary = match model.phase {
            ModelPhase::Waiting(deadline) => deadline,
            _ => 28,
        };
        let ticks = [0, boundary.saturating_sub(1), boundary, boundary.saturating_add(1)];
        for now in ticks {
            for action in [Action::Fault(now), Action::Poll(now)] {
                let mut successor = state;
                let mut oracle = model;
                advance(&mut successor, &mut oracle, action);
                explore(successor, oracle, depth - 1, nodes);
            }
        }
    }

    #[test]
    fn bounded_model_check_all_adversarial_sequences() {
        let mut nodes = 0;
        explore(initialized(0), Model::new(), 6, &mut nodes);
        assert_eq!(nodes, 299_593);
    }

    fn random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn deterministic_random_traces_match_an_independent_model() {
        for seed in 1..=256 {
            let mut entropy = seed;
            let mut state = initialized(0);
            let mut model = Model::new();
            let mut now = 0u64;
            for step in 0..256 {
                let draw = random(&mut entropy);
                now = now.saturating_add((draw >> 8) & 15);
                let tick = match draw & 7 {
                    0 => 0,
                    1 => u64::MAX,
                    2 => u64::MAX - ((draw >> 16) & 31),
                    _ => now,
                };
                let action = if draw & 0x10 == 0 {
                    Action::Fault(tick)
                } else {
                    Action::Poll(tick)
                };
                advance(&mut state, &mut model, action);
                assert!(state.generation >= 1, "seed={seed} step={step}");
            }
        }
    }

    #[test]
    fn independent_cells_cannot_revoke_each_others_handles() {
        for victim in 0..4 {
            let mut states = [initialized(0); 4];
            let handles = [257, 258, 259, 260];
            for cycle in 0..=3 {
                states[victim].fault(cycle * 64);
                for slot in 0..4 {
                    if slot == victim {
                        assert!(resolve(&states, handles[slot]) < 0);
                    } else {
                        assert_eq!(resolve(&states, handles[slot]), slot as i32);
                        assert_eq!(states[slot], initialized(0));
                    }
                }
                states[victim].poll(cycle * 64 + 32);
            }
            assert_eq!(states[victim].phase, QUARANTINED);
        }
    }

    #[test]
    fn epoch_mismatch_takes_precedence_over_availability() {
        let mut state = initialized(0);
        state.generation = 20;
        state.fault(0);
        assert_eq!(resolve(&[state], (19 << 8) | 1), STALE);
        assert_eq!(resolve(&[state], (20 << 8) | 1), UNAVAILABLE);
        assert_eq!(resolve(&[state], (21 << 8) | 1), STALE);
    }

    #[test]
    fn ffi_and_core_have_identical_lifecycle_results() {
        let mut direct = initialized(0);
        let mut ffi = direct;
        for action in [Action::Fault(0), Action::Poll(3), Action::Poll(4),
                       Action::Fault(4), Action::Fault(5), Action::Poll(11),
                       Action::Poll(12), Action::Fault(12), Action::Poll(28),
                       Action::Fault(28), Action::Poll(u64::MAX)] {
            match action {
                Action::Fault(now) => {
                    direct.fault(now);
                    unsafe { z_policy_fault(&mut ffi, now) };
                }
                Action::Poll(now) => {
                    let expected = i32::from(direct.poll(now));
                    assert_eq!(unsafe { z_policy_poll(&mut ffi, now) }, expected);
                }
            }
            assert_eq!(ffi, direct);
            assert_eq!(unsafe { z_policy_check(&ffi) }, 1);
            assert_eq!(unsafe { z_policy_handle(&ffi, 0) }, direct.handle(0));
        }
    }

    #[test]
    fn intentional_exit_is_terminal_without_faulting() {
        let mut state = initialized(0);
        let endpoint = state.handle(0);
        unsafe { z_policy_stop(&mut state) };
        assert_eq!(state.phase, STOPPED);
        assert_eq!(state.generation, 1);
        assert_eq!(state.faults, 0);
        assert_eq!(state.restarts, 0);
        assert_eq!(state.deadline, 0);
        assert_eq!(resolve(&[state], endpoint), UNAVAILABLE);
        assert_eq!(state.handle(0), 0);
        assert!(state.valid());
        let exited = state;
        for now in [0, 1, 4, 1024, u64::MAX] {
            state.fault(now);
            assert!(!state.poll(now));
            state.stop();
            assert_eq!(state, exited);
        }
    }

    #[test]
    fn stop_cancels_pending_recovery_at_every_restart_attempt() {
        let mut current = initialized(0);
        for attempt in 0..3 {
            let mut exiting = current;
            let endpoint = exiting.handle(0);
            exiting.fault(100);
            let deadline = exiting.deadline;
            assert_eq!(exiting.phase, BACKOFF);
            exiting.stop();
            assert_eq!(exiting.phase, STOPPED);
            assert_eq!(exiting.deadline, 0);
            assert_eq!(exiting.restarts, attempt);
            assert_eq!(exiting.generation, u64::from(attempt) + 1);
            assert_eq!(resolve(&[exiting], endpoint), UNAVAILABLE);
            let stopped = exiting;
            for now in [deadline - 1, deadline, deadline + 1, u64::MAX] {
                exiting.fault(now);
                assert!(!exiting.poll(now));
                assert_eq!(exiting, stopped);
            }
            current.fault(100);
            assert!(current.poll(deadline));
        }
    }

    #[test]
    fn stopping_one_cell_preserves_all_other_cells() {
        for victim in 0..4 {
            let mut states = [initialized(0); 4];
            let mut endpoints = [0; 4];
            for slot in 0..4 {
                endpoints[slot] = states[slot].handle(slot as u32);
            }
            unsafe { z_policy_stop(&mut states[victim]) };
            for slot in 0..4 {
                if slot == victim {
                    assert_eq!(resolve(&states, endpoints[slot]), UNAVAILABLE);
                    assert_eq!(states[slot].phase, STOPPED);
                } else {
                    assert_eq!(resolve(&states, endpoints[slot]), slot as i32);
                    assert_eq!(states[slot], initialized(0));
                }
            }
        }
    }

    #[test]
    fn stopping_dormant_and_quarantined_cells_remains_safe() {
        for generation in [0, 1, GENERATION_MAX] {
            let mut state = State { generation, ..dormant() };
            let original = state;
            state.stop();
            assert_eq!(state, original);
            assert!(state.valid());
        }
        let mut state = initialized(0);
        state.generation = GENERATION_MAX;
        state.fault(0);
        assert_eq!(state.phase, QUARANTINED);
        state.stop();
        assert_eq!(state.phase, STOPPED);
        assert_eq!(state.faults, 1);
        assert_eq!(state.generation, GENERATION_MAX);
        assert!(state.valid());
        assert!(!state.poll(u64::MAX));
    }

    #[test]
    fn all_issued_endpoints_fit_positive_signed_syscall_results() {
        for generation in [1, 2, 255, 256, GENERATION_MAX - 1, GENERATION_MAX] {
            let states = [State { generation, ..initialized(0) }; 4];
            for slot in 0..4 {
                let endpoint = states[slot].handle(slot as u32);
                assert!(endpoint > 0);
                assert!((endpoint as i64) > 0);
                assert_eq!(resolve(&states, endpoint), slot as i32);
            }
        }
        let states = [initialized(0); 4];
        for generation in [GENERATION_MAX + 1, u64::MAX >> 8] {
            for slot in 1..=4 {
                assert_eq!(resolve(&states, (generation << 8) | slot), INVALID);
            }
        }
    }
}
