use super::{State, CELLS, GENERATION_MAX, READY};
use core::ptr;

const SLOTS: usize = 32;
const ROOTS: usize = 16;
const MANIFEST_ROOT_CELLS: u32 = 4;
const DELEGATE: u32 = 1 << 31;
const OPERATIONS: u32 = super::Z_RIGHT_OPERATIONS;
const INVALID: i64 = -1;
const DENIED: i64 = -2;
const STALE: i64 = -3;
const AGAIN: i64 = -4;
const NO_SPACE: i64 = -7;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Grant {
    holder: u32,
    target: u32,
    rights: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    holder: u64,
    target: u64,
    rights: u32,
    reserved: u32,
    parent: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    epoch: u64,
    holder: u64,
    target: u64,
    parent: u64,
    issuer: u64,
    rights: u32,
    live: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Root {
    grant: Grant,
    holder_generation: u64,
    target_generation: u64,
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    entries: [Entry; SLOTS],
    roots: [Root; ROOTS],
    next_epoch: u64,
    root_count: u32,
    reserved: u32,
}

fn valid_rights(rights: u32) -> bool {
    rights & OPERATIONS != 0 && rights & !(OPERATIONS | DELEGATE) == 0
}

fn endpoint(states: &[State; CELLS as usize], handle: u64) -> Option<usize> {
    let low = (handle & 255) as usize;
    let generation = handle >> 8;
    if low == 0 || low > states.len() || generation == 0 || generation > GENERATION_MAX {
        return None;
    }
    let state = &states[low - 1];
    (state.valid() && state.phase == READY && state.generation == generation).then_some(low - 1)
}

impl Table {
    fn new() -> Self {
        Self {
            entries: [Entry::default(); SLOTS],
            roots: [Root::default(); ROOTS],
            next_epoch: 1,
            root_count: 0,
            reserved: 0,
        }
    }

    fn slot(&self, handle: u64) -> Result<usize, i64> {
        let low = (handle & 255) as usize;
        let epoch = handle >> 8;
        if low == 0 || low > SLOTS || epoch == 0 || epoch > GENERATION_MAX {
            return Err(INVALID);
        }
        let entry = self.entries[low - 1];
        if entry.live != 1 || entry.epoch != epoch {
            return Err(STALE);
        }
        Ok(low - 1)
    }

    fn handle(&self, slot: usize) -> u64 {
        (self.entries[slot].epoch << 8) | (slot as u64 + 1)
    }

    fn active(&self, states: &[State; CELLS as usize], handle: u64) -> Result<usize, i64> {
        let first = self.slot(handle)?;
        let mut current = first;
        for _ in 0..SLOTS {
            let child = self.entries[current];
            if !valid_rights(child.rights)
                || endpoint(states, child.holder).is_none()
                || endpoint(states, child.target).is_none()
                || endpoint(states, child.issuer).is_none()
            {
                return Err(STALE);
            }
            if child.parent == 0 {
                return Ok(first);
            }
            current = self.slot(child.parent).map_err(|_| STALE)?;
            let parent = self.entries[current];
            if child.epoch <= parent.epoch
                || child.issuer != parent.holder
                || child.target != parent.target
                || parent.rights & DELEGATE == 0
                || child.rights & !parent.rights != 0
            {
                return Err(STALE);
            }
        }
        Err(STALE)
    }

    fn insert(&mut self, holder: u64, target: u64, rights: u32,
              parent: u64, issuer: u64) -> Result<u64, i64> {
        if self.next_epoch == 0 || self.next_epoch > GENERATION_MAX {
            return Err(NO_SPACE);
        }
        let slot = self.entries.iter().position(|entry| entry.live == 0).ok_or(NO_SPACE)?;
        self.entries[slot] = Entry {
            epoch: self.next_epoch, holder, target, parent, issuer, rights, live: 1,
        };
        self.next_epoch += 1;
        Ok(self.handle(slot))
    }

    fn configure(&mut self, grants: &[Grant]) -> i32 {
        if grants.len() > ROOTS || self.root_count != 0 || self.next_epoch != 1 {
            return INVALID as i32;
        }
        for (n, grant) in grants.iter().enumerate() {
            if grant.holder >= MANIFEST_ROOT_CELLS || grant.target >= MANIFEST_ROOT_CELLS || grant.reserved != 0
                || !valid_rights(grant.rights)
                || grants[..n].iter().any(|old| old.holder == grant.holder && old.target == grant.target)
            {
                return INVALID as i32;
            }
        }
        for (n, grant) in grants.iter().enumerate() {
            self.roots[n].grant = *grant;
        }
        self.root_count = grants.len() as u32;
        0
    }

    fn pending_roots(&self, states: &[State; CELLS as usize]) -> Result<([bool; ROOTS], usize), i32> {
        if self.root_count as usize > ROOTS || self.reserved != 0 || self.next_epoch == 0
            || self.next_epoch > GENERATION_MAX + 1 {
            return Err(INVALID as i32);
        }
        let mut pending = [false; ROOTS];
        let mut count = 0;
        for (n, root) in self.roots[..self.root_count as usize].iter().enumerate() {
            if root.grant.holder >= MANIFEST_ROOT_CELLS || root.grant.target >= MANIFEST_ROOT_CELLS
                || root.grant.reserved != 0 || !valid_rights(root.grant.rights)
                || root.holder_generation > GENERATION_MAX || root.target_generation > GENERATION_MAX {
                return Err(INVALID as i32);
            }
            let holder = states[root.grant.holder as usize].handle(root.grant.holder);
            let target = states[root.grant.target as usize].handle(root.grant.target);
            if holder != 0 && target != 0
                && (root.holder_generation != holder >> 8 || root.target_generation != target >> 8)
            {
                pending[n] = true;
                count += 1;
            }
        }
        Ok((pending, count))
    }

    fn refresh_epoch_status(&self, states: &[State; CELLS as usize]) -> i32 {
        let (_, count) = match self.pending_roots(states) { Ok(value) => value, Err(error) => return error };
        if count != 0 && (self.next_epoch > GENERATION_MAX
            || count as u64 - 1 > GENERATION_MAX - self.next_epoch) {
            NO_SPACE as i32
        } else { 0 }
    }

    fn refresh(&mut self, states: &[State; CELLS as usize]) -> i32 {
        let (pending, count) = match self.pending_roots(states) { Ok(value) => value, Err(error) => return error };
        self.reap_stale(states);
        if count == 0 {
            return 0;
        }
        if self.entries.iter().filter(|entry| entry.live == 0).count() < count
            || self.refresh_epoch_status(states) != 0
        {
            return NO_SPACE as i32;
        }
        for (n, needed) in pending.iter().enumerate() {
            if *needed {
                let root = self.roots[n];
                let holder = states[root.grant.holder as usize].handle(root.grant.holder);
                let target = states[root.grant.target as usize].handle(root.grant.target);
                if self.insert(holder, target, root.grant.rights, 0, holder).is_err() {
                    return NO_SPACE as i32;
                }
                self.roots[n].holder_generation = holder >> 8;
                self.roots[n].target_generation = target >> 8;
            }
        }
        0
    }

    fn check(&self, states: &[State; CELLS as usize], holder: u64,
             handle: u64, target: u64, rights: u32) -> i32 {
        if !valid_rights(rights) {
            return INVALID as i32;
        }
        if endpoint(states, holder).is_none() {
            return AGAIN as i32;
        }
        let slot = match self.active(states, handle) {
            Ok(slot) => slot,
            Err(error) => return error as i32,
        };
        let entry = self.entries[slot];
        if holder != entry.holder || target != entry.target || rights & !entry.rights != 0 {
            return DENIED as i32;
        }
        0
    }

    fn find(&self, states: &[State; CELLS as usize], holder: u64,
            target: u64, rights: u32) -> i64 {
        if !valid_rights(rights) {
            return INVALID;
        }
        if endpoint(states, holder).is_none() || endpoint(states, target).is_none() {
            return AGAIN;
        }
        for (slot, entry) in self.entries.iter().enumerate() {
            if entry.live == 1 && entry.holder == holder && entry.target == target
                && rights & !entry.rights == 0 && self.active(states, self.handle(slot)).is_ok()
            {
                return self.handle(slot) as i64;
            }
        }
        DENIED
    }

    fn delegate(&mut self, states: &[State; CELLS as usize], caller: u64,
                parent: u64, holder: u64, rights: u32) -> i64 {
        if !valid_rights(rights) {
            return INVALID;
        }
        if endpoint(states, caller).is_none() || endpoint(states, holder).is_none() {
            return AGAIN;
        }
        let slot = match self.active(states, parent) {
            Ok(slot) => slot,
            Err(error) => return error,
        };
        let entry = self.entries[slot];
        if entry.holder != caller || entry.rights & DELEGATE == 0 || rights & !entry.rights != 0 {
            return DENIED;
        }
        self.insert(holder, entry.target, rights, parent, caller).map_or_else(|error| error, |h| h as i64)
    }

    fn prune(&mut self) {
        for _ in 0..SLOTS {
            let mut changed = false;
            for slot in 0..SLOTS {
                let entry = self.entries[slot];
                if entry.live == 1 && entry.parent != 0 && self.slot(entry.parent).is_err() {
                    self.entries[slot] = Entry::default();
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn reap_stale(&mut self, states: &[State; CELLS as usize]) {
        for entry in &mut self.entries {
            if entry.live == 1 && (endpoint(states, entry.holder).is_none()
                || endpoint(states, entry.target).is_none()
                || endpoint(states, entry.issuer).is_none())
            {
                *entry = Entry::default();
            }
        }
        self.prune();
    }

    fn revoke(&mut self, states: &[State; CELLS as usize], caller: u64, handle: u64) -> i32 {
        if endpoint(states, caller).is_none() {
            return AGAIN as i32;
        }
        let slot = match self.active(states, handle) {
            Ok(slot) => slot,
            Err(error) => return error as i32,
        };
        let mut ancestor = slot;
        let mut allowed = false;
        for _ in 0..SLOTS {
            let entry = self.entries[ancestor];
            if caller == entry.holder || caller == entry.issuer {
                allowed = true;
                break;
            }
            if entry.parent == 0 {
                break;
            }
            ancestor = match self.slot(entry.parent) {
                Ok(slot) => slot,
                Err(_) => break,
            };
        }
        if !allowed {
            return DENIED as i32;
        }
        self.entries[slot] = Entry::default();
        self.prune();
        0
    }

    fn invalidate(&mut self, cell: u32) {
        if cell >= CELLS {
            return;
        }
        for entry in &mut self.entries {
            if entry.live == 1 && [entry.holder, entry.target, entry.issuer].iter()
                .any(|endpoint| endpoint & 255 == u64::from(cell + 1))
            {
                *entry = Entry::default();
            }
        }
        self.prune();
    }

    fn channel(&mut self, states: &[State; CELLS as usize], parent: u64,
               child: u64) -> Result<(u64, u64), i32> {
        if endpoint(states, parent).is_none() {
            return Err(AGAIN as i32);
        }
        let low = (child & 255) as usize;
        let generation = child >> 8;
        if low <= MANIFEST_ROOT_CELLS as usize || low > CELLS as usize
            || generation == 0 || generation > GENERATION_MAX || child == parent
        {
            return Err(INVALID as i32);
        }
        let state = &states[low - 1];
        // The production lifecycle engine can install channels for a prepared
        // future generation or explicitly rebind a currently published child.
        if !state.valid() || !((state.phase == super::DORMANT && generation > state.generation)
            || (state.phase == READY && state.generation == generation))
        {
            return Err(STALE as i32);
        }
        if self.entries.iter().filter(|entry| entry.live == 0).count() < 2
            || self.next_epoch == 0 || self.next_epoch >= GENERATION_MAX
        {
            return Err(NO_SPACE as i32);
        }
        // Preflight makes both insertions infallible. Epochs are never rewound
        // if the encompassing creation transaction later aborts.
        let request = self.insert(parent, child, 1 << 14, 0, parent)
            .map_err(|error| error as i32)?;
        let reply = self.insert(child, parent, 1 << 15, 0, parent)
            .map_err(|error| error as i32)?;
        Ok((request, reply))
    }

    fn drop_channel(&mut self, first: u64, second: u64) {
        for handle in [first, second] {
            if let Ok(slot) = self.slot(handle) {
                self.entries[slot] = Entry::default();
            }
        }
        self.prune();
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_channel(table: *mut Table,
    states: *const [State; CELLS as usize], parent: u64, child: u64,
    parent_cap: *mut u64, child_cap: *mut u64) -> i32 {
    let (table, states) = match (table.as_mut(), states.as_ref()) {
        (Some(table), Some(states)) if !parent_cap.is_null() && !child_cap.is_null()
            && parent_cap != child_cap => (table, states),
        _ => return INVALID as i32,
    };
    match table.channel(states, parent, child) {
        Ok((request, reply)) => { ptr::write(parent_cap, request); ptr::write(child_cap, reply); 0 }
        Err(error) => error,
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_drop_channel(table: *mut Table, first: u64, second: u64) {
    if let Some(table) = table.as_mut() { table.drop_channel(first, second); }
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_init(table: *mut Table) {
    if !table.is_null() {
        ptr::write(table, Table::new());
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_configure(table: *mut Table, grants: *const Grant, count: u32) -> i32 {
    if table.is_null() || count as usize > ROOTS || (count != 0 && grants.is_null()) {
        return INVALID as i32;
    }
    let grants = if count == 0 { &[] } else { core::slice::from_raw_parts(grants, count as usize) };
    (*table).configure(grants)
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_refresh(table: *mut Table, states: *const [State; CELLS as usize]) -> i32 {
    match (table.as_mut(), states.as_ref()) {
        (Some(table), Some(states)) => table.refresh(states),
        _ => INVALID as i32,
    }
}

/// Privileged read-only classification of the exact pending manifest-root
/// batch. This shares root entitlement/generation checks with publication.
#[no_mangle]
pub unsafe extern "C" fn z_caps_refresh_epoch_status(table: *const Table,
    states: *const [State; CELLS as usize]) -> i32 {
    match (table.as_ref(), states.as_ref()) {
        (Some(table), Some(states)) => table.refresh_epoch_status(states),
        _ => INVALID as i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_check(table: *const Table, states: *const [State; CELLS as usize],
    holder: u64, cap: u64, target: u64, rights: u32) -> i32 {
    match (table.as_ref(), states.as_ref()) {
        (Some(table), Some(states)) => table.check(states, holder, cap, target, rights),
        _ => INVALID as i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_find(table: *const Table, states: *const [State; CELLS as usize],
    holder: u64, target: u64, rights: u32) -> i64 {
    match (table.as_ref(), states.as_ref()) {
        (Some(table), Some(states)) => table.find(states, holder, target, rights),
        _ => INVALID,
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_delegate(table: *mut Table, states: *const [State; CELLS as usize],
    caller: u64, parent: u64, holder: u64, rights: u32) -> i64 {
    match (table.as_mut(), states.as_ref()) {
        (Some(table), Some(states)) => table.delegate(states, caller, parent, holder, rights),
        _ => INVALID,
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_query(table: *const Table, states: *const [State; CELLS as usize],
    caller: u64, cap: u64, info: *mut Info) -> i32 {
    let (table, states) = match (table.as_ref(), states.as_ref()) {
        (Some(table), Some(states)) if !info.is_null() => (table, states),
        _ => return INVALID as i32,
    };
    if endpoint(states, caller).is_none() {
        return AGAIN as i32;
    }
    let entry = match table.active(states, cap) {
        Ok(slot) => table.entries[slot],
        Err(error) => return error as i32,
    };
    if entry.holder != caller {
        return DENIED as i32;
    }
    ptr::write(info, Info { holder: entry.holder, target: entry.target,
        rights: entry.rights, reserved: 0, parent: entry.parent });
    0
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_revoke(table: *mut Table, states: *const [State; CELLS as usize],
    caller: u64, cap: u64) -> i32 {
    match (table.as_mut(), states.as_ref()) {
        (Some(table), Some(states)) => table.revoke(states, caller, cap),
        _ => INVALID as i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_caps_invalidate(table: *mut Table, cell: u32) {
    if let Some(table) = table.as_mut() {
        table.invalidate(cell);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    fn states() -> [State; CELLS as usize] {
        [State::initial(); CELLS as usize]
    }

    fn configured(states: &[State; CELLS as usize]) -> Table {
        let mut table = Table::new();
        let roots = [
            Grant { holder: 1, target: 1, rights: 4 | DELEGATE, reserved: 0 },
            Grant { holder: 2, target: 1, rights: 4, reserved: 0 },
        ];
        assert_eq!(table.configure(&roots), 0);
        assert_eq!(table.refresh(states), 0);
        table
    }

    #[test]
    fn capability_ffi_layout_matches_c_and_zig() {
        assert_eq!(size_of::<Grant>(), 16);
        assert_eq!(offset_of!(Grant, rights), 8);
        assert_eq!(size_of::<Info>(), 32);
        assert_eq!(align_of::<Info>(), 8);
        assert_eq!(offset_of!(Info, parent), 24);
        assert_eq!(size_of::<Entry>(), 48);
        assert_eq!(offset_of!(Entry, rights), 40);
        assert_eq!(size_of::<Root>(), 32);
        assert_eq!(offset_of!(Root, holder_generation), 16);
        assert_eq!(size_of::<Table>(), 2064);
        assert_eq!(offset_of!(Table, roots), 1536);
        assert_eq!(offset_of!(Table, next_epoch), 2048);
    }

    #[test]
    fn attenuation_delegation_and_forgery_checks() {
        let states = states();
        let mut table = configured(&states);
        let fs = states[1].handle(1);
        let client = states[2].handle(2);
        let parent = table.find(&states, fs, fs, 4 | DELEGATE);
        assert!(parent > 0);
        let child = table.delegate(&states, fs, parent as u64, client, 4);
        assert!(child > 0 && child != parent);
        assert_eq!(table.check(&states, client, child as u64, fs, 4), 0);
        assert_eq!(table.check(&states, client, child as u64, fs, 1), DENIED as i32);
        assert_eq!(table.check(&states, fs, child as u64, fs, 4), DENIED as i32);
        assert_eq!(table.delegate(&states, client, child as u64, fs, 4), DENIED);
        assert_eq!(table.delegate(&states, fs, parent as u64, client, 4 | DELEGATE | 1), DENIED);
        assert_eq!(table.check(&states, client, (child as u64) ^ (1 << 8), fs, 4), STALE as i32);
    }

    #[test]
    fn storage_operation_rights_do_not_widen_read_authority() {
        let states = states();
        let mut table = configured(&states);
        let fs = states[1].handle(1);
        let client = states[2].handle(2);
        let parent = table.find(&states, fs, fs, 4 | DELEGATE) as u64;
        let child = table.delegate(&states, fs, parent, client, 4) as u64;
        for operation in 7..=super::super::Z_OPERATION_MAX {
            let right = 1 << (operation - 1);
            assert!(valid_rights(right));
            assert_eq!(table.check(&states, client, child, fs, right), DENIED as i32);
            assert_eq!(table.delegate(&states, fs, parent, client, right), DENIED);
        }
        for rights in [0, DELEGATE, 1 << 16, 1 << 30, u32::MAX] {
            assert!(!valid_rights(rights));
            assert_eq!(table.find(&states, client, fs, rights), INVALID);
        }
        let mut writable = Table::new();
        let write = 1 << 11;
        assert_eq!(writable.configure(&[Grant { holder: 2, target: 1,
                                               rights: write, reserved: 0 }]), 0);
        assert_eq!(writable.refresh(&states), 0);
        let authority = writable.find(&states, client, fs, write) as u64;
        assert_eq!(writable.check(&states, client, authority, fs, write), 0);
        assert_eq!(writable.check(&states, client, authority, fs, 4), DENIED as i32);
        assert_eq!(writable.revoke(&states, client, authority), 0);
        assert_eq!(writable.check(&states, client, authority, fs, write), STALE as i32);
    }

    #[test]
    fn ancestor_and_holder_revocation_remove_all_derived_authority() {
        let states = states();
        let mut table = configured(&states);
        let fs = states[1].handle(1);
        let client = states[2].handle(2);
        let parent = table.find(&states, fs, fs, 4 | DELEGATE) as u64;
        let child = table.delegate(&states, fs, parent, client, 4 | DELEGATE) as u64;
        let grandchild = table.delegate(&states, client, child, states[3].handle(3), 4);
        assert!(grandchild > 0);
        assert_eq!(table.revoke(&states, fs, parent), 0);
        assert_eq!(table.check(&states, client, child, fs, 4), STALE as i32);
        assert_eq!(table.check(&states, states[3].handle(3), grandchild as u64, fs, 4), STALE as i32);
    }

    #[test]
    fn reboot_reclaims_slots_without_revalidating_old_handles() {
        let mut states = states();
        let mut table = configured(&states);
        let old = table.find(&states, states[2].handle(2), states[1].handle(1), 4) as u64;
        for generation in 1..=100 {
            states[1].phase = crate::BACKOFF;
            states[1].deadline = 1;
            table.invalidate(1);
            states[1].phase = READY;
            states[1].generation = generation + 1;
            states[1].deadline = 0;
            assert_eq!(table.refresh(&states), 0);
            let fresh = table.find(&states, states[2].handle(2), states[1].handle(1), 4);
            assert!(fresh > 0 && fresh as u64 != old);
            assert_ne!(table.check(&states, states[2].handle(2), old,
                                   states[1].handle(1), 4), 0);
        }
    }

    #[test]
    fn bounded_table_pressure_does_not_partially_insert() {
        let states = states();
        let mut table = configured(&states);
        let fs = states[1].handle(1);
        let client = states[2].handle(2);
        let parent = table.find(&states, fs, fs, 4 | DELEGATE) as u64;
        let mut count = 0;
        while table.delegate(&states, fs, parent, client, 4) > 0 { count += 1; }
        assert_eq!(count, SLOTS - 2);
        let before = table.clone();
        assert_eq!(table.delegate(&states, fs, parent, client, 4), NO_SPACE);
        assert_eq!(table, before);
    }
    #[test]
    fn static_refresh_epoch_status_uses_exact_atomic_pending_batch() {
        let mut states = states();
        let mut table = configured(&states);
        assert_eq!(table.refresh_epoch_status(&states), 0);
        table.invalidate(1);
        states[1].fault(0);
        assert!(states[1].poll(4));
        let (_, pending) = table.pending_roots(&states).unwrap();
        assert_eq!(pending, 2);
        table.next_epoch = GENERATION_MAX;
        let before = table.clone();
        assert_eq!(table.refresh_epoch_status(&states), NO_SPACE as i32);
        assert_eq!(table, before);
        table.next_epoch = GENERATION_MAX - 1;
        assert_eq!(table.refresh_epoch_status(&states), 0);
        assert_eq!(table.refresh(&states), 0);
        assert_eq!(table.next_epoch, GENERATION_MAX + 1);
        assert_eq!(table.refresh_epoch_status(&states), 0);
        assert_eq!(table.refresh(&states), 0);
        states[1].fault(4); assert!(states[1].poll(12));
        assert_eq!(table.refresh_epoch_status(&states), NO_SPACE as i32);
    }
    #[test]
    fn static_refresh_metadata_and_null_ffi_fail_closed_without_mutation() {
        let states = states();
        let original = configured(&states);
        for field in 0..8 {
            let mut table = original.clone();
            match field {
                0 => table.root_count = ROOTS as u32 + 1,
                1 => table.reserved = 1,
                2 => table.roots[0].grant.holder = u32::MAX,
                3 => table.roots[0].grant.target = MANIFEST_ROOT_CELLS,
                4 => table.roots[0].grant.reserved = 1,
                5 => table.roots[0].holder_generation = GENERATION_MAX + 1,
                6 => table.next_epoch = 0,
                7 => table.next_epoch = GENERATION_MAX + 2,
                _ => unreachable!(),
            }
            let before = table.clone();
            assert_eq!(table.refresh_epoch_status(&states), INVALID as i32);
            assert_eq!(table.refresh(&states), INVALID as i32);
            assert_eq!(table, before);
        }
        unsafe {
            assert_eq!(z_caps_refresh_epoch_status(ptr::null(), &states), INVALID as i32);
            assert_eq!(z_caps_refresh_epoch_status(&original, ptr::null()), INVALID as i32);
        }
    }
}
