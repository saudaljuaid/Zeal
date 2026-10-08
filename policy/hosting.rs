//! Finite hierarchy and delegated-resource policy. Physical pages and frames are
//! privileged C mechanisms; this ledger conserves logical commitments and never
//! publishes an execution until C has initialized and copied the result.
use super::{State, BACKOFF, DORMANT, GENERATION_MAX, QUARANTINED, READY, STOPPED};
use core::ptr;

const ROOTS: usize = 4;
const SLOTS: usize = 8;
const OBJECTS: usize = 8;
const PAGES: u32 = 128;
const NO_PARENT: u32 = u32::MAX;
const INSTANCE: u64 = 0x40;
const CONTROL: u64 = 0x50;
const DOMAIN: u64 = 0x60;
const TRANSACTION: u64 = 0x70;
const FREE: u32 = 0;
const PREPARED: u32 = 1;
const ACTIVE: u32 = 2;
const TERMINAL: u32 = 3;
const QUERY: u32 = 1;
const STOP: u32 = 2;
const REAP: u32 = 4;
const FAULT_REASON: u32 = 1;
const STOP_REASON: u32 = 2;
const INVALID: i32 = -1;
const DENIED: i32 = -2;
const STALE: i32 = -3;
const AGAIN: i32 = -4;
const NO_SPACE: i32 = -7;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Template {
    identity: u32,
    pages: u32,
    max_descendant_depth: u32,
    child_template_mask: u32,
    bootstrap_recipe: u32,
    reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Root {
    slot: u32,
    template_mask: u32,
    slot_limit: u32,
    page_limit: u32,
    max_depth: u32,
    bootstrap_recipe: u32,
    reserved0: u32,
    reserved1: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Request {
    domain: u64,
    request_id: u64,
    template_id: u32,
    descendant_slots: u32,
    descendant_pages: u32,
    reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Transaction {
    transaction: u64,
    instance: u64,
    control: u64,
    endpoint: u64,
    domain: u64,
    parent_instance: u64,
    parent_endpoint: u64,
    request_id: u64,
    slot: u32,
    template_id: u32,
    depth: u32,
    pages: u32,
    descendant_slots: u32,
    descendant_pages: u32,
    template_mask: u32,
    bootstrap_recipe: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    instance: u64,
    control: u64,
    endpoint: u64,
    domain: u64,
    parent_instance: u64,
    parent_endpoint: u64,
    generation: u64,
    slot: u32,
    template_id: u32,
    depth: u32,
    phase: u32,
    faults: u32,
    restarts: u32,
    reason: u32,
    own_pages: u32,
    reserved_slots: u32,
    reserved_pages: u32,
    available_slots: u32,
    available_pages: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DomainStatus {
    domain: u64,
    holder: u64,
    instance: u64,
    slot_limit: u32,
    page_limit: u32,
    owned_slots: u32,
    owned_pages: u32,
    reserved_slots: u32,
    reserved_pages: u32,
    available_slots: u32,
    available_pages: u32,
    max_depth: u32,
    template_mask: u32,
    recipe: u32,
    revoked: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Record {
    instance: u64,
    control: u64,
    transaction: u64,
    parent_instance: u64,
    parent_endpoint: u64,
    generation: u64,
    request_id: u64,
    slot: u32,
    parent_slot: u32,
    parent_domain: u32,
    domain: u32,
    template_id: u32,
    depth: u32,
    pages: u32,
    phase: u32,
    rights: u32,
    reason: u32,
    recipe: u32,
    reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Domain {
    token: u64,
    instance: u64,
    holder: u64,
    last_request: u64,
    parent: u32,
    holder_slot: u32,
    template_mask: u32,
    max_depth: u32,
    recipe: u32,
    revoked: u32,
    slot_limit: u32,
    page_limit: u32,
    owned_slots: u32,
    owned_pages: u32,
    reserved_slots: u32,
    reserved_pages: u32,
}
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    history: [u64; SLOTS],
    records: [Record; OBJECTS],
    domains: [Domain; OBJECTS],
    templates: [Template; OBJECTS],
    roots: [Root; ROOTS],
    next_epoch: u64,
    root_mask: u32,
    root_pages: u32,
    template_mask: u32,
    configured: u32,
}

fn token(tag: u64, slot: usize, epoch: u64) -> u64 {
    (epoch << 8) | (tag + slot as u64 + 1)
}
fn token_slot(value: u64, tag: u64) -> Result<usize, i32> {
    let low = value & 255;
    let epoch = value >> 8;
    if low <= tag || low > tag + OBJECTS as u64 || epoch == 0 || epoch > GENERATION_MAX {
        return Err(INVALID);
    }
    Ok((low - tag - 1) as usize)
}
fn endpoint(states: &[State; SLOTS], value: u64) -> Option<usize> {
    let low = value & 255;
    let generation = value >> 8;
    if low == 0 || low > SLOTS as u64 || generation == 0 || generation > GENERATION_MAX {
        return None;
    }
    let slot = low as usize - 1;
    let state = states[slot];
    (state.valid() && state.phase == READY && state.generation == generation).then_some(slot)
}
fn dormant(history: u64) -> State {
    State { generation: history, deadline: 0, faults: 0, restarts: 0,
            phase: DORMANT, reserved: 0 }
}

impl Table {
    fn new(root_mask: u32, root_pages: u32) -> Self {
        Self { history: [0; SLOTS], records: [Record::default(); OBJECTS],
            domains: [Domain::default(); OBJECTS], templates: [Template::default(); OBJECTS],
            roots: [Root::default(); ROOTS], next_epoch: 1, root_mask, root_pages,
            template_mask: 0, configured: 0 }
    }
    fn basic(&self) -> bool {
        self.root_mask & !15 == 0 && self.root_pages <= 80
            && self.next_epoch != 0 && self.next_epoch <= GENERATION_MAX + 1
            && self.configured <= 1
    }
    fn epochs(&mut self, count: u64) -> Result<u64, i32> {
        if count == 0 || self.next_epoch > GENERATION_MAX
            || count - 1 > GENERATION_MAX - self.next_epoch {
            return Err(NO_SPACE);
        }
        let first = self.next_epoch;
        self.next_epoch += count;
        Ok(first)
    }
    fn record_slot(&self, slot: usize) -> Option<usize> {
        self.records.iter().position(|r| r.phase != FREE && r.slot as usize == slot)
    }
    fn instance(&self, slot: usize) -> u64 {
        if slot < ROOTS { 0 } else { self.record_slot(slot).map_or(0, |n| self.records[n].instance) }
    }
    fn control(&self, states: &[State; SLOTS], caller: u64, handle: u64, right: u32) -> Result<usize, i32> {
        let owner = endpoint(states, caller).ok_or(AGAIN)?;
        let n = token_slot(handle, CONTROL)?;
        let r = self.records[n];
        if r.phase == FREE || r.phase == PREPARED || r.control != handle { return Err(STALE); }
        if r.parent_endpoint != caller || r.parent_slot as usize != owner
            || r.parent_instance != self.instance(owner) || right & !r.rights != 0 { return Err(DENIED); }
        Ok(n)
    }
    fn active_domain(&self, states: &[State; SLOTS], caller: u64, handle: u64) -> Result<usize, i32> {
        endpoint(states, caller).ok_or(AGAIN)?;
        let n = token_slot(handle, DOMAIN)?;
        let first = self.domains[n];
        if first.token != handle || first.holder == 0 { return Err(STALE); }
        if first.holder != caller || first.instance != self.instance(first.holder_slot as usize) { return Err(DENIED); }
        let mut current = n;
        for _ in 0..=2 {
            let d = self.domains[current];
            if d.holder == 0 || d.revoked != 0 || endpoint(states, d.holder).is_none()
                || d.instance != self.instance(d.holder_slot as usize) { return Err(DENIED); }
            if d.parent == NO_PARENT { return Ok(n); }
            if d.parent as usize >= OBJECTS { return Err(INVALID); }
            current = d.parent as usize;
        }
        Err(DENIED)
    }
    fn configure(&mut self, states: &[State; SLOTS], templates: &[Template], roots: &[Root]) -> i32 {
        if !self.basic() || self.configured != 0 || templates.len() > OBJECTS || roots.len() > ROOTS
            || self.root_pages > PAGES { return INVALID; }
        let mut mask = 0;
        for t in templates {
            if t.identity == 0 || t.identity > OBJECTS as u32 || t.pages == 0 || t.pages > 20
                || t.max_descendant_depth > 1 || t.child_template_mask & !255 != 0
                || !matches!(t.bootstrap_recipe, 1 | 2) || t.reserved != 0
                || (t.bootstrap_recipe == 2 && !((t.identity == 5 && t.max_descendant_depth == 1 && t.child_template_mask == 32)
                    || (t.identity == 6 && t.max_descendant_depth == 0 && t.child_template_mask == 0)))
                || ((t.max_descendant_depth == 0) != (t.child_template_mask == 0))
                || mask & (1 << (t.identity - 1)) != 0 { return INVALID; }
            mask |= 1 << (t.identity - 1);
        }
        if templates.iter().any(|t| t.child_template_mask & !mask != 0) { return INVALID; }
        let mut owners = 0;
        let mut total_slots: u32 = 0;
        let mut total_pages: u32 = 0;
        for r in roots {
            if r.slot >= ROOTS as u32 || self.root_mask & (1 << r.slot) == 0
                || owners & (1 << r.slot) != 0 || r.template_mask == 0 || r.template_mask & !mask != 0
                || r.slot_limit > 4 || r.page_limit > (PAGES - self.root_pages).min(48) || r.max_depth == 0
                || r.max_depth > 2 || !matches!(r.bootstrap_recipe, 1 | 2) || r.reserved0 != 0 || r.reserved1 != 0
                || (r.bootstrap_recipe == 2 && (r.slot != 3 || r.template_mask != 48))
                || templates.iter().any(|t| r.template_mask & (1 << (t.identity - 1)) != 0 && t.bootstrap_recipe != r.bootstrap_recipe)
                || endpoint(states, states[r.slot as usize].handle(r.slot)).is_none() { return INVALID; }
            owners |= 1 << r.slot;
            total_slots += r.slot_limit;
            total_pages += r.page_limit;
        }
        if total_slots > 4 || total_pages > (PAGES - self.root_pages).min(48) { return NO_SPACE; }
        if !roots.is_empty() && (self.next_epoch > GENERATION_MAX
            || roots.len() as u64 - 1 > GENERATION_MAX - self.next_epoch) { return NO_SPACE; }
        for t in templates { self.templates[t.identity as usize - 1] = *t; }
        self.template_mask = mask;
        for slot in 0..ROOTS {
            if self.root_mask & (1 << slot) != 0 { self.history[slot] = states[slot].generation; }
        }
        for r in roots {
            self.roots[r.slot as usize] = *r;
            let epoch = self.epochs(1).unwrap();
            self.domains[r.slot as usize] = Domain {
                token: token(DOMAIN, r.slot as usize, epoch), holder: states[r.slot as usize].handle(r.slot),
                parent: NO_PARENT, holder_slot: r.slot, template_mask: r.template_mask, max_depth: r.max_depth,
                recipe: r.bootstrap_recipe, slot_limit: r.slot_limit, page_limit: r.page_limit,
                ..Domain::default()
            };
        }
        self.configured = 1;
        0
    }
    fn bind_root(&mut self, states: &[State; SLOTS], slot: usize) -> i32 {
        if !self.basic() || self.configured != 1 || slot >= ROOTS || self.root_mask & (1 << slot) == 0
            || states[slot].phase != READY || !states[slot].valid() { return INVALID; }
        let r = self.roots[slot];
        if r.template_mask == 0 { self.history[slot] = states[slot].generation; return 0; }
        let old = self.domains[slot];
        let holder = states[slot].handle(slot as u32);
        if old.holder == holder && old.token != 0 { return 0; }
        if states[slot].generation < self.history[slot] || old.owned_slots != 0 || old.owned_pages != 0
            || old.reserved_slots != 0 || old.reserved_pages != 0 { return DENIED; }
        let epoch = match self.epochs(1) { Ok(e) => e, Err(e) => return e };
        self.history[slot] = states[slot].generation;
        self.domains[slot] = Domain { token: token(DOMAIN, slot, epoch), holder,
            parent: NO_PARENT, holder_slot: slot as u32, template_mask: r.template_mask,
            max_depth: r.max_depth, recipe: r.bootstrap_recipe, slot_limit: r.slot_limit,
            page_limit: r.page_limit, ..Domain::default() };
        0
    }
    fn tx(&self, n: usize) -> Transaction {
        let r = self.records[n];
        let d = if r.domain == NO_PARENT { Domain::default() } else { self.domains[r.domain as usize] };
        Transaction { transaction: r.transaction, instance: r.instance, control: r.control,
            endpoint: (r.generation << 8) | (r.slot as u64 + 1), domain: d.token,
            parent_instance: r.parent_instance, parent_endpoint: r.parent_endpoint, request_id: r.request_id,
            slot: r.slot, template_id: r.template_id, depth: r.depth, pages: r.pages,
            descendant_slots: d.slot_limit, descendant_pages: d.page_limit,
            template_mask: d.template_mask, bootstrap_recipe: r.recipe }
    }
    fn prepare(&mut self, states: &[State; SLOTS], caller: u64, request: Request) -> Result<Transaction, i32> {
        if !self.basic() || self.configured != 1 || request.reserved != 0 || request.request_id == 0
            || request.template_id == 0 || request.template_id > OBJECTS as u32
            || request.descendant_slots > 4 || request.descendant_pages > PAGES { return Err(INVALID); }
        let parent = endpoint(states, caller).ok_or(AGAIN)?;
        let p = self.active_domain(states, caller, request.domain)?;
        let pd = self.domains[p];
        if request.request_id <= pd.last_request { return Err(STALE); }
        let t = self.templates[request.template_id as usize - 1];
        if t.identity == 0 || t.bootstrap_recipe != pd.recipe || pd.template_mask & (1 << (request.template_id - 1)) == 0 { return Err(DENIED); }
        let depth = if parent < ROOTS { 1 } else {
            let n = self.record_slot(parent).ok_or(DENIED)?;
            if self.records[n].phase != ACTIVE || self.records[n].generation != caller >> 8 { return Err(DENIED); }
            self.records[n].depth + 1
        };
        if depth > 2 || depth > pd.max_depth { return Err(DENIED); }
        let delegated = request.descendant_slots != 0 || request.descendant_pages != 0;
        if delegated && (t.max_descendant_depth == 0 || t.child_template_mask & pd.template_mask == 0
            || depth == pd.max_depth) { return Err(DENIED); }
        let slots = 1u32.checked_add(request.descendant_slots).ok_or(INVALID)?;
        let pages = t.pages.checked_add(request.descendant_pages).ok_or(INVALID)?;
        if pd.owned_slots.checked_add(pd.reserved_slots).and_then(|v| v.checked_add(slots)).ok_or(INVALID)? > pd.slot_limit
            || pd.owned_pages.checked_add(pd.reserved_pages).and_then(|v| v.checked_add(pages)).ok_or(INVALID)? > pd.page_limit {
            return Err(NO_SPACE);
        }
        let n = self.records.iter().position(|r| r.phase == FREE).ok_or(NO_SPACE)?;
        let slot = (ROOTS..SLOTS).find(|slot| self.record_slot(*slot).is_none()
            && states[*slot].phase == DORMANT && self.history[*slot] < GENERATION_MAX).ok_or(NO_SPACE)?;
        // A supervisor may receive a zero-credit domain. It still has typed,
        // attenuated authority, which makes depth/credit exhaustion explicit.
        let dn = if t.max_descendant_depth != 0 { Some((0..OBJECTS).find(|d| self.domains[*d].holder == 0).ok_or(NO_SPACE)?) } else { None };
        let count = if dn.is_some() { 4 } else { 3 };
        let epoch = self.epochs(count)?;
        let generation = self.history[slot] + 1;
        self.records[n] = Record {
            instance: token(INSTANCE, n, epoch), control: token(CONTROL, n, epoch + 1),
            transaction: token(TRANSACTION, n, epoch + 2), parent_instance: self.instance(parent),
            parent_endpoint: caller, generation, request_id: request.request_id,
            slot: slot as u32, parent_slot: parent as u32, parent_domain: p as u32,
            domain: dn.map_or(NO_PARENT, |d| d as u32), template_id: request.template_id,
            depth, pages: t.pages, phase: PREPARED, rights: QUERY | STOP | REAP, recipe: pd.recipe & t.bootstrap_recipe,
            ..Record::default()
        };
        if let Some(d) = dn {
            self.domains[d] = Domain { token: token(DOMAIN, d, epoch + 3),
                instance: self.records[n].instance, holder: (generation << 8) | (slot as u64 + 1),
                parent: p as u32, holder_slot: slot as u32,
                template_mask: pd.template_mask & t.child_template_mask,
                max_depth: pd.max_depth.min(depth + t.max_descendant_depth), recipe: pd.recipe & t.bootstrap_recipe,
                slot_limit: request.descendant_slots, page_limit: request.descendant_pages,
                ..Domain::default() };
        }
        self.domains[p].owned_slots += 1;
        self.domains[p].owned_pages += t.pages;
        self.domains[p].reserved_slots += request.descendant_slots;
        self.domains[p].reserved_pages += request.descendant_pages;
        self.domains[p].last_request = request.request_id;
        Ok(self.tx(n))
    }
    fn transaction(&self, handle: u64) -> Result<usize, i32> {
        let n = token_slot(handle, TRANSACTION)?;
        if self.records[n].phase != PREPARED || self.records[n].transaction != handle { return Err(STALE); }
        Ok(n)
    }
    fn refund(&mut self, n: usize, retain: bool) {
        let r = self.records[n];
        let p = r.parent_domain as usize;
        if !retain { self.domains[p].owned_slots -= 1; }
        if r.pages == 0 { return; }
        self.domains[p].owned_pages -= r.pages;
        if r.domain != NO_PARENT {
            let d = r.domain as usize;
            self.domains[p].reserved_slots -= self.domains[d].slot_limit;
            self.domains[p].reserved_pages -= self.domains[d].page_limit;
            self.domains[d] = Domain::default();
            self.records[n].domain = NO_PARENT;
        }
        self.records[n].pages = 0;
    }
    fn abort(&mut self, handle: u64) -> i32 {
        if !self.basic() { return INVALID; }
        let n = match self.transaction(handle) { Ok(n) => n, Err(e) => return e };
        self.refund(n, false);
        self.records[n] = Record::default();
        0
    }
    fn commit(&mut self, states: &mut [State; SLOTS], caller: u64, handle: u64) -> i32 {
        if !self.basic() { return INVALID; }
        let n = match self.transaction(handle) { Ok(n) => n, Err(e) => return e };
        let r = self.records[n];
        if r.parent_endpoint != caller || self.active_domain(states, caller,
            self.domains[r.parent_domain as usize].token).is_err()
            || r.parent_instance != self.instance(r.parent_slot as usize)
            || states[r.slot as usize].phase != DORMANT || self.history[r.slot as usize].checked_add(1) != Some(r.generation) {
            return DENIED;
        }
        self.history[r.slot as usize] = r.generation;
        states[r.slot as usize] = State { generation: r.generation, ..State::initial() };
        self.records[n].phase = ACTIVE;
        self.records[n].transaction = 0;
        0
    }
    fn descendants(&self, slot: usize) -> u32 {
        if slot >= SLOTS { return 0; }
        let mut mask = 1u32 << slot;
        for _ in 0..2 {
            for r in &self.records {
                if r.phase != FREE && r.slot < SLOTS as u32 && r.parent_slot < SLOTS as u32
                    && mask & (1 << r.parent_slot) != 0 { mask |= 1 << r.slot; }
            }
        }
        mask & !(1 << slot)
    }
    fn discard_descendants(&mut self, states: &mut [State; SLOTS], slot: usize) -> u32 {
        let mask = self.descendants(slot);
        // Mark every affected execution nonrunnable before retiring any owner.
        for child in ROOTS..SLOTS {
            if mask & (1 << child) != 0 { states[child].stop(); }
        }
        // A dead generation cannot reap its children; remove them bottom-up.
        for depth in (1..=2).rev() {
            for n in 0..OBJECTS {
                let r = self.records[n];
                if r.phase != FREE && r.depth == depth && mask & (1 << r.slot) != 0 {
                    self.refund(n, false);
                    self.records[n] = Record::default();
                    states[r.slot as usize] = dormant(self.history[r.slot as usize]);
                }
            }
        }
        mask
    }
    fn stop(&mut self, states: &mut [State; SLOTS], caller: u64, handle: u64) -> Result<u32, i32> {
        if !self.basic() { return Err(INVALID); }
        let n = self.control(states, caller, handle, STOP)?;
        if self.records[n].phase == TERMINAL { return Ok(0); }
        let slot = self.records[n].slot as usize;
        states[slot].stop();
        let mask = self.discard_descendants(states, slot) | (1 << slot);
        self.refund(n, true);
        self.records[n].phase = TERMINAL;
        self.records[n].reason = STOP_REASON;
        Ok(mask)
    }
    fn reap(&mut self, states: &mut [State; SLOTS], caller: u64, handle: u64) -> i32 {
        if !self.basic() { return INVALID; }
        let n = match self.control(states, caller, handle, REAP) { Ok(n) => n, Err(e) => return e };
        let r = self.records[n];
        if r.phase != TERMINAL { return DENIED; }
        self.refund(n, false);
        states[r.slot as usize] = dormant(self.history[r.slot as usize]);
        self.records[n] = Record::default();
        0
    }
    fn fault(&mut self, states: &mut [State; SLOTS], slot: usize, now: u64) -> Result<u32, i32> {
        if !self.basic() || slot >= SLOTS || states[slot].phase != READY || !states[slot].valid() { return Err(INVALID); }
        let n = if slot >= ROOTS { Some(self.record_slot(slot).ok_or(INVALID)?) } else { None };
        if n.is_none() && self.root_mask & (1 << slot) == 0 { return Err(INVALID); }
        if let Some(n) = n { if self.records[n].phase != ACTIVE { return Err(INVALID); } }
        states[slot].fault(now);
        let mask = self.discard_descendants(states, slot) | (1 << slot);
        if let Some(n) = n {
            self.records[n].reason = FAULT_REASON;
            if self.records[n].domain != NO_PARENT { self.domains[self.records[n].domain as usize].token = 0; }
            if states[slot].phase == QUARANTINED {
                self.refund(n, true);
                self.records[n].phase = TERMINAL;
            }
        } else if self.roots[slot].template_mask != 0 {
            self.domains[slot].token = 0;
        }
        Ok(mask)
    }
    fn exit(&mut self, states: &mut [State; SLOTS], slot: usize) -> Result<u32, i32> {
        if !self.basic() || slot >= SLOTS || states[slot].phase != READY || !states[slot].valid() { return Err(INVALID); }
        let n = if slot >= ROOTS { Some(self.record_slot(slot).ok_or(INVALID)?) } else { None };
        if n.is_none() && self.root_mask & (1 << slot) == 0 { return Err(INVALID); }
        if let Some(n) = n { if self.records[n].phase != ACTIVE { return Err(INVALID); } }
        states[slot].stop();
        let mask = self.discard_descendants(states, slot) | (1 << slot);
        if let Some(n) = n {
            self.refund(n, true);
            self.records[n].phase = TERMINAL;
            self.records[n].reason = STOP_REASON;
        } else if self.roots[slot].template_mask != 0 {
            self.domains[slot].token = 0;
        }
        Ok(mask)
    }
    fn poll(&mut self, states: &mut [State; SLOTS], slot: usize, now: u64) -> i32 {
        if !self.basic() || slot >= SLOTS { return INVALID; }
        if slot < ROOTS {
            if self.root_mask & (1 << slot) == 0 { return INVALID; }
            if !states[slot].poll(now) { return 0; }
            self.history[slot] = states[slot].generation;
            let result = self.bind_root(states, slot);
            // Exhausting creation epochs closes the factory, not the root's
            // independent execution lifecycle. The retired token stays zero;
            // C must still cold-initialize and publish this due incarnation.
            return if result == 0 || result == NO_SPACE { 1 } else { result };
        }
        let n = match self.record_slot(slot) { Some(n) => n, None => return INVALID };
        let r = self.records[n];
        if r.phase != ACTIVE || states[slot].phase != BACKOFF { return 0; }
        if endpoint(states, r.parent_endpoint).is_none() || r.parent_instance != self.instance(r.parent_slot as usize) {
            states[slot].stop();
            self.discard_descendants(states, slot);
            self.refund(n, false);
            self.records[n] = Record::default();
            states[slot] = dormant(self.history[slot]);
            return STALE;
        }
        if !states[slot].poll(now) { return 0; }
        if states[slot].generation <= self.history[slot] { return INVALID; }
        self.history[slot] = states[slot].generation;
        self.records[n].generation = states[slot].generation;
        if r.domain != NO_PARENT { self.domains[r.domain as usize].holder = states[slot].handle(slot as u32); }
        1
    }
    fn query(&self, states: &[State; SLOTS], caller: u64, handle: u64) -> Result<Status, i32> {
        if !self.basic() { return Err(INVALID); }
        let n = self.control(states, caller, handle, QUERY)?;
        let r = self.records[n];
        let s = states[r.slot as usize];
        let d = if r.domain == NO_PARENT { Domain::default() } else { self.domains[r.domain as usize] };
        Ok(Status { instance: r.instance, control: r.control, endpoint: s.handle(r.slot), domain: d.token,
            parent_instance: r.parent_instance, parent_endpoint: r.parent_endpoint,
            generation: r.generation, slot: r.slot, template_id: r.template_id, depth: r.depth,
            phase: s.phase, faults: s.faults, restarts: s.restarts, reason: r.reason, own_pages: r.pages,
            reserved_slots: d.slot_limit, reserved_pages: d.page_limit,
            available_slots: d.slot_limit - d.owned_slots - d.reserved_slots,
            available_pages: d.page_limit - d.owned_pages - d.reserved_pages })
    }
    fn rebind(&mut self, states: &[State; SLOTS], caller: u64, handle: u64, creation: u64, request_id: u64) -> Result<Transaction, i32> {
        if !self.basic() || request_id == 0 { return Err(INVALID); }
        let n = self.control(states, caller, handle, QUERY)?;
        let p = self.active_domain(states, caller, creation)?;
        if request_id <= self.domains[p].last_request { return Err(STALE); }
        let r = self.records[n];
        if r.phase != ACTIVE || r.parent_domain as usize != p || !matches!(r.recipe, 1 | 2)
            || self.domains[p].recipe != r.recipe || self.domains[p].template_mask & (1 << (r.template_id - 1)) == 0
            || endpoint(states, states[r.slot as usize].handle(r.slot)).is_none() { return Err(DENIED); }
        if r.domain != NO_PARENT {
            let d = r.domain as usize;
            if self.domains[d].revoked != 0 { return Err(DENIED); }
            let epoch = self.epochs(1)?;
            // A retired execution's token was cleared by fault. The fresh
            // endpoint owns a new request namespace; a same-generation rebind
            // keeps its existing high-water mark and cannot replay requests.
            if self.domains[d].token == 0 { self.domains[d].last_request = 0; }
            self.domains[d].token = token(DOMAIN, d, epoch);
            self.domains[d].holder = states[r.slot as usize].handle(r.slot);
        }
        self.domains[p].last_request = request_id;
        Ok(Transaction { request_id, ..self.tx(n) })
    }
    fn revoke(&mut self, states: &[State; SLOTS], caller: u64, handle: u64) -> i32 {
        let holder = match endpoint(states, caller) { Some(s) => s, None => return AGAIN };
        let n = match token_slot(handle, DOMAIN) { Ok(n) => n, Err(e) => return e };
        let d = self.domains[n];
        if d.holder == 0 || d.token != handle { return STALE; }
        if d.holder != caller && (d.parent == NO_PARENT || self.domains[d.parent as usize].holder != caller)
            || self.instance(holder) != if d.holder == caller { d.instance } else { self.domains[d.parent as usize].instance } {
            return DENIED;
        }
        let mut mask = 1 << n;
        for _ in 0..2 {
            for i in 0..OBJECTS {
                let sub = self.domains[i];
                if sub.holder != 0 && sub.parent != NO_PARENT && mask & (1 << sub.parent) != 0 { mask |= 1 << i; }
            }
        }
        for i in 0..OBJECTS { if mask & (1 << i) != 0 { self.domains[i].revoked = 1; } }
        0
    }
    fn domain_query(&self, states: &[State; SLOTS], caller: u64, handle: u64) -> Result<DomainStatus, i32> {
        let owner = endpoint(states, caller).ok_or(AGAIN)?;
        let n = token_slot(handle, DOMAIN)?;
        let d = self.domains[n];
        if d.holder == 0 || d.token != handle { return Err(STALE); }
        if d.holder != caller || d.holder_slot as usize != owner || d.instance != self.instance(owner) {
            return Err(DENIED);
        }
        Ok(DomainStatus { domain: handle, holder: d.holder, instance: d.instance,
            slot_limit: d.slot_limit, page_limit: d.page_limit, owned_slots: d.owned_slots,
            owned_pages: d.owned_pages, reserved_slots: d.reserved_slots, reserved_pages: d.reserved_pages,
            available_slots: d.slot_limit - d.owned_slots - d.reserved_slots,
            available_pages: d.page_limit - d.owned_pages - d.reserved_pages,
            max_depth: d.max_depth, template_mask: d.template_mask, recipe: d.recipe, revoked: d.revoked })
    }
    fn check(&self, states: &[State; SLOTS]) -> bool {
        if !self.basic() || self.configured != 1 { return false; }
        let mut slots = 0u32;
        let mut owned_slots = [0u32; OBJECTS];
        let mut owned_pages = [0u32; OBJECTS];
        let mut reserved_slots = [0u32; OBJECTS];
        let mut reserved_pages = [0u32; OBJECTS];
        let mut epochs = [0u64; OBJECTS * 4];
        let mut epoch_count = 0;
        for (n, r) in self.records.iter().enumerate() {
            if r.phase == FREE { if *r != Record::default() { return false; } continue; }
            if r.slot < ROOTS as u32 || r.slot >= SLOTS as u32 || r.parent_slot >= SLOTS as u32
                || r.parent_domain >= OBJECTS as u32 || r.depth == 0 || r.depth > 2 || r.reserved != 0
                || r.template_id == 0 || r.template_id > OBJECTS as u32
                || slots & (1 << r.slot) != 0 || token_slot(r.instance, INSTANCE) != Ok(n)
                || token_slot(r.control, CONTROL) != Ok(n) || r.instance >> 8 >= r.control >> 8
                || r.parent_instance != self.instance(r.parent_slot as usize)
                || r.parent_endpoint & 255 != r.parent_slot as u64 + 1 || r.generation == 0
                || r.generation > GENERATION_MAX || r.phase > TERMINAL || r.rights & !(QUERY | STOP | REAP) != 0
                || r.rights & QUERY == 0 || !matches!(r.recipe, 1 | 2)
                || r.recipe != self.templates[r.template_id as usize - 1].bootstrap_recipe { return false; }
            for handle in [r.instance, r.control, r.transaction] {
                if handle == 0 { continue; }
                let epoch = handle >> 8;
                if epoch >= self.next_epoch || epochs[..epoch_count].contains(&epoch) { return false; }
                epochs[epoch_count] = epoch; epoch_count += 1;
            }
            slots |= 1 << r.slot;
            let parent_depth = if r.parent_slot < ROOTS as u32 { 0 } else {
                match self.record_slot(r.parent_slot as usize) { Some(p) => self.records[p].depth, None => return false }
            };
            if parent_depth.checked_add(1) != Some(r.depth) { return false; }
            let p = r.parent_domain as usize;
            if self.domains[p].holder != r.parent_endpoint || self.domains[p].instance != r.parent_instance { return false; }
            if r.phase == PREPARED {
                if token_slot(r.transaction, TRANSACTION) != Ok(n) || states[r.slot as usize].phase != DORMANT
                    || self.history[r.slot as usize].checked_add(1) != Some(r.generation) { return false; }
            } else if r.generation != self.history[r.slot as usize] || r.transaction != 0 { return false; }
            if r.phase == TERMINAL {
                if r.pages != 0 || r.domain != NO_PARENT || ![STOPPED, QUARANTINED].contains(&states[r.slot as usize].phase) { return false; }
            } else {
                if r.pages != self.templates[r.template_id as usize - 1].pages { return false; }
                owned_pages[p] += r.pages;
                if r.phase == ACTIVE && (states[r.slot as usize].generation != r.generation
                    || ![READY, BACKOFF].contains(&states[r.slot as usize].phase)) { return false; }
            }
            owned_slots[p] += 1;
            if r.domain != NO_PARENT {
                if r.domain >= OBJECTS as u32 { return false; }
                let d = self.domains[r.domain as usize];
                if d.parent != r.parent_domain || d.instance != r.instance || d.holder_slot != r.slot
                    || d.holder & 255 != r.slot as u64 + 1 || d.holder >> 8 != r.generation { return false; }
                reserved_slots[p] += d.slot_limit;
                reserved_pages[p] += d.page_limit;
            }
        }
        let mut root_slots = 0u32;
        let mut root_pages = 0u32;
        let mut dynamic_pages = 0u32;
        for (n, d) in self.domains.iter().enumerate() {
            if d.holder == 0 { if *d != Domain::default() { return false; } continue; }
            if d.token != 0 {
                let epoch = d.token >> 8;
                if epoch >= self.next_epoch || epochs[..epoch_count].contains(&epoch) { return false; }
                epochs[epoch_count] = epoch; epoch_count += 1;
            }
            if d.holder_slot >= SLOTS as u32 || d.revoked > 1 || d.max_depth > 2 || !matches!(d.recipe, 1 | 2)
                || d.template_mask & !self.template_mask != 0 || d.slot_limit > 4 || d.page_limit > PAGES
                || d.owned_slots != owned_slots[n] || d.owned_pages != owned_pages[n]
                || d.reserved_slots != reserved_slots[n] || d.reserved_pages != reserved_pages[n]
                || d.owned_slots + d.reserved_slots > d.slot_limit || d.owned_pages + d.reserved_pages > d.page_limit
                || (d.token != 0 && token_slot(d.token, DOMAIN) != Ok(n)) { return false; }
            dynamic_pages += d.owned_pages;
            if d.parent == NO_PARENT {
                if d.holder_slot >= ROOTS as u32 || n != d.holder_slot as usize || d.instance != 0 { return false; }
                let root = self.roots[n];
                if root.template_mask == 0 || d.recipe != root.bootstrap_recipe || d.template_mask & !root.template_mask != 0 || d.max_depth > root.max_depth
                    || d.slot_limit > root.slot_limit || d.page_limit > root.page_limit { return false; }
                root_slots += d.slot_limit;
                root_pages += d.page_limit;
            } else {
                if d.parent >= OBJECTS as u32 || self.domains[d.parent as usize].holder == 0
                    || d.recipe != self.domains[d.parent as usize].recipe
                    || d.template_mask & !self.domains[d.parent as usize].template_mask != 0
                    || d.max_depth > self.domains[d.parent as usize].max_depth { return false; }
                let owner = match self.records.iter().find(|r| r.phase != FREE && r.domain as usize == n
                    && r.instance == d.instance && r.slot == d.holder_slot) { Some(r) => r, None => return false };
                let template = self.templates[owner.template_id as usize - 1];
                if template.max_descendant_depth == 0 || d.template_mask & !template.child_template_mask != 0
                    || d.max_depth > owner.depth + template.max_descendant_depth { return false; }
            }
        }
        if root_slots > 4 || root_pages > (PAGES - self.root_pages).min(48) || dynamic_pages > root_pages { return false; }
        for slot in 0..SLOTS {
            if self.history[slot] > GENERATION_MAX || !states[slot].valid() { return false; }
            if slot < ROOTS {
                if self.root_mask & (1 << slot) != 0 && states[slot].generation != self.history[slot] { return false; }
            } else if self.record_slot(slot).is_none() && (states[slot].phase != DORMANT || states[slot].generation != self.history[slot]) { return false; }
        }
        true
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_host_init(table: *mut Table, root_mask: u32, root_pages: u32) {
    if !table.is_null() { ptr::write(table, Table::new(root_mask, root_pages)); }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_configure(table: *mut Table, states: *const [State; SLOTS],
    templates: *const Template, template_count: u32, roots: *const Root, root_count: u32) -> i32 {
    if template_count as usize > OBJECTS || root_count as usize > ROOTS
        || (template_count != 0 && templates.is_null()) || (root_count != 0 && roots.is_null()) { return INVALID; }
    let ts = if template_count == 0 { &[] } else { core::slice::from_raw_parts(templates, template_count as usize) };
    let rs = if root_count == 0 { &[] } else { core::slice::from_raw_parts(roots, root_count as usize) };
    match (table.as_mut(), states.as_ref()) { (Some(t), Some(s)) => t.configure(s, ts, rs), _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_root_domain(table: *const Table, states: *const [State; SLOTS], caller: u64) -> i64 {
    let (t, s) = match (table.as_ref(), states.as_ref()) { (Some(t), Some(s)) => (t, s), _ => return INVALID as i64 };
    let slot = match endpoint(s, caller) { Some(n) if n < ROOTS => n, _ => return DENIED as i64 };
    let handle = t.domains[slot].token;
    t.active_domain(s, caller, handle).map_or_else(|e| e as i64, |_| handle as i64)
}
#[no_mangle]
pub unsafe extern "C" fn z_host_bind_root(table: *mut Table, states: *const [State; SLOTS], slot: u32) -> i32 {
    match (table.as_mut(), states.as_ref()) { (Some(t), Some(s)) => t.bind_root(s, slot as usize), _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_prepare(table: *mut Table, states: *const [State; SLOTS], caller: u64,
    request: *const Request, result: *mut Transaction) -> i32 {
    match (table.as_mut(), states.as_ref(), request.as_ref(), result.as_mut()) {
        (Some(t), Some(s), Some(r), Some(out)) => match t.prepare(s, caller, *r) { Ok(value) => { *out = value; 0 }, Err(e) => e },
        _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_abort(table: *mut Table, transaction: u64) -> i32 {
    table.as_mut().map_or(INVALID, |t| t.abort(transaction))
}
#[no_mangle]
pub unsafe extern "C" fn z_host_commit(table: *mut Table, states: *mut [State; SLOTS], caller: u64, transaction: u64) -> i32 {
    match (table.as_mut(), states.as_mut()) { (Some(t), Some(s)) => t.commit(s, caller, transaction), _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_query(table: *const Table, states: *const [State; SLOTS], caller: u64,
    control: u64, result: *mut Status) -> i32 {
    match (table.as_ref(), states.as_ref(), result.as_mut()) {
        (Some(t), Some(s), Some(out)) => match t.query(s, caller, control) { Ok(v) => { *out = v; 0 }, Err(e) => e }, _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_stop(table: *mut Table, states: *mut [State; SLOTS], caller: u64,
    control: u64, cleanup_mask: *mut u32) -> i32 {
    match (table.as_mut(), states.as_mut(), cleanup_mask.as_mut()) {
        (Some(t), Some(s), Some(out)) => match t.stop(s, caller, control) { Ok(v) => { *out = v; 0 }, Err(e) => e }, _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_reap(table: *mut Table, states: *mut [State; SLOTS], caller: u64, control: u64) -> i32 {
    match (table.as_mut(), states.as_mut()) { (Some(t), Some(s)) => t.reap(s, caller, control), _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_fault(table: *mut Table, states: *mut [State; SLOTS], slot: u32,
    now: u64, cleanup_mask: *mut u32) -> i32 {
    match (table.as_mut(), states.as_mut(), cleanup_mask.as_mut()) {
        (Some(t), Some(s), Some(out)) => match t.fault(s, slot as usize, now) { Ok(v) => { *out = v; 0 }, Err(e) => e }, _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_exit(table: *mut Table, states: *mut [State; SLOTS], slot: u32, cleanup_mask: *mut u32) -> i32 {
    match (table.as_mut(), states.as_mut(), cleanup_mask.as_mut()) {
        (Some(t), Some(s), Some(out)) => match t.exit(s, slot as usize) { Ok(v) => { *out = v; 0 }, Err(e) => e }, _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_poll(table: *mut Table, states: *mut [State; SLOTS], slot: u32, now: u64) -> i32 {
    match (table.as_mut(), states.as_mut()) { (Some(t), Some(s)) => t.poll(s, slot as usize, now), _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_rebind(table: *mut Table, states: *const [State; SLOTS], caller: u64,
    control: u64, creation_domain: u64, request_id: u64, result: *mut Transaction) -> i32 {
    match (table.as_mut(), states.as_ref(), result.as_mut()) {
        (Some(t), Some(s), Some(out)) => match t.rebind(s, caller, control, creation_domain, request_id) { Ok(v) => { *out = v; 0 }, Err(e) => e }, _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_revoke(table: *mut Table, states: *const [State; SLOTS], caller: u64, domain: u64) -> i32 {
    match (table.as_mut(), states.as_ref()) { (Some(t), Some(s)) => t.revoke(s, caller, domain), _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_domain_query(table: *const Table, states: *const [State; SLOTS], caller: u64,
    domain: u64, result: *mut DomainStatus) -> i32 {
    match (table.as_ref(), states.as_ref(), result.as_mut()) {
        (Some(t), Some(s), Some(out)) => match t.domain_query(s, caller, domain) { Ok(v) => { *out = v; 0 }, Err(e) => e }, _ => INVALID }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_descendants(table: *const Table, slot: u32) -> u32 {
    table.as_ref().map_or(0, |t| t.descendants(slot as usize))
}
#[no_mangle]
pub unsafe extern "C" fn z_host_slot(table: *const Table, instance: u64) -> i32 {
    let t = match table.as_ref() { Some(t) => t, None => return INVALID };
    let n = match token_slot(instance, INSTANCE) { Ok(n) => n, Err(e) => return e };
    let r = t.records[n];
    if r.phase == FREE || r.phase == PREPARED || r.instance != instance { STALE } else { r.slot as i32 }
}
#[no_mangle]
pub unsafe extern "C" fn z_host_check(table: *const Table, states: *const [State; SLOTS]) -> i32 {
    match (table.as_ref(), states.as_ref()) { (Some(t), Some(s)) => i32::from(t.check(s)), _ => 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    fn templates() -> [Template; 2] {
        [Template { identity: 1, pages: 4, max_descendant_depth: 1,
            child_template_mask: 2, bootstrap_recipe: 1, reserved: 0 },
         Template { identity: 2, pages: 2, max_descendant_depth: 0,
            child_template_mask: 0, bootstrap_recipe: 1, reserved: 0 }]
    }
    fn fixture_with_depth(depth: u32) -> (Table, [State; SLOTS], u64) {
        let mut states = [State::initial(); SLOTS];
        for s in &mut states[ROOTS..] { *s = dormant(0); }
        let mut table = Table::new(15, 80);
        let roots = [Root { slot: 3, template_mask: 3, slot_limit: 4, page_limit: 48,
            max_depth: depth, bootstrap_recipe: 1, ..Root::default() }];
        assert_eq!(table.configure(&states, &templates(), &roots), 0);
        let domain = table.domains[3].token;
        assert!(table.check(&states));
        (table, states, domain)
    }
    fn fixture() -> (Table, [State; SLOTS], u64) { fixture_with_depth(2) }
    fn request(table: &Table, domain: u64, template_id: u32, slots: u32, pages: u32) -> Request {
        let d = token_slot(domain, DOMAIN).unwrap();
        Request { domain, request_id: table.domains[d].last_request + 1, template_id,
            descendant_slots: slots, descendant_pages: pages, reserved: 0 }
    }
    fn spawn(table: &mut Table, states: &mut [State; SLOTS], owner: u64,
        domain: u64, template: u32, slots: u32, pages: u32) -> Transaction {
        let req = request(table, domain, template, slots, pages);
        let tx = table.prepare(states, owner, req).unwrap();
        assert!(table.check(states));
        assert_eq!(endpoint(states, tx.endpoint), None);
        assert_eq!(table.commit(states, owner, tx.transaction), 0);
        assert!(table.check(states));
        tx
    }
    fn root(states: &[State; SLOTS]) -> u64 { states[3].handle(3) }

    #[test]
    fn compiled_hosting_abi_layout_matches_c() {
        assert_eq!((size_of::<Template>(), size_of::<Root>(), size_of::<Record>(), size_of::<Domain>()), (24, 32, 104, 80));
        assert_eq!((size_of::<Request>(), align_of::<Request>()), (32, 8));
        assert_eq!([offset_of!(Request, domain), offset_of!(Request, request_id), offset_of!(Request, template_id),
                    offset_of!(Request, descendant_slots), offset_of!(Request, descendant_pages), offset_of!(Request, reserved)], [0, 8, 16, 20, 24, 28]);
        assert_eq!((size_of::<Status>(), align_of::<Status>()), (104, 8));
        assert_eq!([offset_of!(Status, instance), offset_of!(Status, control), offset_of!(Status, endpoint),
            offset_of!(Status, domain), offset_of!(Status, parent_instance), offset_of!(Status, parent_endpoint),
            offset_of!(Status, generation), offset_of!(Status, slot), offset_of!(Status, template_id), offset_of!(Status, depth),
            offset_of!(Status, phase), offset_of!(Status, faults), offset_of!(Status, restarts), offset_of!(Status, reason),
            offset_of!(Status, own_pages), offset_of!(Status, reserved_slots), offset_of!(Status, reserved_pages),
            offset_of!(Status, available_slots), offset_of!(Status, available_pages)],
            [0, 8, 16, 24, 32, 40, 48, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100]);
        assert_eq!((size_of::<Transaction>(), align_of::<Transaction>(), offset_of!(Transaction, slot), offset_of!(Transaction, bootstrap_recipe)), (96, 8, 64, 92));
        assert_eq!((size_of::<DomainStatus>(), align_of::<DomainStatus>(), offset_of!(DomainStatus, slot_limit), offset_of!(DomainStatus, revoked)), (72, 8, 24, 68));
        assert_eq!((size_of::<Table>(), align_of::<Table>()), (1880, 8));
        assert_eq!([offset_of!(Table, records), offset_of!(Table, domains), offset_of!(Table, templates), offset_of!(Table, roots), offset_of!(Table, next_epoch), offset_of!(Table, root_mask)], [64, 896, 1536, 1728, 1856, 1864]);
        assert_eq!((INSTANCE, CONTROL, DOMAIN, TRANSACTION, QUERY, STOP, REAP), (0x40, 0x50, 0x60, 0x70, 1, 2, 4));
    }
    #[test]
    fn genuine_free_slots_and_two_instances_of_one_sealed_image() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let a = spawn(&mut table, &mut states, owner, domain, 2, 0, 0);
        let b = spawn(&mut table, &mut states, owner, domain, 2, 0, 0);
        assert_eq!((a.slot, b.slot), (4, 5));
        assert_ne!(a.instance, b.instance);
        assert_ne!(a.control, b.control);
        assert_ne!(a.endpoint, b.endpoint);
        assert_eq!(a.template_id, b.template_id);
        assert_eq!(table.domains[3].owned_slots, 2);
        assert_eq!(table.domains[3].owned_pages, 4);
        assert_eq!(table.history[..4], [1; 4]);
        for slot in 0..4 { assert_eq!(states[slot], State::initial()); }
    }
    #[test]
    fn reservation_conservation_charges_grandchild_once() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let supervisor = spawn(&mut table, &mut states, owner, domain, 1, 2, 8);
        let worker = spawn(&mut table, &mut states, supervisor.endpoint, supervisor.domain, 2, 0, 0);
        let sibling = spawn(&mut table, &mut states, owner, domain, 2, 0, 0);
        assert_eq!((worker.depth, sibling.depth), (2, 1));
        let root_ledger = table.domain_query(&states, owner, domain).unwrap();
        assert_eq!((root_ledger.owned_slots, root_ledger.owned_pages, root_ledger.reserved_slots, root_ledger.reserved_pages), (2, 6, 2, 8));
        assert_eq!((root_ledger.available_slots, root_ledger.available_pages), (0, 34));
        let child_ledger = table.domain_query(&states, supervisor.endpoint, supervisor.domain).unwrap();
        assert_eq!((child_ledger.owned_slots, child_ledger.owned_pages, child_ledger.available_slots, child_ledger.available_pages), (1, 2, 1, 6));
        assert_eq!(root_ledger.owned_pages + root_ledger.reserved_pages + root_ledger.available_pages, 48);
        assert_eq!(child_ledger.owned_pages + child_ledger.reserved_pages + child_ledger.available_pages, 8);
    }
    #[test]
    fn unpublished_abort_returns_all_resources_and_retires_only_identities() {
        let (mut table, states, domain) = fixture();
        let owner = root(&states);
        let before = table.clone();
        let req = request(&table, domain, 1, 2, 8);
        let tx = table.prepare(&states, owner, req).unwrap();
        assert!(table.check(&states));
        assert_eq!(table.history, before.history);
        assert_eq!(table.abort(tx.transaction), 0);
        let retired = table.next_epoch;
        table.next_epoch = before.next_epoch;
        table.domains[3].last_request = before.domains[3].last_request;
        assert_eq!(table, before);
        table.next_epoch = retired;
        table.domains[3].last_request = req.request_id;
        assert_eq!(table.abort(tx.transaction), STALE);
        assert_eq!(table.prepare(&states, owner, req), Err(STALE));
        let next = table.prepare(&states, owner, request(&table, domain, 2, 0, 0)).unwrap();
        assert_eq!(next.endpoint, tx.endpoint); // Neither unpublished endpoint ever resolved.
        assert_ne!(next.instance, tx.instance);
        assert_ne!(next.control, tx.control);
        assert!(table.check(&states));
    }
    #[test]
    fn retained_terminal_slot_is_charged_until_reap_and_old_lifetimes_stay_stale() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let a = spawn(&mut table, &mut states, owner, domain, 1, 1, 4);
        assert_eq!(table.reap(&mut states, owner, a.control), DENIED);
        assert_eq!(table.stop(&mut states, owner, a.control), Ok(1 << a.slot));
        assert_eq!(table.stop(&mut states, owner, a.control), Ok(0));
        assert_eq!((table.domains[3].owned_slots, table.domains[3].owned_pages, table.domains[3].reserved_pages), (1, 0, 0));
        assert_eq!(table.query(&states, owner, a.control).unwrap().own_pages, 0);
        assert!(table.check(&states));
        assert_eq!(table.reap(&mut states, owner, a.control), 0);
        assert_eq!(table.reap(&mut states, owner, a.control), STALE);
        assert_eq!(table.domains[3].owned_slots, 0);
        let b = spawn(&mut table, &mut states, owner, domain, 2, 0, 0);
        assert_eq!(a.slot, b.slot);
        assert_eq!(b.endpoint >> 8, (a.endpoint >> 8) + 1);
        assert_ne!(a.instance, b.instance);
        assert_ne!(a.control, b.control);
        assert_eq!(table.query(&states, owner, a.control), Err(STALE));
        assert_eq!(endpoint(&states, a.endpoint), None);
    }
    #[test]
    fn recoverable_supervisor_fault_reaps_descendants_retains_reservation_and_requires_rebind() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let supervisor = spawn(&mut table, &mut states, owner, domain, 1, 1, 8);
        let worker = spawn(&mut table, &mut states, supervisor.endpoint, supervisor.domain, 2, 0, 0);
        let sibling = spawn(&mut table, &mut states, owner, domain, 2, 0, 0);
        let sibling_before = states[sibling.slot as usize];
        assert_eq!(table.fault(&mut states, supervisor.slot as usize, 100), Ok((1 << supervisor.slot) | (1 << worker.slot)));
        assert_eq!(states[worker.slot as usize].phase, DORMANT);
        assert_eq!(table.record_slot(worker.slot as usize), None);
        assert_eq!(table.query(&states, owner, supervisor.control).unwrap().phase, BACKOFF);
        assert_eq!((table.domains[3].owned_pages, table.domains[3].reserved_pages), (6, 8));
        let child = token_slot(supervisor.domain, DOMAIN).unwrap();
        assert_eq!((table.domains[child].owned_slots, table.domains[child].owned_pages), (0, 0));
        assert_eq!(table.domains[child].token, 0);
        assert_eq!(table.poll(&mut states, supervisor.slot as usize, 103), 0);
        assert_eq!(table.poll(&mut states, supervisor.slot as usize, 104), 1);
        let status = table.query(&states, owner, supervisor.control).unwrap();
        assert_eq!(status.instance, supervisor.instance);
        assert_eq!(status.generation, 2);
        assert_eq!(status.domain, 0);
        assert_eq!(endpoint(&states, supervisor.endpoint), None);
        assert!(table.prepare(&states, status.endpoint, request(&table, supervisor.domain, 2, 0, 0)).is_err());
        let rebind_request = request(&table, domain, 1, 0, 0).request_id;
        let bound = table.rebind(&states, owner, supervisor.control, domain, rebind_request).unwrap();
        assert_ne!(bound.domain, supervisor.domain);
        let replacement = spawn(&mut table, &mut states, bound.endpoint, bound.domain, 2, 0, 0);
        assert_eq!(replacement.slot, worker.slot);
        assert!(replacement.generation() > worker.generation());
        assert_eq!(states[sibling.slot as usize], sibling_before);
        assert!(table.check(&states));
    }
    impl Transaction { fn generation(self) -> u64 { self.endpoint >> 8 } }
    #[test]
    fn stop_cancels_backoff_and_auto_reaps_children_of_retired_owners() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let parent = spawn(&mut table, &mut states, owner, domain, 1, 1, 8);
        let child = spawn(&mut table, &mut states, parent.endpoint, parent.domain, 2, 0, 0);
        assert!(table.fault(&mut states, child.slot as usize, 10).is_ok());
        assert_eq!(states[child.slot as usize].phase, BACKOFF);
        assert_eq!(table.stop(&mut states, owner, parent.control), Ok((1 << parent.slot) | (1 << child.slot)));
        assert_eq!(states[child.slot as usize].phase, DORMANT);
        assert_eq!(table.poll(&mut states, child.slot as usize, u64::MAX), INVALID);
        assert_eq!(table.poll(&mut states, parent.slot as usize, u64::MAX), 0);
        assert_eq!(table.query(&states, parent.endpoint, child.control), Err(AGAIN));
        assert_eq!(table.domains[3].owned_slots, 1);
        assert_eq!(table.domains[3].owned_pages, 0);
        assert_eq!(table.domains[3].reserved_pages, 0);
        assert!(table.check(&states));
    }
    #[test]
    fn root_generation_retirement_reaps_every_owned_record_before_fresh_root_domain() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let parent = spawn(&mut table, &mut states, owner, domain, 1, 1, 8);
        let child = spawn(&mut table, &mut states, parent.endpoint, parent.domain, 2, 0, 0);
        let sibling = spawn(&mut table, &mut states, owner, domain, 2, 0, 0);
        assert_eq!(table.fault(&mut states, 3, 20), Ok((1 << 3) | (1 << parent.slot) | (1 << child.slot) | (1 << sibling.slot)));
        assert!(table.records.iter().all(|r| r.phase == FREE));
        assert_eq!((table.domains[3].owned_slots, table.domains[3].owned_pages, table.domains[3].reserved_slots, table.domains[3].reserved_pages), (0, 0, 0, 0));
        assert_eq!(table.poll(&mut states, 3, 24), 1);
        let new_owner = root(&states);
        assert_ne!(new_owner, owner);
        assert_ne!(table.domains[3].token, domain);
        assert_eq!(table.query(&states, new_owner, parent.control), Err(STALE));
        assert!(table.prepare(&states, new_owner, Request { domain, request_id: 5, template_id: 2, ..Request::default() }).is_err());
        assert!(table.check(&states));
    }
    #[test]
    fn revocation_denies_future_descendant_creations_and_rebind_but_preserves_control() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let parent = spawn(&mut table, &mut states, owner, domain, 1, 1, 8);
        assert_eq!(table.revoke(&states, owner, domain), 0);
        assert_eq!(table.domain_query(&states, owner, domain).unwrap().revoked, 1);
        assert_eq!(table.prepare(&states, owner, request(&table, domain, 2, 0, 0)), Err(DENIED));
        assert_eq!(table.prepare(&states, parent.endpoint, request(&table, parent.domain, 2, 0, 0)), Err(DENIED));
        assert!(table.query(&states, owner, parent.control).is_ok());
        assert_eq!(table.rebind(&states, owner, parent.control, domain, 2), Err(DENIED));
        assert_eq!(table.stop(&mut states, owner, parent.control), Ok(1 << parent.slot));
        assert_eq!(table.reap(&mut states, owner, parent.control), 0);
        assert!(table.check(&states));
    }
    #[test]
    fn exhausted_depth_is_rejected_with_valid_typed_creation_authority() {
        let (mut table, mut states, domain) = fixture_with_depth(1);
        let owner = root(&states);
        let parent = spawn(&mut table, &mut states, owner, domain, 1, 0, 0);
        assert_ne!(parent.domain, 0);
        assert_eq!(table.active_domain(&states, parent.endpoint, parent.domain), Ok(token_slot(parent.domain, DOMAIN).unwrap()));
        assert_eq!(table.domains[token_slot(parent.domain, DOMAIN).unwrap()].template_mask, 2);
        assert_eq!(table.prepare(&states, parent.endpoint, request(&table, parent.domain, 2, 0, 0)), Err(DENIED));
        assert!(table.check(&states));
    }
    #[test]
    fn handles_reject_wrong_type_bit_mutations_cross_owner_and_query_only_control() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let a = spawn(&mut table, &mut states, owner, domain, 1, 1, 8);
        let b = spawn(&mut table, &mut states, owner, domain, 2, 0, 0);
        for h in [a.instance, a.endpoint, a.domain, a.transaction, (1 << 8) | 1, 0, u64::MAX] {
            assert!(table.query(&states, owner, h).is_err());
        }
        for bit in 0..64 { assert!(table.query(&states, owner, a.control ^ (1 << bit)).is_err(), "bit {bit}"); }
        assert_eq!(table.query(&states, b.endpoint, a.control), Err(DENIED));
        assert_eq!(table.prepare(&states, a.endpoint, request(&table, domain, 2, 0, 0)), Err(DENIED));
        assert_eq!(table.domain_query(&states, b.endpoint, domain), Err(DENIED));
        let n = token_slot(a.control, CONTROL).unwrap();
        table.records[n].rights = QUERY;
        assert!(table.query(&states, owner, a.control).is_ok());
        assert_eq!(table.stop(&mut states, owner, a.control), Err(DENIED));
        assert_eq!(table.reap(&mut states, owner, a.control), DENIED);
        table.records[n].rights = QUERY | STOP | REAP;
        assert!(table.check(&states));
    }
    #[test]
    fn global_slot_and_exact_page_credit_pressure_are_atomic() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        for _ in 0..4 { spawn(&mut table, &mut states, owner, domain, 2, 0, 0); }
        let before = table.clone();
        assert_eq!(table.prepare(&states, owner, request(&table, domain, 2, 0, 0)), Err(NO_SPACE));
        assert_eq!(table, before);
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        table.domains[3].page_limit = 2;
        let a = spawn(&mut table, &mut states, owner, domain, 2, 0, 0);
        assert_eq!(table.domain_query(&states, owner, domain).unwrap().available_pages, 0);
        let before = table.clone();
        assert_eq!(table.prepare(&states, owner, request(&table, domain, 2, 0, 0)), Err(NO_SPACE));
        assert_eq!(table, before);
        assert!(table.stop(&mut states, owner, a.control).is_ok());
        assert_eq!(table.domain_query(&states, owner, domain).unwrap().available_pages, 2);
        assert!(table.check(&states));
    }
    #[test]
    fn epoch_request_and_generation_exhaustion_never_wrap() {
        let (mut table, states, domain) = fixture();
        let owner = root(&states);
        table.next_epoch = GENERATION_MAX - 1;
        let before = table.clone();
        assert_eq!(table.prepare(&states, owner, request(&table, domain, 2, 0, 0)), Err(NO_SPACE));
        assert_eq!(table, before);
        table.next_epoch = GENERATION_MAX - 2;
        let tx = table.prepare(&states, owner, request(&table, domain, 2, 0, 0)).unwrap();
        assert_eq!(table.next_epoch, GENERATION_MAX + 1);
        assert_eq!(table.abort(tx.transaction), 0);
        assert_eq!(table.prepare(&states, owner, request(&table, domain, 2, 0, 0)), Err(NO_SPACE));
        let (mut table, states, domain) = fixture();
        let owner = root(&states);
        let req = Request { domain, request_id: u64::MAX, template_id: 2, ..Request::default() };
        let tx = table.prepare(&states, owner, req).unwrap();
        assert_eq!(table.abort(tx.transaction), 0);
        assert_eq!(table.prepare(&states, owner, req), Err(STALE));
        assert_eq!(table.prepare(&states, owner, Request { request_id: 1, ..req }), Err(STALE));
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        for slot in ROOTS..SLOTS { table.history[slot] = GENERATION_MAX; states[slot] = dormant(GENERATION_MAX); }
        assert_eq!(table.prepare(&states, owner, request(&table, domain, 2, 0, 0)), Err(NO_SPACE));
        assert!(table.check(&states));
    }
    #[test]
    fn malformed_creation_and_configuration_fail_without_mutation() {
        let (mut table, states, domain) = fixture();
        let owner = root(&states);
        let valid = request(&table, domain, 2, 0, 0);
        for req in [Request { reserved: 1, ..valid }, Request { template_id: 0, ..valid },
            Request { template_id: 9, ..valid }, Request { descendant_slots: u32::MAX, ..valid },
            Request { descendant_pages: u32::MAX, ..valid }, Request { request_id: 0, ..valid },
            Request { domain: owner, ..valid }] {
            let before = table.clone();
            assert!(table.prepare(&states, owner, req).is_err());
            assert_eq!(table, before);
        }
        assert_eq!(table.prepare(&states, states[0].handle(0), valid), Err(DENIED));
        let mut empty = Table::new(15, 80);
        let initial = empty.clone();
        let mut bad = templates();
        bad[0].reserved = 1;
        assert_eq!(empty.configure(&states, &bad, &[]), INVALID);
        assert_eq!(empty, initial);
        bad = templates(); bad[0].pages = 21;
        assert_eq!(empty.configure(&states, &bad, &[]), INVALID);
        assert_eq!(empty, initial);
    }
    #[test]
    fn parent_fault_during_preparation_cancels_commit_and_returns_pending_reservation() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let tx = table.prepare(&states, owner, request(&table, domain, 1, 1, 8)).unwrap();
        assert_eq!(table.fault(&mut states, 3, 10), Ok((1 << 3) | (1 << tx.slot)));
        assert_eq!(table.commit(&mut states, owner, tx.transaction), STALE);
        assert_eq!(table.abort(tx.transaction), STALE);
        assert_eq!(table.history[tx.slot as usize], 0);
        assert_eq!((table.domains[3].owned_slots, table.domains[3].owned_pages, table.domains[3].reserved_pages), (0, 0, 0));
        assert!(table.check(&states));
    }
    #[test]
    fn quarantine_releases_pages_but_retains_control_until_owner_reaps() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let a = spawn(&mut table, &mut states, owner, domain, 1, 1, 8);
        for now in [0, 4, 12] {
            assert!(table.fault(&mut states, a.slot as usize, now).is_ok());
            let deadline = states[a.slot as usize].deadline;
            assert_eq!(table.poll(&mut states, a.slot as usize, deadline), 1);
        }
        assert!(table.fault(&mut states, a.slot as usize, 28).is_ok());
        let status = table.query(&states, owner, a.control).unwrap();
        assert_eq!((status.phase, status.own_pages, status.reserved_pages, status.restarts), (QUARANTINED, 0, 0, 3));
        assert_eq!((table.domains[3].owned_slots, table.domains[3].owned_pages), (1, 0));
        assert_eq!(table.poll(&mut states, a.slot as usize, u64::MAX), 0);
        assert_eq!(table.reap(&mut states, owner, a.control), 0);
        assert!(table.check(&states));
    }
    #[test]
    fn null_ffi_hosting_arguments_fail_closed() {
        unsafe {
            z_host_init(ptr::null_mut(), 0, 0);
            assert_eq!(z_host_configure(ptr::null_mut(), ptr::null(), ptr::null(), 0, ptr::null(), 0), INVALID);
            assert_eq!(z_host_root_domain(ptr::null(), ptr::null(), 0), INVALID as i64);
            assert_eq!(z_host_bind_root(ptr::null_mut(), ptr::null(), 0), INVALID);
            assert_eq!(z_host_prepare(ptr::null_mut(), ptr::null(), 0, ptr::null(), ptr::null_mut()), INVALID);
            assert_eq!(z_host_abort(ptr::null_mut(), 0), INVALID);
            assert_eq!(z_host_commit(ptr::null_mut(), ptr::null_mut(), 0, 0), INVALID);
            assert_eq!(z_host_query(ptr::null(), ptr::null(), 0, 0, ptr::null_mut()), INVALID);
            assert_eq!(z_host_stop(ptr::null_mut(), ptr::null_mut(), 0, 0, ptr::null_mut()), INVALID);
            assert_eq!(z_host_reap(ptr::null_mut(), ptr::null_mut(), 0, 0), INVALID);
            assert_eq!(z_host_fault(ptr::null_mut(), ptr::null_mut(), 0, 0, ptr::null_mut()), INVALID);
            assert_eq!(z_host_exit(ptr::null_mut(), ptr::null_mut(), 0, ptr::null_mut()), INVALID);
            assert_eq!(z_host_poll(ptr::null_mut(), ptr::null_mut(), 0, 0), INVALID);
            assert_eq!(z_host_rebind(ptr::null_mut(), ptr::null(), 0, 0, 0, 0, ptr::null_mut()), INVALID);
            assert_eq!(z_host_revoke(ptr::null_mut(), ptr::null(), 0, 0), INVALID);
            assert_eq!(z_host_domain_query(ptr::null(), ptr::null(), 0, 0, ptr::null_mut()), INVALID);
            assert_eq!(z_host_descendants(ptr::null(), 0), 0);
            assert_eq!(z_host_slot(ptr::null(), 0), INVALID);
            assert_eq!(z_host_check(ptr::null(), ptr::null()), 0);
        }
    }

    #[test]
    fn create_and_rebind_share_request_namespace_without_same_generation_reset() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let parent = spawn(&mut table, &mut states, owner, domain, 1, 2, 4);
        let child = spawn(&mut table, &mut states, parent.endpoint, parent.domain, 2, 0, 0);
        let rebound = table.rebind(&states, owner, parent.control, domain, 2).unwrap();
        assert_ne!(rebound.domain, parent.domain);
        assert_eq!(table.domains[token_slot(rebound.domain, DOMAIN).unwrap()].last_request, 1);
        assert_eq!(table.prepare(&states, parent.endpoint, Request { domain: rebound.domain,
            request_id: 1, template_id: 2, ..Request::default() }), Err(STALE));
        assert_eq!(table.prepare(&states, owner, Request { domain, request_id: 2, template_id: 2, ..Request::default() }), Err(STALE));
        assert_eq!(table.rebind(&states, owner, parent.control, domain, 2), Err(STALE));
        assert!(table.query(&states, parent.endpoint, child.control).is_ok());
        assert!(table.fault(&mut states, parent.slot as usize, 0).is_ok());
        assert_eq!(table.poll(&mut states, parent.slot as usize, 4), 1);
        let fresh = table.rebind(&states, owner, parent.control, domain, 3).unwrap();
        assert_eq!(table.domains[token_slot(fresh.domain, DOMAIN).unwrap()].last_request, 0);
        let request = Request { domain: fresh.domain, request_id: 1, template_id: 2, ..Request::default() };
        let tx = table.prepare(&states, fresh.endpoint, request).unwrap();
        assert_eq!(table.commit(&mut states, fresh.endpoint, tx.transaction), 0);
        assert_eq!(table.rebind(&states, owner, parent.control, domain, u64::MAX).unwrap().request_id, u64::MAX);
        assert_eq!(table.rebind(&states, owner, parent.control, domain, 4), Err(STALE));
        assert!(table.check(&states));
    }
    #[test]
    fn voluntary_exit_retains_only_live_owners_terminal_record_and_reaps_descendants() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let parent = spawn(&mut table, &mut states, owner, domain, 1, 1, 4);
        let child = spawn(&mut table, &mut states, parent.endpoint, parent.domain, 2, 0, 0);
        assert_eq!(table.exit(&mut states, parent.slot as usize), Ok((1 << parent.slot) | (1 << child.slot)));
        assert_eq!(table.query(&states, owner, parent.control).unwrap().phase, STOPPED);
        assert_eq!(table.record_slot(child.slot as usize), None);
        assert_eq!((table.domains[3].owned_slots, table.domains[3].owned_pages, table.domains[3].reserved_pages), (1, 0, 0));
        assert_eq!(table.exit(&mut states, parent.slot as usize), Err(INVALID));
        assert_eq!(table.poll(&mut states, parent.slot as usize, u64::MAX), 0);
        assert_eq!(table.reap(&mut states, owner, parent.control), 0);
        assert!(table.check(&states));
        let parent = spawn(&mut table, &mut states, owner, domain, 1, 1, 4);
        let _child = spawn(&mut table, &mut states, parent.endpoint, parent.domain, 2, 0, 0);
        assert!(table.exit(&mut states, 3).is_ok());
        assert!(table.records.iter().all(|r| r.phase == FREE));
        assert_eq!(table.domains[3].token, 0);
        assert_eq!(table.poll(&mut states, 3, u64::MAX), 0);
        assert!(table.check(&states));
    }
    #[test]
    fn invariant_checker_rejects_orphans_future_duplicate_epochs_and_scope_widening() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let parent = spawn(&mut table, &mut states, owner, domain, 1, 1, 4);
        let n = token_slot(parent.instance, INSTANCE).unwrap();
        let d = token_slot(parent.domain, DOMAIN).unwrap();
        for mutation in 0..6 {
            let mut invalid = table.clone();
            match mutation {
                0 => invalid.next_epoch = invalid.records[n].control >> 8,
                1 => invalid.domains[d].token = token(DOMAIN, d, invalid.records[n].instance >> 8),
                2 => invalid.domains[d].template_mask = 3,
                3 => invalid.domains[d].max_depth = 3,
                4 => { let free = (0..OBJECTS).find(|i| invalid.domains[*i].holder == 0).unwrap();
                    invalid.domains[free] = invalid.domains[d]; invalid.domains[free].token = 0; },
                5 => invalid.records[n].rights = 8,
                _ => unreachable!(),
            }
            assert!(!invalid.check(&states), "mutation {mutation}");
        }
    }
    #[test]
    fn all_eight_domains_saturate_at_the_global_runtime_slot_bound() {
        let mut states = [State::initial(); SLOTS];
        for s in &mut states[ROOTS..] { *s = dormant(0); }
        let roots = core::array::from_fn::<_, ROOTS, _>(|slot| Root {
            slot: slot as u32, template_mask: 3, slot_limit: 1, page_limit: 12,
            max_depth: 2, bootstrap_recipe: 1, ..Root::default() });
        // This trusted policy fixture establishes the general four-domain
        // bound. The privileged production manifest authorizes only root400.
        let mut table = Table::new(15, 80);
        assert_eq!(table.configure(&states, &templates(), &roots), 0);
        let mut controls = [0u64; ROOTS];
        for slot in 0..ROOTS {
            let owner = states[slot].handle(slot as u32);
            let authority = table.domains[slot].token;
            let child = spawn(&mut table, &mut states, owner, authority, 1, 0, 0);
            controls[slot] = child.control;
            assert!(table.active_domain(&states, child.endpoint, child.domain).is_ok());
        }
        assert_eq!(table.domains.iter().filter(|d| d.holder != 0).count(), OBJECTS);
        assert_eq!(table.records.iter().filter(|r| r.phase != FREE).count(), SLOTS - ROOTS);
        let before = table.clone();
        let owner = states[0].handle(0);
        let authority = table.domains[0].token;
        assert_eq!(table.prepare(&states, owner, request(&table, authority, 1, 0, 0)), Err(NO_SPACE));
        assert_eq!(table, before);
        for slot in 0..ROOTS {
            let owner = states[slot].handle(slot as u32);
            assert!(table.stop(&mut states, owner, controls[slot]).is_ok());
            assert_eq!(table.reap(&mut states, owner, controls[slot]), 0);
        }
        assert_eq!(table.domains.iter().filter(|d| d.holder != 0).count(), ROOTS);
        assert!(table.records.iter().all(|r| r.phase == FREE));
        assert!(table.check(&states));
    }
    #[test]
    fn root_execution_recovers_when_creation_factory_epochs_are_terminal() {
        let (mut table, mut states, domain) = fixture();
        let owner = root(&states);
        let parent = spawn(&mut table, &mut states, owner, domain, 1, 1, 4);
        let _child = spawn(&mut table, &mut states, parent.endpoint, parent.domain, 2, 0, 0);
        assert!(table.fault(&mut states, 3, 0).is_ok());
        table.next_epoch = GENERATION_MAX + 1;
        assert_eq!(table.poll(&mut states, 3, 4), 1);
        assert_eq!(states[3].phase, READY);
        assert_eq!(states[3].generation, 2);
        assert_eq!(table.domains[3].token, 0);
        assert!(table.records.iter().all(|r| r.phase == FREE));
        assert_eq!(table.prepare(&states, root(&states), Request { domain, request_id: 7,
            template_id: 2, ..Request::default() }), Err(STALE));
        assert!(table.check(&states));
    }

    mod model {
        use super::*;
        use std::collections::BTreeSet;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Life { Running, Delay(u64), Stopped, Quarantined }
        #[derive(Clone, Debug)]
        struct Node {
            logical: u64, control: u64, slot: usize, parent: Option<u64>, template: u32,
            depth: u32, generation: u64, faults: u32, restarts: u32, life: Life,
            slots: u32, pages: u32, authority: bool, revoked: bool, domain: u64,
        }
        impl Node {
            fn endpoint(&self) -> u64 { (self.generation << 8) | (self.slot as u64 + 1) }
            fn allocation(&self) -> u32 {
                if matches!(self.life, Life::Stopped | Life::Quarantined) { 0 }
                else if self.template == 1 { 4 } else { 2 }
            }
            fn reservation(&self) -> (u32, u32) {
                if self.allocation() == 0 { (0, 0) } else { (self.slots, self.pages) }
            }
        }
        #[derive(Clone, Debug)]
        struct Model {
            nodes: Vec<Node>, generations: [u64; SLOTS], root_life: Life,
            root_restarts: u32, root_faults: u32, root_domain: u64, root_revoked: bool,
            dead_controls: Vec<u64>, retired_endpoints: Vec<u64>, identities: BTreeSet<u64>,
            now: u64, requests: u64,
        }
        impl Model {
            fn new(domain: u64) -> Self {
                Self { nodes: Vec::new(), generations: [1, 1, 1, 1, 0, 0, 0, 0],
                    root_life: Life::Running, root_restarts: 0, root_faults: 0,
                    root_domain: domain, root_revoked: false, dead_controls: Vec::new(),
                    retired_endpoints: Vec::new(), identities: BTreeSet::new(), now: 0, requests: 0 }
            }
            fn root(&self) -> u64 { (self.generations[3] << 8) | 4 }
            fn children(&self, parent: Option<u64>) -> impl Iterator<Item = &Node> {
                self.nodes.iter().filter(move |n| n.parent == parent)
            }
            // The model has no domain table or mutable ledger. It derives all
            // commitments from the logical tree and each child's reservation.
            fn ledger(&self, parent: Option<u64>) -> (u32, u32, u32, u32) {
                self.children(parent).fold((0, 0, 0, 0), |(s, p, rs, rp), n| {
                    let (ns, np) = n.reservation();
                    (s + 1, p + n.allocation(), rs + ns, rp + np)
                })
            }
            fn branch(&self, logical: u64) -> BTreeSet<u64> {
                let mut found = BTreeSet::new();
                let mut frontier = vec![logical];
                while let Some(parent) = frontier.pop() {
                    for n in self.children(Some(parent)) {
                        assert!(found.insert(n.logical));
                        frontier.push(n.logical);
                    }
                }
                found
            }
            fn remove(&mut self, removed: &BTreeSet<u64>) {
                for n in self.nodes.iter().filter(|n| removed.contains(&n.logical)) {
                    self.dead_controls.push(n.control);
                    self.retired_endpoints.push(n.endpoint());
                }
                self.nodes.retain(|n| !removed.contains(&n.logical));
            }
            fn compare(&self, table: &Table, states: &[State; SLOTS], seed: u64, sequence: &[String]) {
                assert!(table.check(states), "seed={seed:x} sequence={sequence:?}");
                assert_eq!(table.history, self.generations, "seed={seed:x} sequence={sequence:?}");
                assert_eq!(table.records.iter().filter(|r| r.phase != FREE).count(), self.nodes.len());
                let mut slots = BTreeSet::new();
                let expected_root = match self.root_life { Life::Running => READY, Life::Delay(_) => BACKOFF,
                    Life::Stopped => STOPPED, Life::Quarantined => QUARANTINED };
                assert_eq!(states[3].phase, expected_root);
                assert_eq!((states[3].faults, states[3].restarts), (self.root_faults, self.root_restarts));
                let expected = self.ledger(None);
                let d = table.domains.iter().find(|d| d.holder_slot == 3 && d.holder != 0).unwrap();
                assert_eq!((d.owned_slots, d.owned_pages, d.reserved_slots, d.reserved_pages), expected);
                assert_eq!(d.slot_limit - expected.0 - expected.2, 4 - expected.0 - expected.2);
                assert_eq!(d.page_limit - expected.1 - expected.3, 48 - expected.1 - expected.3);
                for n in &self.nodes {
                    assert!(slots.insert(n.slot));
                    assert!(n.slot >= ROOTS && n.slot < SLOTS);
                    let r = table.records.iter().find(|r| r.instance == n.logical).unwrap();
                    assert_eq!((r.slot as usize, r.parent_instance, r.template_id, r.depth, r.generation, r.pages),
                        (n.slot, n.parent.unwrap_or(0), n.template, n.depth, n.generation, n.allocation()));
                    let expected_phase = match n.life { Life::Running => READY, Life::Delay(_) => BACKOFF,
                        Life::Stopped => STOPPED, Life::Quarantined => QUARANTINED };
                    assert_eq!(states[n.slot].phase, expected_phase);
                    assert_eq!((states[n.slot].faults, states[n.slot].restarts), (n.faults, n.restarts));
                    if let Life::Delay(deadline) = n.life { assert_eq!(states[n.slot].deadline, deadline); }
                    if n.template == 1 && n.allocation() != 0 {
                        let child = table.domains.iter().find(|d| d.instance == n.logical && d.holder != 0).unwrap();
                        let expected = self.ledger(Some(n.logical));
                        assert_eq!((child.slot_limit, child.page_limit), (n.slots, n.pages));
                        assert_eq!((child.owned_slots, child.owned_pages, child.reserved_slots, child.reserved_pages), expected);
                        assert_eq!(child.token != 0, n.authority);
                        assert_eq!(child.revoked != 0, n.revoked || self.root_revoked);
                    }
                    let owner = n.parent.map_or(self.root(), |p| self.nodes.iter().find(|v| v.logical == p).unwrap().endpoint());
                    if endpoint(states, owner).is_some() {
                        let status = table.query(states, owner, n.control).unwrap();
                        assert_eq!((status.instance, status.generation, status.phase, status.own_pages),
                            (n.logical, n.generation, expected_phase, n.allocation()));
                    }
                }
                for handle in &self.dead_controls { assert!(table.query(states, self.root(), *handle).is_err()); }
                for ep in &self.retired_endpoints { assert_eq!(endpoint(states, *ep), None); }
            }
        }
        fn random(state: &mut u64) -> u64 {
            *state ^= *state << 13; *state ^= *state >> 7; *state ^= *state << 17; *state
        }
        fn remember_spawn(model: &mut Model, tx: Transaction, parent: Option<u64>, template: u32, slots: u32, pages: u32) {
            let slot = tx.slot as usize;
            model.generations[slot] += 1;
            assert_eq!(tx.generation(), model.generations[slot]);
            for handle in [tx.instance, tx.control, tx.transaction] { assert!(model.identities.insert(handle)); }
            if tx.domain != 0 { assert!(model.identities.insert(tx.domain)); }
            model.nodes.push(Node { logical: tx.instance, control: tx.control, slot, parent, template,
                depth: parent.map_or(1, |_| 2), generation: model.generations[slot], faults: 0, restarts: 0,
                life: Life::Running, slots, pages, authority: tx.domain != 0, revoked: false, domain: tx.domain });
        }
        fn exhaustive(table: Table, states: [State; SLOTS], model: Model, prefix: u64, remaining: u32, checks: &mut u64) {
            model.compare(&table, &states, prefix, &[format!("base-six prefix {prefix} remaining {remaining}")]);
            *checks += 1;
            if remaining == 0 { return; }
            for action in 0..6 {
                let mut t = table.clone(); let mut s = states; let mut m = model.clone();
                let manager = m.nodes.iter().find(|n| n.template == 1 && n.depth == 1).cloned();
                match action {
                    0 => {
                        let (parent, owner, domain, kind, slots, pages) = match manager.as_ref() {
                            Some(n) if n.life == Life::Running && n.authority => (Some(n.logical), n.endpoint(), n.domain, 2, 0, 0),
                            None => (None, m.root(), m.root_domain, 1, 2, 4),
                            _ => { exhaustive(t, s, m, prefix * 6 + action + 1, remaining - 1, checks); continue; }
                        };
                        let ledger = m.ledger(parent);
                        let (limit_slots, limit_pages) = parent.map_or((4, 48), |p| {
                            let n = m.nodes.iter().find(|n| n.logical == p).unwrap(); (n.slots, n.pages) });
                        let allocation = if kind == 1 { 4 } else { 2 };
                        let fits = ledger.0 + ledger.2 + 1 + slots <= limit_slots
                            && ledger.1 + ledger.3 + allocation + pages <= limit_pages && m.nodes.len() < 4;
                        m.requests += 1;
                        let result = t.prepare(&s, owner, Request { domain, request_id: m.requests, template_id: kind,
                            descendant_slots: slots, descendant_pages: pages, reserved: 0 });
                        assert_eq!(result.is_ok(), fits);
                        if let Ok(tx) = result { assert_eq!(t.commit(&mut s, owner, tx.transaction), 0); remember_spawn(&mut m, tx, parent, kind, slots, pages); }
                    }
                    1 => if let Some(n) = manager.as_ref().filter(|n| n.life == Life::Running) {
                        let branch = m.branch(n.logical);
                        let mask = branch.iter().fold(1 << n.slot, |v, p| v | (1 << m.nodes.iter().find(|n| n.logical == *p).unwrap().slot));
                        assert_eq!(t.fault(&mut s, n.slot, m.now), Ok(mask));
                        m.remove(&branch); m.retired_endpoints.push(n.endpoint());
                        let target = m.nodes.iter_mut().find(|v| v.logical == n.logical).unwrap();
                        target.faults += 1; target.authority = false;
                        target.life = if target.restarts == 3 { Life::Quarantined } else { Life::Delay(m.now + (4 << target.restarts)) };
                    },
                    2 => {
                        m.now += 4;
                        for n in &mut m.nodes {
                            if let Life::Delay(deadline) = n.life {
                                let due = m.now >= deadline;
                                assert_eq!(t.poll(&mut s, n.slot, m.now), i32::from(due));
                                if due { m.generations[n.slot] += 1; n.generation += 1; n.restarts += 1; n.life = Life::Running; }
                            }
                        }
                    }
                    3 => if let Some(n) = manager.as_ref() {
                        let terminal = matches!(n.life, Life::Stopped | Life::Quarantined);
                        let branch = m.branch(n.logical);
                        let mask = branch.iter().fold(1 << n.slot, |v, p| v | (1 << m.nodes.iter().find(|n| n.logical == *p).unwrap().slot));
                        assert_eq!(t.stop(&mut s, m.root(), n.control), Ok(if terminal { 0 } else { mask }));
                        if !terminal {
                            m.remove(&branch); m.retired_endpoints.push(n.endpoint());
                            let target = m.nodes.iter_mut().find(|v| v.logical == n.logical).unwrap(); target.life = Life::Stopped; target.authority = false;
                        }
                    },
                    4 => if let Some(n) = manager.as_ref() {
                        let terminal = matches!(n.life, Life::Stopped | Life::Quarantined);
                        assert_eq!(t.reap(&mut s, m.root(), n.control), if terminal { 0 } else { DENIED });
                        if terminal { m.remove(&[n.logical].into_iter().collect()); }
                    },
                    5 => if let Some(n) = manager.as_ref() {
                        m.requests += 1;
                        let result = t.rebind(&s, m.root(), n.control, m.root_domain, m.requests);
                        assert_eq!(result.is_ok(), n.life == Life::Running);
                        if let Ok(tx) = result {
                            assert!(m.identities.insert(tx.domain));
                            let target = m.nodes.iter_mut().find(|v| v.logical == n.logical).unwrap(); target.domain = tx.domain; target.authority = true;
                        }
                    },
                    _ => unreachable!(),
                }
                exhaustive(t, s, m, prefix * 6 + action + 1, remaining - 1, checks);
            }
        }
        #[test]
        fn bounded_exhaustive_hierarchy_fault_stop_reap_rebind_and_reuse() {
            let (mut table, mut states, domain) = fixture();
            let mut model = Model::new(domain);
            let owner = model.root();
            let manager = spawn(&mut table, &mut states, owner, domain, 1, 2, 4);
            remember_spawn(&mut model, manager, None, 1, 2, 4);
            let sibling = spawn(&mut table, &mut states, owner, domain, 2, 0, 0);
            remember_spawn(&mut model, sibling, None, 2, 0, 0);
            let child = spawn(&mut table, &mut states, manager.endpoint, manager.domain, 2, 0, 0);
            remember_spawn(&mut model, child, Some(manager.instance), 2, 0, 0);
            model.requests = 3;
            let mut checks = 0;
            exhaustive(table, states, model, 0, 6, &mut checks);
            assert_eq!(checks, 55_987); // All six-action prefixes, length zero through six.
        }
        #[test]
        fn independent_tree_model_generated_failures_recovery_revocation_and_reuse() {
            for seed in [1, 0x5ea1, 0xbadc0ffee, 0x7649abddc7, 0x9e3779b97f4a7c15, 0xd1b54a32d192ed03] {
                let (mut table, mut states, domain) = fixture();
                let mut model = Model::new(domain);
                let mut rng = seed;
                let mut sequence = Vec::new();
                for step in 0..3000 {
                    let operation = random(&mut rng) % 10;
                    let choice = random(&mut rng) as usize;
                    let selected = if model.nodes.is_empty() { None } else { Some(choice % model.nodes.len()) };
                    let description: String;
                    match operation {
                        0..=2 if model.root_life == Life::Running => {
                            let creators: Vec<_> = model.nodes.iter().filter(|n| n.template == 1 && n.life == Life::Running && n.authority).map(|n| n.logical).collect();
                            let parent = if creators.is_empty() || choice % 3 == 0 { None } else { Some(creators[choice % creators.len()]) };
                            let (owner, domain, depth, slots, pages, allowed, revoked) = match parent {
                                None => (model.root(), model.root_domain, 1, 4, 48, 3, model.root_revoked),
                                Some(p) => { let n = model.nodes.iter().find(|n| n.logical == p).unwrap();
                                    (n.endpoint(), n.domain, n.depth + 1, n.slots, n.pages, 2, n.revoked || model.root_revoked) }
                            };
                            let template = if choice % 3 == 1 { 1 } else { 2 };
                            let delegated_slots = if template == 1 { (random(&mut rng) % 3) as u32 } else { 0 };
                            let delegated_pages = if template == 1 { (random(&mut rng) % 13) as u32 } else { 0 };
                            let allocation = if template == 1 { 4 } else { 2 };
                            let ledger = model.ledger(parent);
                            let expected = if revoked || allowed & (1 << (template - 1)) == 0 || depth > 2 { Err(DENIED) }
                                else if ledger.0 + ledger.2 + 1 + delegated_slots > slots || ledger.1 + ledger.3 + allocation + delegated_pages > pages || model.nodes.len() == 4 { Err(NO_SPACE) }
                                else { Ok(()) };
                            model.requests += 1;
                            let req = Request { domain, request_id: model.requests, template_id: template,
                                descendant_slots: delegated_slots, descendant_pages: delegated_pages, reserved: 0 };
                            let result = table.prepare(&states, owner, req);
                            assert_eq!(result.as_ref().map(|_| ()).map_err(|e| *e), expected, "seed={seed:x} step={step} sequence={sequence:?}");
                            let injected_abort = random(&mut rng) % 4 == 0;
                            description = format!("spawn parent={parent:?} template={template} reserve={delegated_slots}/{delegated_pages} abort={injected_abort} result={expected:?}");
                            if let Ok(tx) = result {
                                for h in [tx.instance, tx.control, tx.transaction] { assert!(model.identities.insert(h)); }
                                if tx.domain != 0 { assert!(model.identities.insert(tx.domain)); }
                                assert_eq!(endpoint(&states, tx.endpoint), None);
                                if injected_abort {
                                    assert_eq!(table.abort(tx.transaction), 0);
                                    model.dead_controls.push(tx.control);
                                } else {
                                    assert_eq!(table.commit(&mut states, owner, tx.transaction), 0);
                                    let slot = tx.slot as usize;
                                    model.generations[slot] += 1;
                                    assert_eq!(tx.generation(), model.generations[slot]);
                                    model.nodes.push(Node { logical: tx.instance, control: tx.control, slot, parent, template,
                                        depth, generation: model.generations[slot], faults: 0, restarts: 0, life: Life::Running,
                                        slots: delegated_slots, pages: delegated_pages, authority: tx.domain != 0,
                                        revoked: false, domain: tx.domain });
                                }
                            }
                        }
                        3 if selected.is_some() => {
                            let i = selected.unwrap(); let target = model.nodes[i].clone();
                            description = format!("fault {} {:?}", target.logical, target.life);
                            if target.life == Life::Running {
                                let branch = model.branch(target.logical);
                                let expected_mask = branch.iter().fold(1 << target.slot, |mask, id| mask | (1 << model.nodes.iter().find(|n| n.logical == *id).unwrap().slot));
                                assert_eq!(table.fault(&mut states, target.slot, model.now), Ok(expected_mask));
                                model.remove(&branch);
                                model.retired_endpoints.push(target.endpoint());
                                let n = model.nodes.iter_mut().find(|n| n.logical == target.logical).unwrap();
                                n.faults += 1; n.authority = false;
                                n.life = if n.restarts == 3 { Life::Quarantined } else { Life::Delay(model.now + (4 << n.restarts)) };
                            }
                        }
                        4 => {
                            model.now += random(&mut rng) % 9 + 1;
                            description = format!("advance {}", model.now);
                            if let Life::Delay(deadline) = model.root_life {
                                let due = model.now >= deadline;
                                assert_eq!(table.poll(&mut states, 3, model.now), i32::from(due));
                                if due { model.generations[3] += 1; model.root_restarts += 1; model.root_life = Life::Running;
                                    model.root_revoked = false; model.root_domain = table.domains[3].token;
                                    assert!(model.identities.insert(model.root_domain)); }
                            }
                            for i in 0..model.nodes.len() {
                                if let Life::Delay(deadline) = model.nodes[i].life {
                                    let due = model.now >= deadline;
                                    assert_eq!(table.poll(&mut states, model.nodes[i].slot, model.now), i32::from(due));
                                    if due { model.generations[model.nodes[i].slot] += 1; model.nodes[i].generation += 1;
                                        model.nodes[i].restarts += 1; model.nodes[i].life = Life::Running; }
                                }
                            }
                        }
                        5 if selected.is_some() => {
                            let target = model.nodes[selected.unwrap()].clone();
                            description = format!("stop {}", target.logical);
                            let owner = target.parent.map_or(model.root(), |p| model.nodes.iter().find(|n| n.logical == p).unwrap().endpoint());
                            let terminal = matches!(target.life, Life::Stopped | Life::Quarantined);
                            let branch = model.branch(target.logical);
                            let mask = branch.iter().fold(1 << target.slot, |m, p| m | (1 << model.nodes.iter().find(|n| n.logical == *p).unwrap().slot));
                            assert_eq!(table.stop(&mut states, owner, target.control), Ok(if terminal { 0 } else { mask }));
                            if !terminal {
                                model.remove(&branch); model.retired_endpoints.push(target.endpoint());
                                let n = model.nodes.iter_mut().find(|n| n.logical == target.logical).unwrap();
                                n.life = Life::Stopped; n.authority = false;
                            }
                        }
                        6 if selected.is_some() => {
                            let target = model.nodes[selected.unwrap()].clone();
                            description = format!("reap {}", target.logical);
                            let owner = target.parent.map_or(model.root(), |p| model.nodes.iter().find(|n| n.logical == p).unwrap().endpoint());
                            if matches!(target.life, Life::Stopped | Life::Quarantined) {
                                assert_eq!(table.reap(&mut states, owner, target.control), 0);
                                let removed = [target.logical].into_iter().collect(); model.remove(&removed);
                            } else { assert_eq!(table.reap(&mut states, owner, target.control), DENIED); }
                        }
                        7 if selected.is_some() => {
                            let target = model.nodes[selected.unwrap()].clone();
                            description = format!("rebind {}", target.logical);
                            let owner = target.parent.map_or(model.root(), |p| model.nodes.iter().find(|n| n.logical == p).unwrap().endpoint());
                            let creation = target.parent.map_or(model.root_domain, |p| model.nodes.iter().find(|n| n.logical == p).unwrap().domain);
                            let allowed = target.life == Life::Running && !model.root_revoked && !target.revoked;
                            model.requests += 1;
                            let result = table.rebind(&states, owner, target.control, creation, model.requests);
                            assert_eq!(result.is_ok(), allowed);
                            if let Ok(tx) = result {
                                if tx.domain != 0 { assert!(model.identities.insert(tx.domain)); }
                                let n = model.nodes.iter_mut().find(|n| n.logical == target.logical).unwrap();
                                n.authority = tx.domain != 0; n.domain = tx.domain;
                            }
                        }
                        8 if model.root_life == Life::Running => {
                            description = "revoke root creation domain".into();
                            assert_eq!(table.revoke(&states, model.root(), model.root_domain), 0);
                            model.root_revoked = true;
                        }
                        9 if model.root_life == Life::Running && model.root_restarts < 3 => {
                            description = "fault root owner".into();
                            let expected = model.nodes.iter().fold(1 << 3, |m, n| m | (1 << n.slot));
                            assert_eq!(table.fault(&mut states, 3, model.now), Ok(expected));
                            let removed = model.nodes.iter().map(|n| n.logical).collect(); model.remove(&removed);
                            model.retired_endpoints.push(model.root());
                            model.root_faults += 1;
                            model.root_life = Life::Delay(model.now + (4 << model.root_restarts));
                        }
                        _ => { description = format!("no-op {operation}"); }
                    }
                    sequence.push(description);
                    if sequence.len() > 50 { sequence.remove(0); }
                    model.compare(&table, &states, seed, &sequence);
                    // Keep every seed active after the bounded root restart
                    // budget; replenishment occurs by starting a fresh boot,
                    // never by resetting an occupied runtime slot's history.
                    if model.root_restarts == 3 && model.root_revoked && step < 2800 {
                        let (fresh_table, fresh_states, fresh_domain) = fixture();
                        table = fresh_table; states = fresh_states; model = Model::new(fresh_domain);
                        sequence.push("fresh independent boot".into());
                    }
                }
            }
        }
    }
}
