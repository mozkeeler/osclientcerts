use crate::macos_backend::*;
use crate::types::*;

use std::collections::BTreeSet;

pub struct Implementation {
    sessions: BTreeSet<CK_SESSION_HANDLE>,
    next_session: CK_SESSION_HANDLE,
}

impl Implementation {
    pub fn new() -> Implementation {
        Implementation {
            sessions: BTreeSet::new(),
            next_session: 1,
        }
    }

    pub fn open_session(&mut self) -> CK_SESSION_HANDLE {
        let next_session = self.next_session;
        self.next_session += 1;
        self.sessions.insert(next_session);
        next_session
    }

    pub fn close_all_sessions(&mut self) {
        self.sessions.clear();
    }

    pub fn find_certs(&mut self) {
        list_keys();
    }
}
