use crate::macos_backend::*;
use crate::types::*;

use std::collections::{BTreeMap, BTreeSet};

pub struct Implementation {
    sessions: BTreeSet<CK_SESSION_HANDLE>,
    searches: BTreeMap<CK_SESSION_HANDLE, Vec<CK_OBJECT_HANDLE>>,
    certs: BTreeMap<CK_OBJECT_HANDLE, Cert>,
    next_session: CK_SESSION_HANDLE,
    next_handle: CK_OBJECT_HANDLE,
}

impl Implementation {
    pub fn new() -> Implementation {
        Implementation {
            sessions: BTreeSet::new(),
            searches: BTreeMap::new(),
            certs: BTreeMap::new(),
            next_session: 1,
            next_handle: 1,
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

    fn get_next_handle(&mut self) -> CK_OBJECT_HANDLE {
        let next_handle = self.next_handle;
        self.next_handle += 1;
        next_handle
    }

    pub fn find_certs(
        &mut self,
        session: CK_SESSION_HANDLE,
        expect_already_exists: bool,
    ) -> Option<&Vec<CK_OBJECT_HANDLE>> {
        if !self.searches.contains_key(&session) {
            if expect_already_exists {
                return None;
            }
            let certs = list_certs();
            let mut handles = Vec::with_capacity(certs.len());
            for cert in certs {
                let handle = self.get_next_handle();
                self.certs.insert(handle, cert);
                handles.push(handle);
            }
            self.searches.insert(session, handles);
        }
        self.searches.get(&session)
    }
}
