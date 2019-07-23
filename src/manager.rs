pub use crate::macos_backend::*;
use crate::types::*;

use std::collections::{BTreeMap, BTreeSet};

pub struct Manager {
    sessions: BTreeSet<CK_SESSION_HANDLE>,
    searches: BTreeMap<CK_SESSION_HANDLE, Vec<CK_OBJECT_HANDLE>>,
    certs: BTreeMap<CK_OBJECT_HANDLE, Cert>,
    next_session: CK_SESSION_HANDLE,
    next_handle: CK_OBJECT_HANDLE,
}

impl Manager {
    pub fn new() -> Manager {
        Manager {
            sessions: BTreeSet::new(),
            searches: BTreeMap::new(),
            certs: BTreeMap::new(),
            next_session: 1,
            next_handle: 1,
        }
    }

    pub fn open_session(&mut self) -> CK_SESSION_HANDLE {
        let certs = list_certs();
        for cert in certs {
            let handle = self.get_next_handle();
            self.certs.insert(handle, cert);
        }
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
        attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        expect_already_exists: bool,
    ) -> Option<&Vec<CK_OBJECT_HANDLE>> {
        if !self.searches.contains_key(&session) {
            if expect_already_exists {
                return None;
            }
            // TODO: so... we just keep making more certs here... should we have a Set that keeps
            // track?  Seems like multiple searches can happen in one session, but maybe not in
            // parallel? (otherwise how would that work). So we need to clear the previous search
            // when C_FindObjectsFinal gets called.
            let mut handles = Vec::new();
            for (handle, cert) in &self.certs {
                if cert_matches_attrs(cert, attrs) {
                    handles.push(*handle);
                }
            }
            self.searches.insert(session, handles);
        }
        self.searches.get(&session)
    }

    // uhhhh maybe there's a better way to do this (the reason for this is that I think we still
    // need to have an empty search if NSS asks us for something we don't have. Maybe we just need
    // to push the determination of what's a known attribute into the manager here rather than
    // making C_FindObjectsInit responsible for it?)
    pub fn start_empty_search(&mut self, session: CK_SESSION_HANDLE) {
        self.searches.insert(session, Vec::new());
    }

    pub fn clear_search(&mut self, session: CK_SESSION_HANDLE) {
        self.searches.remove(&session);
    }

    pub fn find_cert(&mut self, object_handle: CK_OBJECT_HANDLE) -> Option<&Cert> {
        self.certs.get(&object_handle)
    }
}

fn cert_matches_attrs(cert: &Cert, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
    eprintln!("cert_matches_attrs...");
    for (attr_type, attr_value) in attrs {
        match *attr_type {
            CKA_ISSUER => {
                eprintln!("{:?}", attr_value);
                eprintln!("{:?}", cert.issuer());
                if attr_value.as_slice() != cert.issuer() {
                    return false;
                }
            }
            CKA_SERIAL_NUMBER => {
                eprintln!("{:?}", attr_value);
                eprintln!("{:?}", cert.serial_number());
                if attr_value.as_slice() != cert.serial_number() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}
