use std::collections::{BTreeMap, BTreeSet};

#[cfg(target_os = "macos")]
use crate::backend_macos as backend;
#[cfg(target_os = "windows")]
use crate::backend_windows as backend;
use crate::types::*;
use backend::*;

pub struct Manager {
    sessions: BTreeSet<CK_SESSION_HANDLE>,
    searches: BTreeMap<CK_SESSION_HANDLE, Vec<CK_OBJECT_HANDLE>>,
    signs: BTreeMap<CK_SESSION_HANDLE, CK_OBJECT_HANDLE>,
    objects: BTreeMap<CK_OBJECT_HANDLE, Object>,
    cert_ids: BTreeSet<Vec<u8>>,
    key_ids: BTreeSet<Vec<u8>>,
    next_session: CK_SESSION_HANDLE,
    next_handle: CK_OBJECT_HANDLE,
}

impl Manager {
    pub fn new() -> Manager {
        let mut manager = Manager {
            sessions: BTreeSet::new(),
            searches: BTreeMap::new(),
            signs: BTreeMap::new(),
            objects: BTreeMap::new(),
            cert_ids: BTreeSet::new(),
            key_ids: BTreeSet::new(),
            next_session: 1,
            next_handle: 1,
        };
        manager.find_new_objects();
        manager
    }

    fn find_new_objects(&mut self) {
        let objects = list_objects();
        debug!("found {} objects", objects.len());
        for object in objects {
            match &object {
                Object::Cert(cert) => {
                    if self.cert_ids.contains(cert.id()) {
                        continue;
                    }
                    self.cert_ids.insert(cert.id().to_vec());
                    let handle = self.get_next_handle();
                    self.objects.insert(handle, object);
                }
                Object::Key(key) => {
                    if self.key_ids.contains(key.id()) {
                        continue;
                    }
                    self.key_ids.insert(key.id().to_vec());
                    let handle = self.get_next_handle();
                    self.objects.insert(handle, object);
                }
            }
        }
    }

    pub fn open_session(&mut self) -> CK_SESSION_HANDLE {
        self.find_new_objects();
        let next_session = self.next_session;
        self.next_session += 1;
        self.sessions.insert(next_session);
        next_session
    }

    pub fn close_session(&mut self, session: CK_SESSION_HANDLE) -> Result<(), ()> {
        if self.sessions.remove(&session) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn close_all_sessions(&mut self) {
        self.sessions.clear();
    }

    fn get_next_handle(&mut self) -> CK_OBJECT_HANDLE {
        let next_handle = self.next_handle;
        self.next_handle += 1;
        next_handle
    }

    pub fn start_search(
        &mut self,
        session: CK_SESSION_HANDLE,
        attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<(), ()> {
        if self.searches.contains_key(&session) {
            return Err(());
        }
        let mut handles = Vec::new();
        for (handle, object) in &self.objects {
            if object.matches(attrs) {
                handles.push(*handle);
            }
        }
        self.searches.insert(session, handles);
        Ok(())
    }

    pub fn search(&self, session: CK_SESSION_HANDLE) -> Result<&Vec<CK_OBJECT_HANDLE>, ()> {
        match self.searches.get(&session) {
            Some(search) => Ok(search),
            None => Err(()),
        }
    }

    pub fn clear_search(&mut self, session: CK_SESSION_HANDLE) {
        self.searches.remove(&session);
    }

    pub fn get_object(&mut self, object_handle: CK_OBJECT_HANDLE) -> Result<&Object, ()> {
        match self.objects.get(&object_handle) {
            Some(object) => Ok(object),
            None => Err(()),
        }
    }

    pub fn start_sign(
        &mut self,
        session: CK_SESSION_HANDLE,
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), ()> {
        // TODO: per the spec, can we have multiple signs for the same session
        // but different keys?
        if self.signs.contains_key(&session) {
            return Err(());
        }
        let key = match self.objects.get(&key_handle) {
            Some(Object::Key(key)) => key,
            _ => return Err(()),
        };
        self.signs.insert(session, key_handle);
        Ok(())
    }

    pub fn sign(&self, session: CK_SESSION_HANDLE, data: &[u8]) -> Result<Vec<u8>, ()> {
        let key_handle = match self.signs.get(&session) {
            Some(key_handle) => key_handle,
            None => return Err(()),
        };
        let key = match self.objects.get(&key_handle) {
            Some(Object::Key(key)) => key,
            _ => return Err(()),
        };
        key.sign(data)
    }
}
