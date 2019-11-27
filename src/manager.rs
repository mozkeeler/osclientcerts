/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use pkcs11::types::*;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(target_os = "macos")]
use crate::backend_macos as backend;
#[cfg(target_os = "windows")]
use crate::backend_windows as backend;
use backend::*;

use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

type ManagerArgumentsSender = Sender<ManagerFunctionArguments>;
type ManagerReturnValueReceiver = Receiver<ManagerReturnValue>;

enum ManagerFunctionArguments {
    OpenSession,
    CloseSession(CK_SESSION_HANDLE),
    CloseAllSessions,
    StartSearch(CK_SESSION_HANDLE, Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>),
    Search(CK_SESSION_HANDLE, usize),
    ClearSearch(CK_SESSION_HANDLE),
    GetAttributes(CK_OBJECT_HANDLE, Vec<CK_ATTRIBUTE_TYPE>),
    StartSign(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        Option<CK_RSA_PKCS_PSS_PARAMS>,
    ),
    GetSignatureLength(CK_SESSION_HANDLE, Vec<u8>),
    Sign(CK_SESSION_HANDLE, Vec<u8>),
}

enum ManagerReturnValue {
    OpenSession(CK_SESSION_HANDLE),
    CloseSession(Result<(), ()>),
    CloseAllSessions,
    StartSearch(Result<(), ()>),
    Search(Result<Vec<CK_OBJECT_HANDLE>, ()>),
    ClearSearch,
    GetAttributes(Result<Vec<Option<Vec<u8>>>, ()>),
    StartSign(Result<(), ()>),
    GetSignatureLength(Result<usize, ()>),
    Sign(Result<Vec<u8>, ()>),
}

pub struct ManagerProxy {
    sender: ManagerArgumentsSender,
    receiver: ManagerReturnValueReceiver,
}

impl ManagerProxy {
    pub fn new() -> ManagerProxy {
        let (proxy_sender, manager_receiver) = channel();
        let (manager_sender, proxy_receiver) = channel();
        thread::spawn(move || {
            let mut real_manager = Manager::new();
            loop {
                let arguments = match manager_receiver.recv() {
                    Ok(arguments) => arguments,
                    Err(e) => {
                        error!("error recv()ing arguments from ManagerProxy: {}", e);
                        break;
                    }
                };
                let results = match arguments {
                    ManagerFunctionArguments::OpenSession => {
                        ManagerReturnValue::OpenSession(real_manager.open_session())
                    }
                    ManagerFunctionArguments::CloseSession(session_handle) => {
                        ManagerReturnValue::CloseSession(real_manager.close_session(session_handle))
                    }
                    ManagerFunctionArguments::CloseAllSessions => {
                        real_manager.close_all_sessions();
                        ManagerReturnValue::CloseAllSessions
                    }
                    ManagerFunctionArguments::StartSearch(session, attrs) => {
                        ManagerReturnValue::StartSearch(real_manager.start_search(session, &attrs))
                    }
                    ManagerFunctionArguments::Search(session, max_objects) => {
                        ManagerReturnValue::Search(real_manager.search(session, max_objects))
                    }
                    ManagerFunctionArguments::ClearSearch(session) => {
                        real_manager.clear_search(session);
                        ManagerReturnValue::ClearSearch
                    }
                    ManagerFunctionArguments::GetAttributes(object_handle, attr_types) => {
                        ManagerReturnValue::GetAttributes(
                            real_manager.get_attributes(object_handle, attr_types),
                        )
                    }
                    ManagerFunctionArguments::StartSign(session, key_handle, params) => {
                        ManagerReturnValue::StartSign(
                            real_manager.start_sign(session, key_handle, params),
                        )
                    }
                    ManagerFunctionArguments::GetSignatureLength(session, data) => {
                        ManagerReturnValue::GetSignatureLength(
                            real_manager.get_signature_length(session, &data),
                        )
                    }
                    ManagerFunctionArguments::Sign(session, data) => {
                        ManagerReturnValue::Sign(real_manager.sign(session, &data))
                    }
                };
                match manager_sender.send(results) {
                    Ok(()) => {}
                    Err(e) => {
                        error!("error send()ing results from Manager: {}", e);
                        break;
                    }
                }
            }
        });
        ManagerProxy {
            sender: proxy_sender,
            receiver: proxy_receiver,
        }
    }

    fn proxy_call(&self, args: ManagerFunctionArguments) -> Result<ManagerReturnValue, ()> {
        match self.sender.send(args) {
            Ok(()) => {}
            Err(e) => {
                error!("error send()ing arguments to Manager: {}", e);
                return Err(());
            }
        };
        let result = match self.receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                error!("error recv()ing result from Manager: {}", e);
                return Err(());
            }
        };
        Ok(result)
    }

    pub fn open_session(&mut self) -> Result<CK_SESSION_HANDLE, ()> {
        match self.proxy_call(ManagerFunctionArguments::OpenSession) {
            Ok(ManagerReturnValue::OpenSession(session_handle)) => Ok(session_handle),
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(())
            }
            Err(()) => Err(()),
        }
    }

    pub fn close_session(&mut self, session: CK_SESSION_HANDLE) -> Result<(), ()> {
        match self.proxy_call(ManagerFunctionArguments::CloseSession(session)) {
            Ok(ManagerReturnValue::CloseSession(result)) => result,
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(())
            }
            Err(()) => Err(()),
        }
    }

    pub fn close_all_sessions(&mut self) -> Result<(), ()> {
        match self.proxy_call(ManagerFunctionArguments::CloseAllSessions) {
            Ok(ManagerReturnValue::CloseAllSessions) => Ok(()),
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(())
            }
            Err(()) => Err(()),
        }
    }

    pub fn start_search(
        &mut self,
        session: CK_SESSION_HANDLE,
        attrs: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>,
    ) -> Result<(), ()> {
        match self.proxy_call(ManagerFunctionArguments::StartSearch(session, attrs)) {
            Ok(ManagerReturnValue::StartSearch(result)) => result,
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(())
            }
            Err(()) => Err(()),
        }
    }

    pub fn search(
        &mut self,
        session: CK_SESSION_HANDLE,
        max_objects: usize,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, ()> {
        match self.proxy_call(ManagerFunctionArguments::Search(session, max_objects)) {
            Ok(ManagerReturnValue::Search(result)) => result,
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(())
            }
            Err(()) => Err(()),
        }
    }

    pub fn clear_search(&mut self, session: CK_SESSION_HANDLE) -> Result<(), ()> {
        match self.proxy_call(ManagerFunctionArguments::ClearSearch(session)) {
            Ok(ManagerReturnValue::ClearSearch) => Ok(()),
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(())
            }
            Err(()) => Err(()),
        }
    }

    pub fn get_attributes(
        &self,
        object_handle: CK_OBJECT_HANDLE,
        attr_types: Vec<CK_ATTRIBUTE_TYPE>,
    ) -> Result<Vec<Option<Vec<u8>>>, ()> {
        match self.proxy_call(ManagerFunctionArguments::GetAttributes(
            object_handle,
            attr_types,
        )) {
            Ok(ManagerReturnValue::GetAttributes(result)) => result,
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(())
            }
            Err(()) => Err(()),
        }
    }

    pub fn start_sign(
        &mut self,
        session: CK_SESSION_HANDLE,
        key_handle: CK_OBJECT_HANDLE,
        params: Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<(), ()> {
        match self.proxy_call(ManagerFunctionArguments::StartSign(
            session, key_handle, params,
        )) {
            Ok(ManagerReturnValue::StartSign(result)) => result,
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(())
            }
            Err(()) => Err(()),
        }
    }

    pub fn get_signature_length(
        &self,
        session: CK_SESSION_HANDLE,
        data: Vec<u8>,
    ) -> Result<usize, ()> {
        match self.proxy_call(ManagerFunctionArguments::GetSignatureLength(session, data)) {
            Ok(ManagerReturnValue::GetSignatureLength(result)) => result,
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(())
            }
            Err(()) => Err(()),
        }
    }

    pub fn sign(&mut self, session: CK_SESSION_HANDLE, data: Vec<u8>) -> Result<Vec<u8>, ()> {
        match self.proxy_call(ManagerFunctionArguments::Sign(session, data)) {
            Ok(ManagerReturnValue::Sign(result)) => result,
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(())
            }
            Err(()) => Err(()),
        }
    }
}

/// The `Manager` keeps track of the state of this module with respect to the PKCS #11
/// specification. This includes what sessions are open, which search and sign operations are
/// ongoing, and what objects are known and by what handle.
struct Manager {
    /// A set of sessions. Sessions can be created (opened) and later closed.
    sessions: BTreeSet<CK_SESSION_HANDLE>,
    /// A map of searches to PKCS #11 object handles that match those searches.
    searches: BTreeMap<CK_SESSION_HANDLE, Vec<CK_OBJECT_HANDLE>>,
    /// A map of sign operations to a pair of the object handle and optionally some params being
    /// used by each one.
    signs: BTreeMap<CK_SESSION_HANDLE, (CK_OBJECT_HANDLE, Option<CK_RSA_PKCS_PSS_PARAMS>)>,
    /// A map of object handles to the underlying objects.
    objects: BTreeMap<CK_OBJECT_HANDLE, Object>,
    /// A set of certificate identifiers (not the same as handles).
    cert_ids: BTreeSet<Vec<u8>>,
    /// A set of key identifiers (not the same as handles). For each id in this set, there should be
    /// a corresponding identical id in the `cert_ids` set, and vice-versa.
    key_ids: BTreeSet<Vec<u8>>,
    /// The next session handle to hand out.
    next_session: CK_SESSION_HANDLE,
    /// The next object handle to hand out.
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

    /// When a new `Manager` is created and when a new session is opened, this searches for
    /// certificates and keys to expose. We de-duplicate previously-found certificates and keys by
    /// keeping track of their IDs.
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

    /// PKCS #11 specifies that search operations happen in three phases: setup, get any matches
    /// (this part may be repeated if the caller uses a small buffer), and end. This implementation
    /// does all of the work up front and gathers all matching objects during setup and retains them
    /// until they are retrieved and consumed via `search`.
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

    /// Given a session and a maximum number of object handles to return, attempts to retrieve up to
    /// that many objects from the corresponding search. Updates the search so those objects are not
    /// returned repeatedly. `max_objects` must be non-zero.
    pub fn search(
        &mut self,
        session: CK_SESSION_HANDLE,
        max_objects: usize,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, ()> {
        if max_objects == 0 {
            return Err(());
        }
        match self.searches.get_mut(&session) {
            Some(search) => {
                let split_at = if max_objects >= search.len() {
                    0
                } else {
                    search.len() - max_objects
                };
                let to_return = search.split_off(split_at);
                if to_return.len() > max_objects {
                    error!(
                        "search trying to return too many handles: {} > {}",
                        to_return.len(),
                        max_objects
                    );
                    return Err(());
                }
                Ok(to_return)
            }
            None => Err(()),
        }
    }

    pub fn clear_search(&mut self, session: CK_SESSION_HANDLE) {
        self.searches.remove(&session);
    }

    pub fn get_attributes(
        &self,
        object_handle: CK_OBJECT_HANDLE,
        attr_types: Vec<CK_ATTRIBUTE_TYPE>,
    ) -> Result<Vec<Option<Vec<u8>>>, ()> {
        let object = match self.objects.get(&object_handle) {
            Some(object) => object,
            None => return Err(()),
        };
        let mut results = Vec::with_capacity(attr_types.len());
        for attr_type in attr_types {
            let result = match object.get_attribute(attr_type) {
                Some(value) => Some(value.to_owned()),
                None => None,
            };
            results.push(result);
        }
        Ok(results)
    }

    /// The way NSS uses PKCS #11 to sign data happens in two phases: setup and sign. This
    /// implementation makes a note of which key is to be used (if it exists) during setup. When the
    /// caller finishes with the sign operation, this implementation retrieves the key handle and
    /// performs the signature.
    pub fn start_sign(
        &mut self,
        session: CK_SESSION_HANDLE,
        key_handle: CK_OBJECT_HANDLE,
        params: Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<(), ()> {
        if self.signs.contains_key(&session) {
            return Err(());
        }
        match self.objects.get(&key_handle) {
            Some(Object::Key(_)) => {}
            _ => return Err(()),
        };
        self.signs.insert(session, (key_handle, params));
        Ok(())
    }

    pub fn get_signature_length(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<usize, ()> {
        let (key_handle, params) = match self.signs.get(&session) {
            Some((key_handle, params)) => (key_handle, params),
            None => return Err(()),
        };
        let key = match self.objects.get(&key_handle) {
            Some(Object::Key(key)) => key,
            _ => return Err(()),
        };
        key.get_signature_length(data, params)
    }

    pub fn sign(&mut self, session: CK_SESSION_HANDLE, data: &[u8]) -> Result<Vec<u8>, ()> {
        // Performing the signature (via C_Sign, which is the only way we support) finishes the sign
        // operation, so it needs to be removed here.
        let (key_handle, params) = match self.signs.remove(&session) {
            Some((key_handle, params)) => (key_handle, params),
            None => return Err(()),
        };
        let key = match self.objects.get(&key_handle) {
            Some(Object::Key(key)) => key,
            _ => return Err(()),
        };
        key.sign(data, &params)
    }
}
