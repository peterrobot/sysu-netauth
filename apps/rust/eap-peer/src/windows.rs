//! EAPHost ABI: callers own valid pointers for the sizes specified by the SDK.
#![allow(clippy::too_many_arguments)]

use super::{Action, CONNECTION_DATA, Credentials, Peer, wipe};
use std::{collections::BTreeMap, ffi::c_void, ptr, sync::Mutex};
use windows_sys::Win32::{
    Foundation::*,
    Security::ExtensibleAuthenticationProtocol::*,
    System::{Com::CoTaskMemFree, Memory::*},
    UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
};

struct Sessions {
    next: usize,
    peers: BTreeMap<usize, Peer>,
}
static SESSIONS: Mutex<Sessions> = Mutex::new(Sessions {
    next: 1,
    peers: BTreeMap::new(),
});
static METHOD: EAP_TYPE = EAP_TYPE {
    r#type: 4,
    dwVendorId: 0,
    dwVendorType: 0,
};

unsafe fn clear_error(error: *mut *mut EAP_ERROR) {
    if !error.is_null() {
        unsafe { error.write(ptr::null_mut()) };
    }
}

unsafe fn connection_valid(len: u32, data: *const u8) -> bool {
    len as usize == CONNECTION_DATA.len()
        && !data.is_null()
        && unsafe { std::slice::from_raw_parts(data, len as usize) } == CONNECTION_DATA
}

// All outgoing buffers use the same allocator and are released by our export.
unsafe fn allocate(bytes: &[u8]) -> Result<*mut u8, u32> {
    let data =
        unsafe { HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes.len().max(1)) }.cast::<u8>();
    if data.is_null() {
        return Err(ERROR_NOT_ENOUGH_MEMORY);
    }
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), data, bytes.len()) };
    Ok(data)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn EapPeerFreeMemory(data: *mut c_void) {
    if !data.is_null() {
        let heap = unsafe { GetProcessHeap() };
        let size = unsafe { HeapSize(heap, 0, data) };
        if size != usize::MAX {
            wipe(unsafe { std::slice::from_raw_parts_mut(data.cast::<u8>(), size) });
            unsafe { HeapFree(heap, 0, data) };
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn EapPeerFreeErrorMemory(_error: *mut EAP_ERROR) {
    // This method returns Win32 errors and always sets ppEapError to NULL.
}

fn load_credentials() -> Result<Credentials, u32> {
    // The known folder API prevents environment overrides inside the host service.
    let mut folder = ptr::null_mut();
    let hr =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut folder) };
    if hr < 0 {
        return Err(ERROR_PATH_NOT_FOUND);
    }
    let path = unsafe {
        let mut len = 0;
        while *folder.add(len) != 0 {
            len += 1;
        }
        let path = std::path::PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(
            folder, len,
        )));
        CoTaskMemFree(folder.cast());
        path.join("SYSUNetAuth")
            .join("EapHost")
            .join("credentials.json")
    };
    let credentials: Credentials =
        netauth::config::read(&path).map_err(|_| ERROR_CANT_ACCESS_FILE)?;
    credentials.validate().map_err(|_| ERROR_INVALID_DATA)?;
    Ok(credentials)
}

unsafe fn credentials(len: u32, data: *const u8) -> Result<Credentials, u32> {
    if len == 0 {
        return load_credentials();
    }
    if data.is_null() || len > 8192 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let credentials: Credentials =
        serde_json::from_slice(unsafe { std::slice::from_raw_parts(data, len as usize) })
            .map_err(|_| ERROR_INVALID_DATA)?;
    credentials.validate().map_err(|_| ERROR_INVALID_DATA)?;
    Ok(credentials)
}

unsafe extern "system" fn initialize(error: *mut *mut EAP_ERROR) -> u32 {
    unsafe { clear_error(error) };
    ERROR_SUCCESS
}

unsafe extern "system" fn get_identity(
    _flags: u32,
    config_len: u32,
    config: *const u8,
    user_len: u32,
    user: *const u8,
    _token: HANDLE,
    invoke_ui: *mut i32,
    out_len: *mut u32,
    out: *mut *mut u8,
    identity: *mut *mut u16,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    if invoke_ui.is_null() || out_len.is_null() || out.is_null() || identity.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    unsafe {
        invoke_ui.write(0);
        out_len.write(0);
        out.write(ptr::null_mut());
        identity.write(ptr::null_mut());
    }
    if !unsafe { connection_valid(config_len, config) } {
        return ERROR_INVALID_DATA;
    }
    let credentials = match unsafe { credentials(user_len, user) } {
        Ok(c) => c,
        Err(e) => return e,
    };
    let wide: Vec<u16> = credentials.username.encode_utf16().chain(Some(0)).collect();
    let identity_buffer = match unsafe {
        allocate(std::slice::from_raw_parts(
            wide.as_ptr().cast::<u8>(),
            wide.len() * 2,
        ))
    } {
        Ok(p) => p,
        Err(e) => return e,
    };
    // Snapshot the credentials so BeginSession uses the same identity. EAPHost
    // receives no instruction to persist this transient user blob.
    let mut blob = match serde_json::to_vec(&credentials) {
        Ok(blob) => blob,
        Err(_) => {
            unsafe { EapPeerFreeMemory(identity_buffer.cast()) };
            return ERROR_INVALID_DATA;
        }
    };
    let user_buffer = unsafe { allocate(&blob) };
    let blob_len = blob.len() as u32;
    wipe(&mut blob);
    match user_buffer {
        Ok(p) => unsafe {
            out.write(p);
            out_len.write(blob_len);
            identity.write(identity_buffer.cast());
        },
        Err(e) => {
            unsafe { EapPeerFreeMemory(identity_buffer.cast()) };
            return e;
        }
    }
    ERROR_SUCCESS
}

unsafe extern "system" fn begin_session(
    _flags: u32,
    _attributes: *const EAP_ATTRIBUTES,
    _token: HANDLE,
    config_len: u32,
    config: *mut u8,
    user_len: u32,
    user: *mut u8,
    max_packet: u32,
    session: *mut *mut c_void,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    if session.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    unsafe { session.write(ptr::null_mut()) };
    if !unsafe { connection_valid(config_len, config) } {
        return ERROR_INVALID_DATA;
    }
    let credentials = match unsafe { credentials(user_len, user) } {
        Ok(c) => c,
        Err(e) => return e,
    };
    let peer = match Peer::new(credentials, max_packet as usize) {
        Ok(p) => p,
        Err(_) => return ERROR_INVALID_DATA,
    };
    let Ok(mut sessions) = SESSIONS.lock() else {
        return ERROR_INTERNAL_ERROR;
    };
    if sessions.peers.len() >= 64 || sessions.next == usize::MAX {
        return ERROR_TOO_MANY_SESS;
    }
    let id = sessions.next;
    sessions.next += 1;
    sessions.peers.insert(id, peer);
    unsafe { session.write(id as *mut c_void) };
    ERROR_SUCCESS
}

unsafe extern "system" fn set_credentials(
    _session: *mut c_void,
    _identity: *mut u16,
    _password: *mut u16,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    // GetIdentity supplies credentials; Windows' built-in dialogs are disabled.
    ERROR_NOT_SUPPORTED
}

unsafe extern "system" fn process_request(
    session: *mut c_void,
    len: u32,
    packet: *mut EapPacket,
    output: *mut EapPeerMethodOutput,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    if output.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    unsafe { output.write(EapPeerMethodOutput::default()) };
    if packet.is_null() || len > netauth::protocol::MAX_FRAME as u32 || len < 4 {
        return ERROR_INVALID_PARAMETER;
    }
    let Ok(mut sessions) = SESSIONS.lock() else {
        return ERROR_INTERNAL_ERROR;
    };
    let Some(peer) = sessions.peers.get_mut(&(session as usize)) else {
        return ERROR_INVALID_HANDLE;
    };
    let action =
        peer.process(unsafe { std::slice::from_raw_parts(packet.cast::<u8>(), len as usize) });
    unsafe {
        (*output).action = match action {
            Action::Discard => EapPeerMethodResponseActionDiscard,
            Action::Send => EapPeerMethodResponseActionSend,
            Action::Result => EapPeerMethodResponseActionResult,
        };
    }
    ERROR_SUCCESS
}

unsafe extern "system" fn get_response(
    session: *mut c_void,
    len: *mut u32,
    packet: *mut EapPacket,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    if len.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let capacity = unsafe { *len };
    unsafe { len.write(0) };
    let Ok(sessions) = SESSIONS.lock() else {
        return ERROR_INTERNAL_ERROR;
    };
    let Some(peer) = sessions.peers.get(&(session as usize)) else {
        return ERROR_INVALID_HANDLE;
    };
    if peer.response().is_empty() {
        return ERROR_INVALID_STATE;
    }
    let needed = peer.response().len();
    unsafe { len.write(needed as u32) };
    if capacity < needed as u32 {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    if packet.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    unsafe { ptr::copy_nonoverlapping(peer.response().as_ptr(), packet.cast::<u8>(), needed) };
    ERROR_SUCCESS
}

unsafe extern "system" fn get_result(
    session: *mut c_void,
    reason: EapPeerMethodResultReason,
    result: *mut EapPeerMethodResult,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    if result.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    unsafe { result.write(EapPeerMethodResult::default()) };
    if ![
        EapPeerMethodResultUnknown,
        EapPeerMethodResultSuccess,
        EapPeerMethodResultFailure,
    ]
    .contains(&reason)
    {
        return ERROR_INVALID_PARAMETER;
    }
    let Ok(sessions) = SESSIONS.lock() else {
        return ERROR_INTERNAL_ERROR;
    };
    let Some(peer) = sessions.peers.get(&(session as usize)) else {
        return ERROR_INVALID_HANDLE;
    };
    let success =
        reason != EapPeerMethodResultFailure && peer.result(reason == EapPeerMethodResultSuccess);
    unsafe {
        (*result).fIsSuccess = i32::from(success);
        (*result).dwFailureReasonCode = if success { 0 } else { ERROR_ACCESS_DENIED };
    }
    ERROR_SUCCESS
}

unsafe extern "system" fn get_ui(
    _session: *mut c_void,
    len: *mut u32,
    data: *mut *mut u8,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    if !len.is_null() {
        unsafe { len.write(0) };
    }
    if !data.is_null() {
        unsafe { data.write(ptr::null_mut()) };
    }
    ERROR_NOT_SUPPORTED
}

unsafe extern "system" fn set_ui(
    _session: *mut c_void,
    _len: u32,
    _data: *const u8,
    output: *mut EapPeerMethodOutput,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    if !output.is_null() {
        unsafe { output.write(EapPeerMethodOutput::default()) };
    }
    ERROR_NOT_SUPPORTED
}

unsafe extern "system" fn get_attributes(
    _session: *mut c_void,
    attributes: *mut EAP_ATTRIBUTES,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    if !attributes.is_null() {
        unsafe { attributes.write(std::mem::zeroed()) };
    }
    ERROR_NOT_SUPPORTED
}

unsafe extern "system" fn set_attributes(
    _session: *mut c_void,
    _attributes: *mut EAP_ATTRIBUTES,
    output: *mut EapPeerMethodOutput,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    if !output.is_null() {
        unsafe { output.write(EapPeerMethodOutput::default()) };
    }
    ERROR_NOT_SUPPORTED
}

unsafe extern "system" fn end_session(session: *mut c_void, error: *mut *mut EAP_ERROR) -> u32 {
    unsafe { clear_error(error) };
    let Ok(mut sessions) = SESSIONS.lock() else {
        return ERROR_INTERNAL_ERROR;
    };
    if sessions.peers.remove(&(session as usize)).is_none() {
        return ERROR_INVALID_HANDLE;
    }
    ERROR_SUCCESS
}

unsafe extern "system" fn shutdown(error: *mut *mut EAP_ERROR) -> u32 {
    unsafe { clear_error(error) };
    let Ok(mut sessions) = SESSIONS.lock() else {
        return ERROR_INTERNAL_ERROR;
    };
    sessions.peers.clear();
    ERROR_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn EapPeerGetInfo(
    method: *mut EAP_TYPE,
    info: *mut EAP_PEER_METHOD_ROUTINES,
    error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(error) };
    if info.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    unsafe { info.write(EAP_PEER_METHOD_ROUTINES::default()) };
    if method.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let method = unsafe { &*method };
    if method.r#type != 4 || method.dwVendorId != 0 || method.dwVendorType != 0 {
        return ERROR_NOT_SUPPORTED;
    }
    unsafe {
        info.write(EAP_PEER_METHOD_ROUTINES {
            dwVersion: 1,
            pEapType: (&METHOD as *const EAP_TYPE).cast_mut(),
            EapPeerInitialize: initialize as *const () as isize,
            EapPeerGetIdentity: get_identity as *const () as isize,
            EapPeerBeginSession: begin_session as *const () as isize,
            EapPeerSetCredentials: set_credentials as *const () as isize,
            EapPeerProcessRequestPacket: process_request as *const () as isize,
            EapPeerGetResponsePacket: get_response as *const () as isize,
            EapPeerGetResult: get_result as *const () as isize,
            EapPeerGetUIContext: get_ui as *const () as isize,
            EapPeerSetUIContext: set_ui as *const () as isize,
            EapPeerGetResponseAttributes: get_attributes as *const () as isize,
            EapPeerSetResponseAttributes: set_attributes as *const () as isize,
            EapPeerEndSession: end_session as *const () as isize,
            EapPeerShutdown: shutdown as *const () as isize,
        });
    }
    ERROR_SUCCESS
}
