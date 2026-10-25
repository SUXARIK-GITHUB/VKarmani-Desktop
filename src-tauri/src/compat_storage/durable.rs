//! Windows native authority. No production AppData is opened by the tests.
use super::*;

pub(crate) const V2_NAME: &str = "client-state-v2.dpapi";
pub(crate) const V2_PLAIN_LIMIT: u64 = 12 * 1024 * 1024;
pub(crate) const V2_CIPHER_LIMIT: u64 = 36 * 1024 * 1024;
const OPERATION_WINDOW: usize = 64;
const V2_MARKER: &str = "VKARMANI_STATE_V2";
type StateResult<T> = Result<T, StateStorageError>;

fn failure(code: &'static str) -> StateStorageError {
    StateStorageError::new(
        code,
        "Операция с сохранённым состоянием не завершена. Оригиналы сохранены; проверьте хранилище.",
        true,
    )
}

pub(crate) fn random_state_id() -> StateResult<String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        let mut bytes = [0u8; 24];
        if unsafe {
            BCryptGenRandom(
                null_mut(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } < 0
        {
            return Err(failure("STATE_RANDOM_FAILED"));
        }
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
    #[cfg(not(windows))]
    {
        Err(failure("STATE_PLATFORM_UNSUPPORTED"))
    }
}

#[derive(Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DurablePayload {
    #[serde(rename = "public")]
    pub(crate) public_state: serde_json::Map<String, Value>,
    pub(crate) protected: serde_json::Map<String, Value>,
    pub(crate) access_key: Option<String>,
    #[serde(with = "decimal_u64")]
    pub(crate) session_generation: u64,
    pub(crate) legacy_web_view: Option<serde_json::Map<String, Value>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationReceipt {
    id: String,
    hash: String,
    revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    generation: String,
    revision: u64,
    updated_at: String,
    payload: DurablePayload,
    operations: Vec<OperationReceipt>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DurableSnapshot {
    pub(crate) schema_version: u32,
    pub(crate) generation: String,
    // Decimal strings preserve exact u64 values across the WebView boundary.
    pub(crate) revision: String,
    pub(crate) updated_at: String,
    pub(crate) payload: DurablePayload,
    pub(crate) read_only: bool,
    pub(crate) recovery_token: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StateChange {
    pub(crate) scope: String,
    pub(crate) key: String,
    pub(crate) value: Option<Value>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StatePatch {
    pub(crate) generation: String,
    pub(crate) expected_revision: String,
    pub(crate) expected_session_generation: String,
    pub(crate) operation_id: String,
    pub(crate) changes: Vec<StateChange>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StateCommit {
    pub(crate) snapshot: DurableSnapshot,
    pub(crate) deduplicated: bool,
}

struct Loaded {
    envelope: Envelope,
    ciphertext: Option<String>,
    recovery_token: Option<String>,
    corrupt_primary: Option<Vec<u8>>,
}
impl Loaded {
    fn snapshot(&self) -> DurableSnapshot {
        DurableSnapshot {
            schema_version: 2,
            generation: self.envelope.generation.clone(),
            revision: self.envelope.revision.to_string(),
            updated_at: self.envelope.updated_at.clone(),
            payload: self.envelope.payload.clone(),
            read_only: self.recovery_token.is_some(),
            recovery_token: self.recovery_token.clone(),
        }
    }
}

struct WriterLease {
    #[cfg(windows)]
    file: File,
    _parents: Vec<File>,
}
impl WriterLease {
    #[cfg(windows)]
    fn acquire(root: &Path) -> StateResult<Self> {
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        use windows_sys::Win32::{Storage::FileSystem::*, System::IO::OVERLAPPED};
        let parents = state_directory_guards(root, true).map_err(StateStorageError::io)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(root.join("state-v2.writer.lock"))
            .map_err(StateStorageError::io)?;
        check_state_file(&file).map_err(StateStorageError::io)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            if unsafe {
                LockFileEx(
                    file.as_raw_handle().cast(),
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    1,
                    0,
                    &mut overlapped,
                )
            } != 0
            {
                return Ok(Self {
                    file,
                    _parents: parents,
                });
            }
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(32 | 33)) {
                return Err(StateStorageError::io(error));
            }
            if Instant::now() >= deadline {
                return Err(failure("STATE_WRITER_BUSY"));
            }
            // Bounded wait for a proven lock, never retry ACL/path/decryption errors.
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[cfg(not(windows))]
    fn acquire(_root: &Path) -> StateResult<Self> {
        Err(failure("STATE_PLATFORM_UNSUPPORTED"))
    }
}
impl Drop for WriterLease {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{Storage::FileSystem::UnlockFileEx, System::IO::OVERLAPPED};
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            // Closing this exact owned handle also releases its lock on failure.
            unsafe {
                UnlockFileEx(self.file.as_raw_handle().cast(), 0, 1, 0, &mut overlapped);
            }
        }
    }
}

pub(crate) struct DurableStore {
    root: PathBuf,
}
impl DurableStore {
    pub(crate) fn at(root: PathBuf) -> Self {
        Self { root }
    }
    fn primary(&self) -> PathBuf {
        self.root.join(V2_NAME)
    }
    fn backup(&self) -> PathBuf {
        self.root.join(format!("{V2_NAME}.lkg.dpapi"))
    }
    fn read_bytes(&self, path: &Path) -> StateResult<Option<Vec<u8>>> {
        read_state_bytes(path, V2_CIPHER_LIMIT).map_err(StateStorageError::io)
    }
    fn write(&self, path: &Path, ciphertext: &str) -> StateResult<()> {
        atomic_write_state_text_with_limit(path, ciphertext, V2_CIPHER_LIMIT)
            .map_err(|error| StateStorageError::write_io(error, "STATE_WRITE_FAILED"))
    }
    pub(crate) fn load(&self) -> StateResult<DurableSnapshot> {
        let _lease = WriterLease::acquire(&self.root)?;
        Ok(self.load_locked()?.snapshot())
    }
    fn load_locked(&self) -> StateResult<Loaded> {
        let primary = self.read_bytes(&self.primary())?;
        if let Some(raw) = primary.as_ref() {
            match decode_envelope(raw) {
                Ok((envelope, ciphertext)) => {
                    self.preserve_rollback_originals(raw)?;
                    return Ok(Loaded {
                        envelope,
                        ciphertext: Some(ciphertext),
                        recovery_token: None,
                        corrupt_primary: None,
                    });
                }
                Err(error) if error.code == "STATE_UNSUPPORTED_SCHEMA" => return Err(error),
                Err(_) => {}
            }
        }
        let backup = self.read_bytes(&self.backup())?;
        if let Some(raw) = backup.as_ref() {
            let (envelope, ciphertext) =
                decode_envelope(raw).map_err(|_| failure("STATE_BACKUP_CORRUPT"))?;
            return Ok(Loaded {
                envelope,
                ciphertext: Some(ciphertext),
                recovery_token: Some(recovery_digest(primary.as_deref(), raw)),
                corrupt_primary: primary,
            });
        }
        if primary.is_some() {
            return Err(failure("STATE_CORRUPT"));
        }
        self.migrate_legacy_locked()
    }
    fn preserve_rollback_originals(&self, primary: &[u8]) -> StateResult<()> {
        // One immutable encrypted pre-rollback snapshot. Normal v2 primary/LKG
        // continue their existing transaction semantics; originals stay recoverable.
        let directory = self.root.join("rollback-083-originals");
        let _guards = state_directory_guards(&directory, true).map_err(StateStorageError::io)?;
        let manifest = directory.join("COMPLETE.json");
        let names = [
            V2_NAME,
            "client-state-v2.dpapi.lkg.dpapi",
            "state-v2.initialized",
        ];
        if let Some(text) = read_state_file(&manifest, 4096).map_err(StateStorageError::io)? {
            let receipt: serde_json::Map<String, Value> =
                serde_json::from_str(&text).map_err(|_| failure("STATE_ORIGINALS_INVALID"))?;
            if receipt.len() != names.len() {
                return Err(failure("STATE_ORIGINALS_INVALID"));
            }
            for name in names {
                let expected = receipt
                    .get(name)
                    .ok_or_else(|| failure("STATE_ORIGINALS_INVALID"))?;
                let actual = read_state_bytes(&directory.join(name), V2_CIPHER_LIMIT)
                    .map_err(StateStorageError::io)?;
                match (expected.as_str(), expected.is_null(), actual) {
                    (Some(hash), _, Some(bytes)) if hash == sha256_hex_bytes(&bytes) => {}
                    (None, true, None) => {}
                    _ => return Err(failure("STATE_ORIGINALS_INVALID")),
                }
            }
            return Ok(());
        }
        let sources = [
            Some(primary.to_vec()),
            self.read_bytes(&self.backup())?,
            read_state_bytes(&self.root.join("state-v2.initialized"), 64)
                .map_err(StateStorageError::io)?,
        ];
        let mut receipt = serde_json::Map::new();
        for (name, source) in names.into_iter().zip(sources) {
            let target = directory.join(name);
            let existing =
                read_state_bytes(&target, V2_CIPHER_LIMIT).map_err(StateStorageError::io)?;
            if let Some(bytes) = source {
                if let Some(saved) = existing {
                    if saved != bytes {
                        return Err(failure("STATE_ORIGINALS_CONFLICT"));
                    }
                } else {
                    write_new_owned_bytes(&target, &bytes)?;
                }
                receipt.insert(name.into(), Value::String(sha256_hex_bytes(&bytes)));
            } else {
                if existing.is_some() {
                    return Err(failure("STATE_ORIGINALS_CONFLICT"));
                }
                receipt.insert(name.into(), Value::Null);
            }
        }
        write_new_owned_text(&manifest, &Value::Object(receipt).to_string())
    }
    fn migrate_legacy_locked(&self) -> StateResult<Loaded> {
        let marker = read_state_file(&self.root.join("state-v2.initialized"), 64)
            .map_err(StateStorageError::io)?;
        if marker.as_deref().is_some_and(|value| value != V2_MARKER) {
            return Err(failure("STATE_MARKER_INVALID"));
        }
        let paths = [
            self.root.join("client-state-v1.json"),
            self.root.join("sensitive-client-state-v1.dpapi"),
            self.root.join("access-key.dpapi"),
            self.root.join("client-state-v1.json.lkg.dpapi"),
            self.root.join("sensitive-client-state-v1.dpapi.lkg.dpapi"),
        ];
        let before = paths
            .iter()
            .map(|path| self.read_bytes(path))
            .collect::<StateResult<Vec<_>>>()?;
        if marker.is_some() && before.iter().take(3).all(Option::is_none) {
            return Err(failure("STATE_MISSING"));
        }
        let public = read_client_state_at(&paths[0], false)?;
        let protected = read_client_state_at(&paths[1], true)?;
        let access_key = before[2]
            .as_ref()
            .map(|raw| -> StateResult<String> {
                if raw.len() > 64 * 1024 {
                    return Err(failure("STATE_TOO_LARGE"));
                }
                let encrypted =
                    std::str::from_utf8(raw).map_err(|_| failure("STATE_LEGACY_KEY_CORRUPT"))?;
                let decrypted = decrypt_access_key(encrypted)
                    .map_err(|_| failure("STATE_LEGACY_KEY_CORRUPT"))?;
                normalize_access_key_for_native(&decrypted)
                    .map_err(|_| failure("STATE_LEGACY_KEY_CORRUPT"))
            })
            .transpose()?;
        let mut payload = DurablePayload {
            public_state: public.values,
            protected: protected.values,
            access_key,
            ..Default::default()
        };
        if let Some(legacy) = payload.public_state.get_mut("lastKnownServers") {
            if let Some(servers) = legacy.as_array_mut() {
                if !payload.protected.contains_key("lastKnownServers")
                    && servers.iter().any(|server| {
                        server.get("runtimeTemplate").is_some() || server.get("rawUri").is_some()
                    })
                {
                    payload
                        .protected
                        .insert("lastKnownServers".into(), Value::Array(servers.clone()));
                }
                for server in servers {
                    if let Some(map) = server.as_object_mut() {
                        map.remove("runtimeTemplate");
                        map.remove("rawUri");
                    }
                }
            }
        }
        validate_payload(&payload)?;
        let after = paths
            .iter()
            .map(|path| self.read_bytes(path))
            .collect::<StateResult<Vec<_>>>()?;
        if before != after {
            return Err(failure("STATE_LEGACY_CHANGED"));
        }
        let envelope = Envelope {
            schema_version: 2,
            generation: random_state_id()?,
            revision: 0,
            updated_at: timestamp(),
            payload,
            operations: Vec::new(),
        };
        let recover = public.recovered || protected.recovered || marker.is_some();
        if recover {
            let identity = before
                .iter()
                .map(|raw| raw.as_ref().map(|bytes| sha256_hex_bytes(bytes)))
                .collect::<Vec<_>>();
            let token = sha256_hex_bytes(
                &serde_json::to_vec(&identity).map_err(|_| failure("STATE_CORRUPT"))?,
            );
            return Ok(Loaded {
                envelope,
                ciphertext: None,
                recovery_token: Some(token),
                corrupt_primary: None,
            });
        }
        let ciphertext = encode_envelope(&envelope)?;
        // A staged backup without primary remains read-only, never a silent
        // successful migration. Original v1 files are not modified at all.
        self.write(&self.root.join("state-v2.initialized"), V2_MARKER)?;
        self.write(&self.backup(), &ciphertext)?;
        self.write(&self.primary(), &ciphertext)?;
        Ok(Loaded {
            envelope,
            ciphertext: Some(ciphertext),
            recovery_token: None,
            corrupt_primary: None,
        })
    }
    pub(crate) fn patch(&self, request: StatePatch) -> StateResult<StateCommit> {
        if request.operation_id.is_empty()
            || request.operation_id.len() > 128
            || !request
                .operation_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
            || request.changes.is_empty()
            || request.changes.len() > 8
        {
            return Err(failure("STATE_PATCH_INVALID"));
        }
        let _lease = WriterLease::acquire(&self.root)?;
        let mut loaded = self.load_locked()?;
        if loaded.recovery_token.is_some() {
            return Err(failure("STATE_RECOVERY_REQUIRED"));
        }
        let hash = sha256_hex_bytes(
            &serde_json::to_vec(&request).map_err(|_| failure("STATE_PATCH_INVALID"))?,
        );
        if let Some(prior) = loaded
            .envelope
            .operations
            .iter()
            .find(|receipt| receipt.id == request.operation_id)
        {
            if prior.hash != hash {
                return Err(failure("STATE_OPERATION_REUSED"));
            }
            return Ok(StateCommit {
                snapshot: loaded.snapshot(),
                deduplicated: true,
            });
        }
        if loaded.envelope.generation != request.generation
            || loaded.envelope.revision.to_string() != request.expected_revision
            || loaded.envelope.payload.session_generation.to_string()
                != request.expected_session_generation
        {
            let mut error = failure("STATE_CONFLICT");
            error.current_generation = Some(loaded.envelope.generation.clone().into_boxed_str());
            error.current_revision = Some(loaded.envelope.revision.to_string().into_boxed_str());
            return Err(error);
        }
        let original = loaded.envelope.payload.clone();
        let mut erase = false;
        for change in &request.changes {
            erase |= apply_change(&mut loaded.envelope.payload, change)?;
        }
        validate_payload(&loaded.envelope.payload)?;
        if loaded.envelope.payload == original {
            return Ok(StateCommit {
                snapshot: loaded.snapshot(),
                deduplicated: false,
            });
        }
        loaded.envelope.revision = loaded
            .envelope
            .revision
            .checked_add(1)
            .ok_or_else(|| failure("STATE_REVISION_OVERFLOW"))?;
        loaded.envelope.updated_at = timestamp();
        loaded.envelope.operations.push(OperationReceipt {
            id: request.operation_id,
            hash,
            revision: loaded.envelope.revision,
        });
        if loaded.envelope.operations.len() > OPERATION_WINDOW {
            loaded.envelope.operations.remove(0);
        }
        let ciphertext = encode_envelope(&loaded.envelope)?;
        let backup = if erase {
            &ciphertext
        } else {
            loaded
                .ciphertext
                .as_ref()
                .ok_or_else(|| failure("STATE_CORRUPT"))?
        };
        self.write(&self.backup(), backup)?;
        self.write(&self.primary(), &ciphertext)?;
        Ok(StateCommit {
            snapshot: loaded.snapshot(),
            deduplicated: false,
        })
    }
    pub(crate) fn recover(&self, token: &str) -> StateResult<DurableSnapshot> {
        let _lease = WriterLease::acquire(&self.root)?;
        let mut loaded = self.load_locked()?;
        if token.len() != 64 || loaded.recovery_token.as_deref() != Some(token) {
            return Err(failure("STATE_RECOVERY_CHANGED"));
        }
        if let Some(original) = loaded.corrupt_primary.as_ref() {
            // Even a malicious plaintext replacement is preserved encrypted.
            let quarantined = encrypt_access_key(&general_purpose::STANDARD.encode(original))?;
            let path = self
                .root
                .join(format!("state-preserved-{}.dpapi", random_state_id()?));
            write_new_owned_text(&path, &quarantined)?;
        }
        loaded.envelope.generation = random_state_id()?;
        loaded.envelope.revision = 0;
        loaded.envelope.updated_at = timestamp();
        loaded.envelope.operations.clear();
        let ciphertext = encode_envelope(&loaded.envelope)?;
        self.write(&self.root.join("state-v2.initialized"), V2_MARKER)?;
        self.write(&self.backup(), &ciphertext)?;
        self.write(&self.primary(), &ciphertext)?;
        loaded.recovery_token = None;
        Ok(loaded.snapshot())
    }
    pub(crate) fn export_legacy(&self, generation: &str, revision: &str) -> StateResult<PathBuf> {
        let _lease = WriterLease::acquire(&self.root)?;
        let loaded = self.load_locked()?;
        if loaded.recovery_token.is_some()
            || loaded.envelope.generation != generation
            || loaded.envelope.revision.to_string() != revision
        {
            return Err(failure("STATE_CONFLICT"));
        }
        let target = self
            .root
            .join(format!("legacy-export-{}", random_state_id()?));
        fs::create_dir(&target).map_err(StateStorageError::io)?;
        let payload = &loaded.envelope.payload;
        let public = encrypt_access_key(
            &serde_json::to_string(&payload.public_state)
                .map_err(|_| failure("STATE_EXPORT_FAILED"))?,
        )?;
        let protected = encrypt_access_key(
            &serde_json::to_string(&payload.protected)
                .map_err(|_| failure("STATE_EXPORT_FAILED"))?,
        )?;
        let mut manifest = serde_json::Map::new();
        for (name, data) in [
            ("client-state-v1.json.dpapi", Some(public)),
            ("sensitive-client-state-v1.dpapi", Some(protected)),
            (
                "access-key.dpapi",
                payload
                    .access_key
                    .as_ref()
                    .map(|key| encrypt_access_key(key))
                    .transpose()?,
            ),
        ] {
            if let Some(text) = data {
                write_new_owned_text(&target.join(name), &text)?;
                manifest.insert(
                    name.into(),
                    json!({"sha256":sha256_hex_bytes(text.as_bytes()),"size":text.len()}),
                );
            } else {
                manifest.insert(name.into(), Value::Null);
            }
        }
        // Manifest is written last. Its absence means incomplete export, never
        // a rollback package. No active v1 file is changed or app launched.
        write_new_owned_text(&target.join("COMPLETE.json"), &json!({"schemaVersion":1,"sourceGeneration":generation,"sourceRevision":revision,"publicStateEncoding":"dpapi-utf8","files":manifest}).to_string())?;
        Ok(target)
    }
}

fn write_new_owned_text(path: &Path, payload: &str) -> StateResult<()> {
    write_new_owned_bytes(path, payload.as_bytes())
}
fn write_new_owned_bytes(path: &Path, payload: &[u8]) -> StateResult<()> {
    if payload.len() as u64 > V2_CIPHER_LIMIT {
        return Err(failure("STATE_PRESERVATION_TOO_LARGE"));
    }
    let _parents = state_directory_guards(
        path.parent().ok_or_else(|| failure("STATE_PATH_INVALID"))?,
        false,
    )
    .map_err(StateStorageError::io)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(StateStorageError::io)?;
    file.write_all(payload)
        .and_then(|_| file.sync_all())
        .map_err(StateStorageError::io)
}
fn timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}
fn recovery_digest(primary: Option<&[u8]>, backup: &[u8]) -> String {
    let bytes = json!({"primary":primary.map(sha256_hex_bytes),"backup":sha256_hex_bytes(backup)})
        .to_string();
    sha256_hex_bytes(bytes.as_bytes())
}
fn encode_envelope(envelope: &Envelope) -> StateResult<String> {
    let plaintext = serde_json::to_string(envelope).map_err(|_| failure("STATE_INVALID_VALUE"))?;
    if plaintext.len() as u64 > V2_PLAIN_LIMIT {
        return Err(failure("STATE_TOO_LARGE"));
    }
    let ciphertext = encrypt_access_key(&plaintext)?;
    if ciphertext.len() as u64 > V2_CIPHER_LIMIT {
        return Err(failure("STATE_TOO_LARGE"));
    }
    Ok(ciphertext)
}
fn decode_envelope(raw: &[u8]) -> StateResult<(Envelope, String)> {
    let ciphertext = std::str::from_utf8(raw).map_err(|_| failure("STATE_CORRUPT"))?;
    let plaintext = decrypt_access_key(ciphertext).map_err(|_| failure("STATE_CORRUPT"))?;
    if plaintext.len() as u64 > V2_PLAIN_LIMIT {
        return Err(failure("STATE_TOO_LARGE"));
    }
    let value: Value = serde_json::from_str(&plaintext).map_err(|_| failure("STATE_CORRUPT"))?;
    match value.get("schemaVersion").and_then(Value::as_u64) {
        Some(2) => {}
        Some(_) => return Err(failure("STATE_UNSUPPORTED_SCHEMA")),
        None => return Err(failure("STATE_CORRUPT")),
    }
    let envelope: Envelope = serde_json::from_value(value).map_err(|_| failure("STATE_CORRUPT"))?;
    if envelope.generation.len() != 48
        || !envelope.generation.bytes().all(|b| b.is_ascii_hexdigit())
        || envelope.operations.len() > OPERATION_WINDOW
    {
        return Err(failure("STATE_CORRUPT"));
    }
    validate_payload(&envelope.payload)?;
    Ok((envelope, ciphertext.to_string()))
}
fn validate_payload(payload: &DurablePayload) -> StateResult<()> {
    for (map, limit) in [
        (&payload.public_state, CLIENT_STATE_MAX_BYTES),
        (&payload.protected, SENSITIVE_CLIENT_STATE_MAX_BYTES),
    ] {
        if serde_json::to_vec(map)
            .map_err(|_| failure("STATE_INVALID_VALUE"))?
            .len() as u64
            > limit
        {
            return Err(failure("STATE_TOO_LARGE"));
        }
    }
    if let Some(history) = payload.public_state.get("sessionHistory") {
        validate_session_history(history)?;
    }
    for key in [
        "splitTunnelEntries",
        "favoriteServerIds",
        "lastKnownServers",
    ] {
        if payload
            .public_state
            .get(key)
            .is_some_and(|value| !value.is_array())
        {
            return Err(failure("STATE_INVALID_VALUE"));
        }
    }
    if payload
        .public_state
        .get("settings")
        .is_some_and(|value| !value.is_object())
        || payload
            .public_state
            .get("selectedServerId")
            .is_some_and(|value| !value.is_string())
    {
        return Err(failure("STATE_INVALID_VALUE"));
    }
    if payload
        .protected
        .get("lastKnownServers")
        .is_some_and(|value| !value.is_object() && !value.is_array())
    {
        return Err(failure("STATE_INVALID_VALUE"));
    }
    if let Some(key) = &payload.access_key {
        normalize_access_key_for_native(key).map_err(|_| failure("STATE_INVALID_VALUE"))?;
    }
    if let Some(mirror) = &payload.legacy_web_view {
        const KEYS: [&str; 9] = [
            "vkarmani.settings",
            "vkarmani.split-tunnel.entries",
            "vkarmani.servers.favorites",
            "vkarmani.servers.selected",
            "vkarmani.servers.last-known-xray-json",
            "vkarmani.access-key",
            "vkarmani.form.access-key",
            "vkarmani.access-key.fallback-v1",
            "vkarmani.mirror-version",
        ];
        if mirror.len() > KEYS.len()
            || mirror.keys().any(|key| !KEYS.contains(&key.as_str()))
            || serde_json::to_vec(mirror)
                .map_err(|_| failure("STATE_INVALID_VALUE"))?
                .len() as u64
                > CLIENT_STATE_MAX_BYTES
        {
            return Err(failure("STATE_TOO_LARGE"));
        }
    }
    Ok(())
}
fn merge_settings(old: &Value, new: &Value, depth: usize) -> StateResult<Value> {
    if depth > 32 {
        return Err(failure("STATE_INVALID_VALUE"));
    }
    if let (Some(old), Some(new)) = (old.as_object(), new.as_object()) {
        let mut map = old.clone();
        for (key, value) in new {
            map.insert(
                key.clone(),
                merge_settings(map.get(key).unwrap_or(&Value::Null), value, depth + 1)?,
            );
        }
        Ok(Value::Object(map))
    } else {
        Ok(new.clone())
    }
}
fn apply_change(payload: &mut DurablePayload, change: &StateChange) -> StateResult<bool> {
    match change.scope.as_str() {
        "public" if is_allowed_client_state_key(&change.key) => {
            if let Some(value) = &change.value {
                if change.key == "sessionHistory" {
                    validate_session_history(value)?;
                }
                let value = if change.key == "settings" {
                    merge_settings(
                        payload
                            .public_state
                            .get(&change.key)
                            .unwrap_or(&Value::Null),
                        value,
                        0,
                    )?
                } else {
                    value.clone()
                };
                if change.key == "lastKnownServers"
                    && value.as_array().is_some_and(|servers| {
                        servers.iter().any(|server| {
                            server.get("runtimeTemplate").is_some()
                                || server.get("rawUri").is_some()
                        })
                    })
                {
                    return Err(failure("STATE_PUBLIC_SECRET_REJECTED"));
                }
                payload.public_state.insert(change.key.clone(), value);
            } else {
                payload.public_state.remove(&change.key);
            }
        }
        "protected" if is_allowed_sensitive_client_state_key(&change.key) => {
            if let Some(value) = &change.value {
                payload.protected.insert(change.key.clone(), value.clone());
            } else {
                payload.protected.remove(&change.key);
            }
        }
        "credential" if change.key == "accessKey" => {
            let key = change
                .value
                .as_ref()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| failure("STATE_INVALID_VALUE"))
                        .and_then(|key| {
                            normalize_access_key_for_native(key)
                                .map_err(|_| failure("STATE_INVALID_VALUE"))
                        })
                })
                .transpose()?;
            if key != payload.access_key {
                payload.access_key = key;
                payload.session_generation = payload
                    .session_generation
                    .checked_add(1)
                    .ok_or_else(|| failure("STATE_REVISION_OVERFLOW"))?;
                payload.public_state.remove("lastKnownServers");
                payload.protected.remove("lastKnownServers");
                // A user logout must not be recoverable from a legacy mirror.
                if let Some(mirror) = payload.legacy_web_view.as_mut() {
                    mirror.retain(|key, _| {
                        !key.contains("access-key") && !key.contains("last-known")
                    });
                }
                return Ok(true);
            }
        }
        "legacy" if change.key == "webView" && payload.legacy_web_view.is_none() => {
            payload.legacy_web_view = Some(
                change
                    .value
                    .as_ref()
                    .and_then(Value::as_object)
                    .cloned()
                    .ok_or_else(|| failure("STATE_INVALID_VALUE"))?,
            );
        }
        _ => return Err(failure("STATE_KEY_INVALID")),
    }
    Ok(change.value.is_none())
}

fn validate_session_history(value: &Value) -> StateResult<()> {
    let rows = value
        .as_array()
        .ok_or_else(|| failure("STATE_INVALID_VALUE"))?;
    if rows.len() > 128 {
        return Err(failure("STATE_TOO_LARGE"));
    }
    let mut ids = std::collections::HashSet::new();
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| failure("STATE_INVALID_VALUE"))?;
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("STATE_INVALID_VALUE"))?;
        let started = row
            .get("startedAtMs")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("STATE_INVALID_VALUE"))?;
        if object.len() != 5
            || object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "id" | "startedAtMs" | "durationSeconds" | "mode" | "status"
                )
            })
            || id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !ids.insert(id)
            || started.is_empty()
            || started.len() > 16
            || !started.bytes().all(|b| b.is_ascii_digit())
            || (started.len() > 1 && started.starts_with('0'))
            || started
                .parse::<u64>()
                .map_or(true, |value| value > 8640000000000000)
            || row
                .get("durationSeconds")
                .and_then(Value::as_u64)
                .map_or(true, |value| value > 315360000)
            || !matches!(
                row.get("mode").and_then(Value::as_str),
                Some("proxy" | "tun")
            )
            || !matches!(
                row.get("status").and_then(Value::as_str),
                Some("current" | "completed" | "interrupted")
            )
        {
            return Err(failure("STATE_INVALID_VALUE"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "durable_state_tests.rs"]
mod tests;

mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("invalid decimal generation"));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}
