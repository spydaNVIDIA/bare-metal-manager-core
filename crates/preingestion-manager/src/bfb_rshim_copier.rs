/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::sync::Arc;
use std::time::Duration;

use carbide_secrets::credentials::{CredentialKey, CredentialReader, Credentials};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

const UNIFIED_PREINGESTION_BFB_PATH: &str =
    "/forge-boot-artifacts/blobs/internal/aarch64/preingestion_unified_update.bfb";
const PREINGESTION_BFB_PATH: &str = "/forge-boot-artifacts/blobs/internal/aarch64/preingestion.bfb";

#[derive(Debug, thiserror::Error)]
pub(crate) enum BfbRshimCopyError {
    #[error("missing credential {key}: {cause}")]
    MissingCredentials { key: String, cause: String },
    #[error("secrets engine error occurred: {cause}")]
    SecretsEngineError { cause: String },
    #[error("error: {details}")]
    Other { details: String },
}

pub(crate) struct BfbRshimCopier {
    credential_reader: Option<Arc<dyn CredentialReader>>,
    bfb_file_lock: Arc<Mutex<()>>,
}

impl BfbRshimCopier {
    pub(crate) fn new(credential_reader: Option<Arc<dyn CredentialReader>>) -> Self {
        Self {
            credential_reader,
            bfb_file_lock: Arc::new(Mutex::new(())),
        }
    }

    fn valid_bmc_password(credentials: &Credentials) -> bool {
        let (_, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        !password.is_empty()
    }

    async fn get_bmc_root_credentials(
        &self,
        credential_key: &CredentialKey,
    ) -> Result<Credentials, BfbRshimCopyError> {
        let Some(credential_reader) = &self.credential_reader else {
            return Err(BfbRshimCopyError::MissingCredentials {
                key: credential_key.to_key_str().to_string(),
                cause: "credential reader is not configured".to_string(),
            });
        };

        match credential_reader.get_credentials(credential_key).await {
            Ok(Some(credentials)) => {
                if !Self::valid_bmc_password(&credentials) {
                    return Err(BfbRshimCopyError::Other {
                        details: format!(
                            "vault does not have a valid password entry at {}",
                            credential_key.to_key_str()
                        ),
                    });
                }

                Ok(credentials)
            }
            Ok(None) => Err(BfbRshimCopyError::MissingCredentials {
                key: credential_key.to_key_str().to_string(),
                cause: "No credentials exists".to_string(),
            }),
            Err(err) => Err(BfbRshimCopyError::SecretsEngineError {
                cause: err.to_string(),
            }),
        }
    }

    async fn is_rshim_enabled(
        &self,
        bmc_ip_address: std::net::SocketAddr,
        credentials: Credentials,
    ) -> Result<bool, BfbRshimCopyError> {
        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        forge_ssh::ssh::is_rshim_enabled(bmc_ip_address, username, password)
            .await
            .map_err(|err| BfbRshimCopyError::Other {
                details: format!("failed query RSHIM status on on {bmc_ip_address}: {err}"),
            })
    }

    async fn enable_rshim(
        &self,
        bmc_ip_address: std::net::SocketAddr,
        credentials: Credentials,
    ) -> Result<(), BfbRshimCopyError> {
        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        forge_ssh::ssh::enable_rshim(bmc_ip_address, username, password)
            .await
            .map_err(|err| BfbRshimCopyError::Other {
                details: format!("failed enable RSHIM on {bmc_ip_address}: {err}"),
            })
    }

    async fn check_and_enable_rshim(
        &self,
        bmc_ip_address: std::net::SocketAddr,
        credentials: &Credentials,
    ) -> Result<(), BfbRshimCopyError> {
        let mut i = 0;
        while i < 3 {
            if !self
                .is_rshim_enabled(bmc_ip_address, credentials.clone())
                .await?
            {
                tracing::warn!(%bmc_ip_address, "RSHIM is not enabled");
                self.enable_rshim(bmc_ip_address, credentials.clone())
                    .await?;

                // Sleep for 10 seconds before checking again
                tokio::time::sleep(Duration::from_secs(10)).await;
                i += 1;
            } else {
                return Ok(());
            }
        }

        Err(BfbRshimCopyError::Other {
            details: format!("could not enable RSHIM on {bmc_ip_address}"),
        })
    }

    async fn create_unified_preingestion_bfb(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(), BfbRshimCopyError> {
        let _lock = self.bfb_file_lock.lock().await;

        Self::write_unified_preingestion_bfb(
            PREINGESTION_BFB_PATH,
            UNIFIED_PREINGESTION_BFB_PATH,
            username,
            password,
        )
        .await
    }

    /// Assemble the unified pre-ingestion BFB by concatenating the base BFB with
    /// a `bf.cfg` blob carrying the BMC credentials.
    ///
    /// The `bf.cfg` blob embeds the BMC root password in cleartext, so the
    /// artifact is created with `0o600` (owner read/write only). The mode is
    /// applied atomically by `open` at creation time rather than being left to
    /// the process umask, so the password is never momentarily readable by other
    /// local users/processes.
    async fn write_unified_preingestion_bfb(
        source_bfb_path: &str,
        unified_bfb_path: &str,
        username: &str,
        password: &str,
    ) -> Result<(), BfbRshimCopyError> {
        if fs::metadata(unified_bfb_path).await.is_err() {
            tracing::info!(path = unified_bfb_path, "Writing unified preingestion BFB");
            let bf_cfg_contents = format!(
                "BMC_USER=\"{username}\"\nBMC_PASSWORD=\"{password}\"\nBMC_REBOOT=\"yes\"\nCEC_REBOOT=\"yes\"\n"
            );

            let mut preingestion_bfb =
                File::open(source_bfb_path)
                    .await
                    .map_err(|err| BfbRshimCopyError::Other {
                        details: format!("failed to open {source_bfb_path}: {err}"),
                    })?;

            let mut unified_bfb = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(unified_bfb_path)
                .await
                .map_err(|err| BfbRshimCopyError::Other {
                    details: format!("failed to create {unified_bfb_path}: {err}"),
                })?;

            let mut buffer = vec![0; 1024 * 1024].into_boxed_slice(); // 1 MB buffer

            tracing::info!(path = unified_bfb_path, "Writing BFB payload");
            loop {
                let n = preingestion_bfb.read(&mut buffer).await.map_err(|err| {
                    BfbRshimCopyError::Other {
                        details: format!("failed to read BFB: {err}"),
                    }
                })?;

                if n == 0 {
                    break;
                }

                unified_bfb.write_all(&buffer[..n]).await.map_err(|err| {
                    BfbRshimCopyError::Other {
                        details: format!("failed to write BFB to {unified_bfb_path}: {err}"),
                    }
                })?;
            }

            tracing::info!(path = unified_bfb_path, "Writing bf.cfg payload");

            unified_bfb
                .write_all(bf_cfg_contents.as_bytes())
                .await
                .map_err(|err| BfbRshimCopyError::Other {
                    details: format!("failed to write bf.cfg: {err}"),
                })?;

            unified_bfb
                .sync_all()
                .await
                .map_err(|err| BfbRshimCopyError::Other {
                    details: format!("failed to flush {unified_bfb_path}: {err}"),
                })?;
        }

        Ok(())
    }

    pub(crate) async fn copy_bfb_to_dpu_rshim(
        &self,
        bmc_ip_address: std::net::SocketAddr,
        credential_key: &CredentialKey,
    ) -> Result<(), BfbRshimCopyError> {
        let credentials = self.get_bmc_root_credentials(credential_key).await?;
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        self.create_unified_preingestion_bfb(&username, &password)
            .await?;

        self.check_and_enable_rshim(bmc_ip_address, &credentials)
            .await?;

        forge_ssh::ssh::copy_bfb_to_bmc_rshim(
            bmc_ip_address,
            username,
            password,
            UNIFIED_PREINGESTION_BFB_PATH.to_string(),
        )
        .await
        .map_err(|err| BfbRshimCopyError::Other {
            details: format!(
                "failed to copy BFB from {UNIFIED_PREINGESTION_BFB_PATH} to BMC RSHIM on {bmc_ip_address}: {err}"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// The unified BFB embeds the BMC root password in cleartext, so the
    /// assembled artifact must be readable only by its owner (`0o600`),
    /// independent of the process umask.
    #[tokio::test]
    async fn write_unified_preingestion_bfb_creates_owner_only_artifact() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let source_path = dir.path().join("preingestion.bfb");
        let unified_path = dir.path().join("preingestion_unified_update.bfb");

        let base_payload = b"base-bfb-payload";
        fs::write(&source_path, base_payload)
            .await
            .expect("write source bfb");

        BfbRshimCopier::write_unified_preingestion_bfb(
            source_path.to_str().expect("utf-8 source path"),
            unified_path.to_str().expect("utf-8 unified path"),
            "root",
            "s3cr3t-p@ssw0rd",
        )
        .await
        .expect("write unified bfb");

        let mode = fs::metadata(&unified_path)
            .await
            .expect("stat unified bfb")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "unified BFB must be owner-only, got {:o}",
            mode & 0o777
        );

        // The base BFB is concatenated with the bf.cfg blob carrying the creds.
        let written = fs::read(&unified_path).await.expect("read unified bfb");
        assert!(
            written.starts_with(base_payload),
            "unified BFB must start with the base BFB payload"
        );
        let bf_cfg = String::from_utf8_lossy(&written[base_payload.len()..]);
        assert!(bf_cfg.contains("BMC_USER=\"root\""));
        assert!(bf_cfg.contains("BMC_PASSWORD=\"s3cr3t-p@ssw0rd\""));
    }
}
