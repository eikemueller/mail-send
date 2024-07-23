/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use log::info;
use smtp_proto::{EhloResponse, EXT_START_TLS};
use std::hash::Hash;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use worker::{SecureTransport, Socket};

use crate::{Credentials, SmtpClient, SmtpClientBuilder};

use super::AssertReply;

impl<T: AsRef<str> + PartialEq + Eq + Hash> SmtpClientBuilder<T> {
    pub fn new(hostname: T, port: u16, secure_transport: SecureTransport) -> Self {
        SmtpClientBuilder {
            timeout: Duration::from_secs(60 * 60),
            hostname,
            port,
            secure_transport,
            is_lmtp: false,
            local_host: String::from("[127.0.0.1]"),
            credentials: None,
            say_ehlo: true,
        }
    }

    /// Use LMTP instead of SMTP
    pub fn lmtp(mut self, is_lmtp: bool) -> Self {
        self.is_lmtp = is_lmtp;
        self
    }

    // Say EHLO/LHLO
    pub fn say_ehlo(mut self, say_ehlo: bool) -> Self {
        self.say_ehlo = say_ehlo;
        self
    }

    /// Set the EHLO/LHLO hostname
    pub fn helo_host(mut self, host: impl Into<String>) -> Self {
        self.local_host = host.into();
        self
    }

    /// Sets the authentication credentials
    pub fn credentials(mut self, credentials: impl Into<Credentials<T>>) -> Self {
        self.credentials = Some(credentials.into());
        self
    }

    /// Sets the SMTP connection timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn connect(&self) -> crate::Result<SmtpClient<Socket>> {
        info!("connecting to {}:{}", self.hostname.as_ref(), self.port);
        let mut client = SmtpClient::connect(
            self.hostname.as_ref(),
            self.port,
            self.secure_transport.clone(),
            self.timeout,
        )
        .await?;
        info!("await completion");
        client.read().await?.assert_positive_completion()?;
        info!("awaited completion");

        if self.secure_transport == SecureTransport::StartTls {
            info!("starttls");
            // Send EHLO
            let response = if !self.is_lmtp {
                client.ehlo(&self.local_host).await?
            } else {
                client.lhlo(&self.local_host).await?
            };
            if response.has_capability(EXT_START_TLS) {
                client = client.start_tls().await?;
            } else {
                return Err(crate::Error::MissingStartTls);
            }
        }

        info!("connected");

        if self.say_ehlo {
            // Obtain capabilities
            let capabilities = client.capabilities(&self.local_host, self.is_lmtp).await?;
            // Authenticate
            if let Some(credentials) = &self.credentials {
                client.authenticate(&credentials, &capabilities).await?;
            }
        }

        Ok(client)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    pub async fn capabilities(
        &mut self,
        local_host: &str,
        is_lmtp: bool,
    ) -> crate::Result<EhloResponse<String>> {
        if !is_lmtp {
            self.ehlo(local_host).await
        } else {
            self.lhlo(local_host).await
        }
    }
}

impl SmtpClient<Socket> {
    pub async fn connect(
        hostname: &str,
        port: u16,
        secure_transport: SecureTransport,
        timeout: Duration,
    ) -> crate::Result<Self> {
        let socket = Socket::builder()
            .secure_transport(secure_transport)
            .connect(hostname, port)?;
        Self::new(socket, timeout).await
    }

    pub async fn start_tls(self) -> crate::Result<Self> {
        Self::new(self.stream.start_tls(), self.timeout).await
    }

    async fn new(socket: Socket, timeout: Duration) -> crate::Result<Self> {
        socket.opened().await?;
        Ok(Self {
            stream: socket,
            timeout,
        })
    }
}
