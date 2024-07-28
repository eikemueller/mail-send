/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use smtp_proto::{response::parser::ResponseReceiver, Response};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(not(target_family = "wasm"))]
use tokio::time::timeout;
#[cfg(target_family = "wasm")]
use wasmtimer::tokio::timeout;

use crate::SmtpClient;

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    pub async fn read(&mut self) -> crate::Result<Response<String>> {
        let mut buf = vec![0u8; 1024];
        let mut parser = ResponseReceiver::default();

        loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                match parser.parse(&mut buf[..br].iter()) {
                    Ok(reply) => return Ok(reply),
                    Err(err) => match err {
                        smtp_proto::Error::NeedsMoreData { .. } => (),
                        _ => {
                            return Err(crate::Error::UnparseableReply);
                        }
                    },
                }
            } else {
                return Err(crate::Error::UnparseableReply);
            }
        }
    }

    pub async fn read_many(&mut self, num: usize) -> crate::Result<Vec<Response<String>>> {
        let mut buf = vec![0u8; 1024];
        let mut response = Vec::with_capacity(num);
        let mut parser = ResponseReceiver::default();

        'outer: loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                let mut iter = buf[..br].iter();

                loop {
                    match parser.parse(&mut iter) {
                        Ok(reply) => {
                            response.push(reply);
                            if response.len() != num {
                                parser.reset();
                            } else {
                                break 'outer;
                            }
                        }
                        Err(err) => match err {
                            smtp_proto::Error::NeedsMoreData { .. } => break,
                            _ => {
                                return Err(crate::Error::UnparseableReply);
                            }
                        },
                    }
                }
            } else {
                return Err(crate::Error::UnparseableReply);
            }
        }

        Ok(response)
    }

    /// Sends a command to the SMTP server and waits for a reply.
    pub async fn cmd(&mut self, cmd: impl AsRef<[u8]>) -> crate::Result<Response<String>> {
        timeout(self.timeout, async {
            self.stream.write_all(cmd.as_ref()).await?;
            self.stream.flush().await?;
            self.read().await
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }

    /// Pipelines multiple command to the SMTP server and waits for a reply.
    pub async fn cmds(
        &mut self,
        cmds: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> crate::Result<Vec<Response<String>>> {
        timeout(self.timeout, async {
            let mut num_replies = 0;
            for cmd in cmds {
                self.stream.write_all(cmd.as_ref()).await?;
                num_replies += 1;
            }
            self.stream.flush().await?;
            self.read_many(num_replies).await
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncWrite};

    use crate::SmtpClient;

    #[derive(Default)]
    struct AsyncBufWriter {
        buf: Vec<u8>,
    }

    impl AsyncRead for AsyncBufWriter {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            unreachable!()
        }
    }

    impl AsyncWrite for AsyncBufWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            self.buf.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[cfg_attr(not(target_family = "wasm"), tokio::test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
    async fn transparency_procedure() {
        const SMUGGLER: &str = r#"From: Joe SixPack <john@foobar.net>
To: Suzie Q <suzie@foobar.org>
Subject: Is dinner ready?

Hi.

We lost the game. Are you hungry yet?

Joe.

<SEP>.
MAIL FROM:<admin@foobar.net>
RCPT TO:<ok@foobar.org>
DATA
From: Joe SixPack <admin@foobar.net>
To: Suzie Q <suzie@foobar.org>
Subject: smuggled message

This is a smuggled message
"#;

        for (test, result) in [
            (
                "A: b\r\n.\r\n".to_string(),
                "A: b\r\n..\r\n\r\n.\r\n".to_string(),
            ),
            ("A: b\r\n.".to_string(), "A: b\r\n..\r\n.\r\n".to_string()),
            (
                "A: b\r\n..\r\n".to_string(),
                "A: b\r\n...\r\n\r\n.\r\n".to_string(),
            ),
            ("A: ...b".to_string(), "A: ...b\r\n.\r\n".to_string()),
            (
                "A: \n.\r\nMAIL FROM:<>".to_string(),
                "A: \n..\r\nMAIL FROM:<>\r\n.\r\n".to_string(),
            ),
            (
                "A: \r.\r\nMAIL FROM:<>".to_string(),
                "A: \r..\r\nMAIL FROM:<>\r\n.\r\n".to_string(),
            ),
            (
                SMUGGLER
                    .replace('\r', "")
                    .replace('\n', "\r\n")
                    .replace("<SEP>", "\r"),
                SMUGGLER
                    .replace('\r', "")
                    .replace('\n', "\r\n")
                    .replace("<SEP>", "\r.")
                    + "\r\n.\r\n",
            ),
            (
                SMUGGLER
                    .replace('\r', "")
                    .replace('\n', "\r\n")
                    .replace("<SEP>", "\n"),
                SMUGGLER
                    .replace('\r', "")
                    .replace('\n', "\r\n")
                    .replace("<SEP>", "\n.")
                    + "\r\n.\r\n",
            ),
        ] {
            let mut client = SmtpClient {
                stream: AsyncBufWriter::default(),
                timeout: Duration::from_secs(30),
            };
            client.write_message(test.as_bytes()).await.unwrap();
            assert_eq!(String::from_utf8(client.stream.buf).unwrap(), result);
        }
    }
}
