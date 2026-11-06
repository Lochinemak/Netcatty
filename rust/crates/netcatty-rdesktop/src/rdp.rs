//! RDP sessions on top of IronRDP.
//!
//! Scope of this first version: TLS + NLA (CredSSP with NTLM) logon with a
//! user name and password, bitmap graphics decoded into an RGBA framebuffer,
//! keyboard and mouse input. Not implemented: Kerberos, clipboard, audio,
//! drive redirection and dynamic resize (the desktop keeps the size requested
//! at connect time; the renderer scales it).

use crate::net::connect_tcp;
use crate::{clamp_desktop_size, ConnectOptions, EventSink, RemoteEvent, RemoteInput};
use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{
    ClientConnector, Config, ConnectionResult, ConnectorError, ConnectorErrorExt as _,
    ConnectorResult, Credentials, DesktopSize, ServerName,
};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp_pdu::gcc::{ConnectionType, KeyboardType};
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_pdu::WriteBuf;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_tokio::{
    single_sequence_step_read, split_tokio_framed, FramedWrite as _, NetworkClient, TokioFramed,
};
use netcatty_core::{CoreError, CoreResult};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedReceiver;

type TlsFramed = TokioFramed<ironrdp_tls::TlsStream<TcpStream>>;

/// One wheel notch in RDP rotation units.
const WHEEL_NOTCH: i16 = 120;
const MAX_WHEEL_NOTCHES: i16 = 8;

pub(crate) async fn run(
    options: &ConnectOptions,
    inputs: &mut UnboundedReceiver<RemoteInput>,
    sink: &EventSink,
) -> CoreResult<()> {
    let (connection, framed) = connect(options).await?;
    session(connection, framed, inputs, sink).await
}

/// CredSSP may ask for a network round trip (Kerberos KDC, CRL fetch). Only
/// NTLM is supported here, which never does.
struct NoNetworkClient;

impl NetworkClient for NoNetworkClient {
    async fn send(&mut self, _request: &NetworkRequest) -> ConnectorResult<Vec<u8>> {
        Err(ConnectorError::general(
            "Kerberos authentication is not supported; use an NTLM-capable account",
        ))
    }
}

fn build_config(options: &ConnectOptions) -> Config {
    let domain = options
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(str::to_owned);

    Config {
        desktop_size: DesktopSize {
            width: clamp_desktop_size(options.width),
            height: clamp_desktop_size(options.height),
        },
        monitor_layout: None,
        desktop_scale_factor: 0,
        desktop_physical_size: None,
        desktop_orientation: None,
        device_scale_factor: None,
        monitor_extended_layout: None,
        relative_mouse_input: false,
        enable_tls: true,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        credentials: Credentials::UsernamePassword {
            username: options.username.clone().unwrap_or_default(),
            password: options.password.clone().unwrap_or_default(),
        },
        domain,
        client_build: 0,
        client_name: "Netcatty".to_owned(),
        keyboard_type: KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        connection_type: ConnectionType::Lan,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::empty(),
        platform: platform(),
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        enable_audio_capture: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        compression_type: None,
        // The server pointer is composited into the framebuffer, so the
        // renderer does not need a separate cursor channel.
        enable_server_pointer: true,
        pointer_software_rendering: true,
        multitransport_flags: None,
        support_dyn_vc_gfx_protocol: false,
    }
}

fn platform() -> MajorPlatformType {
    if cfg!(windows) {
        MajorPlatformType::WINDOWS
    } else if cfg!(target_os = "macos") {
        MajorPlatformType::MACINTOSH
    } else {
        MajorPlatformType::UNIX
    }
}

async fn connect(options: &ConnectOptions) -> CoreResult<(ConnectionResult, TlsFramed)> {
    let tcp = connect_tcp(&options.host, options.port).await?;
    let client_addr = tcp
        .local_addr()
        .map_err(|err| CoreError::network(format!("cannot read local address: {err}")))?;

    let mut framed = TokioFramed::new(tcp);
    let mut connector = ClientConnector::new(build_config(options), client_addr);

    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(connector_error)?;

    // RDP servers almost always present a self-signed certificate, so the
    // chain is not validated (the same default as mstsc's "connect anyway").
    let tcp = framed.into_inner_no_leftover();
    let (tls, certificate) = ironrdp_tls::upgrade(tcp, &options.host)
        .await
        .map_err(|err| CoreError::network(format!("RDP TLS handshake failed: {err}")))?;
    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&certificate)
        .ok_or_else(|| CoreError::network("RDP server certificate has no public key"))?
        .to_vec();

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = TokioFramed::new(tls);

    let outcome = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut NoNetworkClient,
        ServerName::new(options.host.clone()),
        server_public_key,
        None,
    )
    .await
    .map_err(connector_error)?;

    let connection = outcome.into_connected().map_err(connector_error)?;
    Ok((connection, framed))
}

async fn session(
    connection: ConnectionResult,
    framed: TlsFramed,
    inputs: &mut UnboundedReceiver<RemoteInput>,
    sink: &EventSink,
) -> CoreResult<()> {
    let (mut reader, mut writer) = split_tokio_framed(framed);
    let activation_factory = connection.activation_factory;

    let mut image = DecodedImage::new(
        PixelFormat::RgbA32,
        connection.desktop_size.width,
        connection.desktop_size.height,
    );
    let mut stage: ActiveStage = ActiveStageBuilder {
        static_channels: connection.static_channels,
        user_channel_id: connection.user_channel_id,
        io_channel_id: connection.io_channel_id,
        message_channel_id: connection.message_channel_id,
        share_id: connection.share_id,
        compression_type: connection.compression_type,
        enable_server_pointer: connection.enable_server_pointer,
        pointer_software_rendering: connection.pointer_software_rendering,
    }
    .build();

    sink(RemoteEvent::Connected {
        width: image.width(),
        height: image.height(),
    });

    let mut input_db = Database::new();
    let mut buttons = 0u8;

    loop {
        let outputs = tokio::select! {
            frame = reader.read_pdu() => {
                let (action, payload) = frame
                    .map_err(|err| CoreError::network(format!("RDP connection lost: {err}")))?;
                stage
                    .process(&mut image, action, &payload, reader.last_read_at())
                    .map_err(session_error)?
            }
            input = inputs.recv() => {
                let Some(input) = input else { return Ok(()) };
                let events = match input {
                    // Repaint from the local framebuffer copy.
                    RemoteInput::Refresh => {
                        emit_full_frame(&image, sink);
                        continue;
                    }
                    other => input_db.apply(operations(other, &mut buttons)),
                };
                stage
                    .process_fastpath_input(&mut image, &events)
                    .map_err(session_error)?
            }
        };

        for output in outputs {
            match output {
                ActiveStageOutput::ResponseFrame(frame) => writer
                    .write_all(&frame)
                    .await
                    .map_err(|err| CoreError::network(format!("RDP write failed: {err}")))?,
                ActiveStageOutput::GraphicsUpdate(region) => emit_region(&image, &region, sink),
                ActiveStageOutput::Terminate(reason) => {
                    tracing::info!(%reason, "RDP session terminated by the server");
                    return Err(CoreError::network(format!(
                        "RDP session ended: {}",
                        reason.description()
                    )));
                }
                ActiveStageOutput::DeactivateAll => {
                    // Deactivation-Reactivation Sequence: the server
                    // renegotiates capabilities, typically after a logon or a
                    // resolution change.
                    let mut activation = activation_factory.create();
                    let mut buf = WriteBuf::new();
                    loop {
                        let written =
                            single_sequence_step_read(&mut reader, &mut activation, &mut buf)
                                .await
                                .map_err(connector_error)?;
                        if written.size().is_some() {
                            writer.write_all(buf.filled()).await.map_err(|err| {
                                CoreError::network(format!("RDP write failed: {err}"))
                            })?;
                        }
                        if let ConnectionActivationState::Finalized {
                            desktop_size,
                            share_id,
                            static_channel_chunk_size,
                            enable_server_pointer,
                            pointer_software_rendering,
                            ..
                        } = activation.connection_activation_state()
                        {
                            image = DecodedImage::new(
                                PixelFormat::RgbA32,
                                desktop_size.width,
                                desktop_size.height,
                            );
                            if !stage.reactivate(
                                activation.io_channel_id(),
                                activation.user_channel_id(),
                                share_id,
                                enable_server_pointer,
                                pointer_software_rendering,
                                static_channel_chunk_size,
                            ) {
                                return Err(CoreError::network(
                                    "RDP reactivation negotiated an invalid channel chunk size",
                                ));
                            }
                            sink(RemoteEvent::Resize {
                                width: desktop_size.width,
                                height: desktop_size.height,
                            });
                            break;
                        }
                    }
                }
                // Pointer shape, monitor layout and logon notifications are
                // not surfaced to the renderer.
                _ => {}
            }
        }
    }
}

/// Translate one renderer input into IronRDP input operations. Button state
/// arrives as a mask, IronRDP wants transitions, hence the diff against the
/// previous mask.
fn operations(input: RemoteInput, buttons: &mut u8) -> Vec<Operation> {
    match input {
        RemoteInput::Pointer {
            x,
            y,
            buttons: mask,
        } => {
            let mut ops = vec![Operation::MouseMove(MousePosition { x, y })];
            for (bit, button) in [
                (0b001, MouseButton::Left),
                (0b010, MouseButton::Middle),
                (0b100, MouseButton::Right),
            ] {
                match (*buttons & bit != 0, mask & bit != 0) {
                    (false, true) => ops.push(Operation::MouseButtonPressed(button)),
                    (true, false) => ops.push(Operation::MouseButtonReleased(button)),
                    _ => {}
                }
            }
            *buttons = mask & 0b111;
            ops
        }
        RemoteInput::Wheel {
            x,
            y,
            delta_x,
            delta_y,
        } => {
            let mut ops = vec![Operation::MouseMove(MousePosition { x, y })];
            for (delta, is_vertical) in [(delta_y, true), (delta_x, false)] {
                let notches = delta.clamp(-MAX_WHEEL_NOTCHES, MAX_WHEEL_NOTCHES);
                if notches != 0 {
                    ops.push(Operation::WheelRotations(WheelRotations {
                        is_vertical,
                        rotation_units: notches * WHEEL_NOTCH,
                    }));
                }
            }
            ops
        }
        RemoteInput::Key {
            down,
            keysym,
            scancode,
        } => {
            if scancode != 0 {
                let scancode = Scancode::from_u16(scancode);
                vec![if down {
                    Operation::KeyPressed(scancode)
                } else {
                    Operation::KeyReleased(scancode)
                }]
            } else if let Some(character) = keysym_to_char(keysym) {
                // No physical key: send the character itself.
                vec![if down {
                    Operation::UnicodeKeyPressed(character)
                } else {
                    Operation::UnicodeKeyReleased(character)
                }]
            } else {
                Vec::new()
            }
        }
        // Clipboard redirection is not implemented for RDP; `Refresh` is
        // handled by the caller.
        RemoteInput::Clipboard(_) | RemoteInput::Refresh => Vec::new(),
    }
}

/// X11 keysym → character, for keysyms that denote a printable character:
/// Latin-1 keysyms equal their code point, others carry it in the low 24 bits
/// behind the `0x0100_0000` Unicode marker.
fn keysym_to_char(keysym: u32) -> Option<char> {
    let code = match keysym {
        0x20..=0x7E | 0xA0..=0xFF => keysym,
        0x0100_0000..=0x0110_FFFF => keysym - 0x0100_0000,
        _ => return None,
    };
    char::from_u32(code).filter(|c| !c.is_control())
}

fn emit_full_frame(image: &DecodedImage, sink: &EventSink) {
    let (width, height) = (image.width(), image.height());
    if width == 0 || height == 0 {
        return;
    }
    emit_region(
        image,
        &InclusiveRectangle {
            left: 0,
            top: 0,
            right: width - 1,
            bottom: height - 1,
        },
        sink,
    );
}

/// Send the pixels of `region` (inclusive bounds) as one frame event.
fn emit_region(image: &DecodedImage, region: &InclusiveRectangle, sink: &EventSink) {
    if let Some((x, y, width, height, rgba)) = copy_region(
        image.data(),
        image.stride(),
        image.bytes_per_pixel(),
        image.width(),
        image.height(),
        region,
    ) {
        sink(RemoteEvent::Frame {
            x,
            y,
            width,
            height,
            rgba,
        });
    }
}

/// Copy an inclusive rectangle out of a framebuffer into a tightly packed
/// opaque RGBA buffer. The rectangle is clipped to the framebuffer; `None`
/// when nothing is left or the buffer is not 4 bytes per pixel.
fn copy_region(
    data: &[u8],
    stride: usize,
    bytes_per_pixel: usize,
    image_width: u16,
    image_height: u16,
    region: &InclusiveRectangle,
) -> Option<(u16, u16, u16, u16, Vec<u8>)> {
    if bytes_per_pixel != 4 || image_width == 0 || image_height == 0 {
        return None;
    }
    let right = region.right.min(image_width - 1);
    let bottom = region.bottom.min(image_height - 1);
    if region.left > right || region.top > bottom {
        return None;
    }
    let width = right - region.left + 1;
    let height = bottom - region.top + 1;
    let row_len = usize::from(width) * 4;

    let mut rgba = Vec::with_capacity(row_len * usize::from(height));
    for row in region.top..=bottom {
        let start = usize::from(row) * stride + usize::from(region.left) * 4;
        rgba.extend_from_slice(data.get(start..start + row_len)?);
    }
    crate::make_opaque(&mut rgba);
    Some((region.left, region.top, width, height, rgba))
}

fn connector_error(err: ConnectorError) -> CoreError {
    let message = format!("{err:#}");
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("credssp") || lowered.contains("logon") || lowered.contains("access denied")
    {
        CoreError::auth(format!("RDP authentication failed: {message}"))
    } else {
        CoreError::network(format!("RDP connection failed: {message}"))
    }
}

fn session_error(err: ironrdp_session::SessionError) -> CoreError {
    CoreError::network(format!("RDP session error: {err:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framebuffer(width: u16, height: u16) -> Vec<u8> {
        // Pixel (x, y) = [x, y, 7, 0]: alpha deliberately transparent.
        let mut data = Vec::new();
        for y in 0..height {
            for x in 0..width {
                data.extend_from_slice(&[x as u8, y as u8, 7, 0]);
            }
        }
        data
    }

    #[test]
    fn copy_region_packs_the_inclusive_rectangle_and_forces_alpha() {
        let data = framebuffer(4, 3);
        let region = InclusiveRectangle {
            left: 1,
            top: 1,
            right: 2,
            bottom: 2,
        };
        let (x, y, width, height, rgba) = copy_region(&data, 16, 4, 4, 3, &region).unwrap();
        assert_eq!((x, y, width, height), (1, 1, 2, 2));
        assert_eq!(
            rgba,
            vec![1, 1, 7, 255, 2, 1, 7, 255, 1, 2, 7, 255, 2, 2, 7, 255]
        );
    }

    #[test]
    fn copy_region_clips_to_the_framebuffer() {
        let data = framebuffer(4, 3);
        let region = InclusiveRectangle {
            left: 3,
            top: 2,
            right: 50,
            bottom: 50,
        };
        let (x, y, width, height, rgba) = copy_region(&data, 16, 4, 4, 3, &region).unwrap();
        assert_eq!((x, y, width, height), (3, 2, 1, 1));
        assert_eq!(rgba, vec![3, 2, 7, 255]);

        let outside = InclusiveRectangle {
            left: 9,
            top: 0,
            right: 12,
            bottom: 1,
        };
        assert!(copy_region(&data, 16, 4, 4, 3, &outside).is_none());
        assert!(copy_region(&data, 12, 3, 4, 3, &region).is_none());
    }

    #[test]
    fn pointer_mask_changes_become_button_transitions() {
        let mut buttons = 0;
        let ops = operations(
            RemoteInput::Pointer {
                x: 10,
                y: 20,
                buttons: 0b101,
            },
            &mut buttons,
        );
        assert_eq!(ops.len(), 3);
        assert!(matches!(
            ops[0],
            Operation::MouseMove(MousePosition { x: 10, y: 20 })
        ));
        assert!(matches!(
            ops[1],
            Operation::MouseButtonPressed(MouseButton::Left)
        ));
        assert!(matches!(
            ops[2],
            Operation::MouseButtonPressed(MouseButton::Right)
        ));
        assert_eq!(buttons, 0b101);

        // Same mask again: movement only.
        let ops = operations(
            RemoteInput::Pointer {
                x: 11,
                y: 20,
                buttons: 0b101,
            },
            &mut buttons,
        );
        assert_eq!(ops.len(), 1);

        let ops = operations(
            RemoteInput::Pointer {
                x: 11,
                y: 20,
                buttons: 0b100,
            },
            &mut buttons,
        );
        assert!(matches!(
            ops[1],
            Operation::MouseButtonReleased(MouseButton::Left)
        ));
        assert_eq!(buttons, 0b100);
    }

    #[test]
    fn keys_prefer_the_scancode_and_fall_back_to_unicode() {
        let mut buttons = 0;
        let ops = operations(
            RemoteInput::Key {
                down: true,
                keysym: 0x61,
                scancode: 0x1E,
            },
            &mut buttons,
        );
        assert!(matches!(ops[..], [Operation::KeyPressed(code)] if code.as_u16() == 0x1E));

        let ops = operations(
            RemoteInput::Key {
                down: false,
                keysym: 0x0100_4E2D, // 中
                scancode: 0,
            },
            &mut buttons,
        );
        assert!(matches!(ops[..], [Operation::UnicodeKeyReleased('中')]));

        let ops = operations(
            RemoteInput::Key {
                down: true,
                keysym: 0xFFE1, // Shift_L has no character
                scancode: 0,
            },
            &mut buttons,
        );
        assert!(ops.is_empty());
    }

    #[test]
    fn wheel_is_clamped_and_converted_to_rotation_units() {
        let mut buttons = 0;
        let ops = operations(
            RemoteInput::Wheel {
                x: 1,
                y: 2,
                delta_x: 0,
                delta_y: -100,
            },
            &mut buttons,
        );
        assert_eq!(ops.len(), 2);
        assert!(matches!(
            ops[1],
            Operation::WheelRotations(WheelRotations {
                is_vertical: true,
                rotation_units: -960,
            })
        ));
    }

    #[test]
    fn config_requests_nla_with_the_given_credentials() {
        let config = build_config(&ConnectOptions {
            protocol: crate::RemoteProtocol::Rdp,
            host: "example.test".into(),
            port: 3389,
            username: Some("alice".into()),
            password: Some("secret".into()),
            domain: Some("  ".into()),
            width: 10,
            height: 20_000,
        });
        assert!(config.enable_tls && config.enable_credssp);
        assert_eq!(config.domain, None, "a blank domain is dropped");
        assert_eq!(config.desktop_size.width, crate::MIN_DESKTOP_SIZE);
        assert_eq!(config.desktop_size.height, crate::MAX_DESKTOP_SIZE);
        assert!(matches!(
            config.credentials,
            Credentials::UsernamePassword { ref username, ref password }
                if username == "alice" && password == "secret"
        ));
    }
}
