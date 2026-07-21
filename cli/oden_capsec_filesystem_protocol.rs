// Copyright 2018-2026 the Deno authors. MIT license.

use std::ffi::OsStr;
use std::ffi::OsString;

pub(crate) const REFUSAL_EXIT_CODE: i32 = 76;

pub(crate) struct ReservedRequest {
  pub(crate) manifest_digest: String,
  pub(crate) case_id: String,
}

pub(crate) fn parse_reserved_request(
  args: &[OsString],
  exact_flag: &str,
  reserved_prefix: &str,
) -> Option<Result<ReservedRequest, ()>> {
  if !args
    .iter()
    .skip(1)
    .any(|arg| os_bytes(arg).starts_with(reserved_prefix.as_bytes()))
  {
    return None;
  }
  Some(parse_exact_request(args, exact_flag))
}

fn parse_exact_request(
  args: &[OsString],
  exact_flag: &str,
) -> Result<ReservedRequest, ()> {
  if args.len() != 4 || os_bytes(&args[1]) != exact_flag.as_bytes() {
    return Err(());
  }
  let manifest_digest = canonical_ascii(&args[2]).ok_or(())?;
  if !is_canonical_sha256_digest(manifest_digest) {
    return Err(());
  }
  let case_id = canonical_ascii(&args[3]).ok_or(())?;
  if !is_canonical_identifier(case_id) {
    return Err(());
  }
  Ok(ReservedRequest {
    manifest_digest: manifest_digest.to_string(),
    case_id: case_id.to_string(),
  })
}

fn canonical_ascii(value: &OsStr) -> Option<&str> {
  let value = value.to_str()?;
  value.is_ascii().then_some(value)
}

pub(crate) fn is_canonical_sha256_digest(value: &str) -> bool {
  let Some(payload) = value.strip_prefix("sha256-") else {
    return false;
  };
  payload.len() == 43
    && payload
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    && payload
      .as_bytes()
      .last()
      .is_some_and(|last| b"AEIMQUYcgkosw048".contains(last))
}

pub(crate) fn is_canonical_identifier(value: &str) -> bool {
  !value.is_empty()
    && value.len() <= 4096
    && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(unix)]
#[allow(
  dead_code,
  reason = "transport remains dormant while the compiled case tables are empty"
)]
pub(crate) mod unix_transport {
  use std::io;
  use std::mem::size_of;
  use std::os::fd::AsFd;
  use std::os::fd::AsRawFd;
  use std::os::fd::BorrowedFd;
  use std::os::fd::FromRawFd;
  use std::os::fd::OwnedFd;
  use std::os::fd::RawFd;
  #[cfg(target_os = "macos")]
  use std::ptr;
  use std::time::Instant;

  use deno_core::serde_json::Value;

  pub(crate) const MAX_CONTROL_PACKET_BYTES: usize = 64 * 1024;
  pub(crate) const MAX_CANDIDATE_READY_PACKET_BYTES: usize = 16 * 1024;
  const FRAME_HEADER_BYTES: usize = size_of::<u32>();
  const LINUX_SCM_MAX_FD: usize = 253;
  const XNU_UIPC_MAX_CMSG_FD: usize = 512;
  const RECEIVE_CONTROL_BYTES: usize = 64 * 1024;
  // Keep the portable authored sender at Linux's lower per-message limit.
  pub(crate) const MAX_DESCRIPTOR_COUNT: usize = LINUX_SCM_MAX_FD;
  // XNU can internalize UIPC_MAX_CMSG_FD rights in one mbuf. Provisioning a
  // fixed, aligned 64-KiB receive buffer prevents MSG_CTRUNC from installing
  // rights whose descriptor numbers user space was never given and cannot
  // close. The conservative expression allows one aligned cmsg per right.
  const _: () = assert!(
    RECEIVE_CONTROL_BYTES
      >= XNU_UIPC_MAX_CMSG_FD
        * (size_of::<libc::cmsghdr>()
          + size_of::<RawFd>()
          + 2 * size_of::<usize>())
  );
  // TODO(ENG-24019): transport deadlines do not replace the supervisor's hard
  // child kill-and-reap deadline. Keep both compiled case tables empty until
  // that independent process-lifecycle barrier is implemented and captured.

  // @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
  // The native candidate channel carries one bounded logical frame and an
  // exact descriptor vector; descriptors become CLOEXEC before a frame escapes.
  #[derive(Debug)]
  pub(crate) struct FramedStreamEndpoint {
    fd: OwnedFd,
  }

  #[derive(Debug)]
  struct ReceivedPacket {
    bytes: Vec<u8>,
    descriptors: Vec<OwnedFd>,
  }

  #[derive(Debug)]
  pub(crate) struct ReceivedCanonicalJcsPacket {
    pub(crate) raw_bytes: Vec<u8>,
    pub(crate) value: Value,
    pub(crate) descriptors: Vec<OwnedFd>,
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) struct FrameByteLimit(usize);

  impl FrameByteLimit {
    pub(crate) const CONTROL: Self = Self(MAX_CONTROL_PACKET_BYTES);
    pub(crate) const CANDIDATE_READY: Self =
      Self(MAX_CANDIDATE_READY_PACKET_BYTES);

    fn bytes(self) -> usize {
      self.0
    }
  }

  impl FramedStreamEndpoint {
    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
      self.fd.as_fd()
    }

    pub(crate) fn send_packet_with_descriptors(
      &self,
      packet: &[u8],
      descriptors: &[BorrowedFd<'_>],
      deadline: Instant,
    ) -> io::Result<()> {
      self.send_packet_with_descriptors_bounded(
        packet,
        descriptors,
        FrameByteLimit::CONTROL,
        deadline,
      )
    }

    pub(crate) fn send_packet_with_descriptors_bounded(
      &self,
      packet: &[u8],
      descriptors: &[BorrowedFd<'_>],
      byte_limit: FrameByteLimit,
      deadline: Instant,
    ) -> io::Result<()> {
      let raw_descriptors = descriptors
        .iter()
        .map(AsRawFd::as_raw_fd)
        .collect::<Vec<_>>();
      self.send_packet_with_raw_descriptors_bounded(
        packet,
        &raw_descriptors,
        byte_limit,
        deadline,
        || {},
      )
    }

    // The spawn-result handoff consumes the parent's sole candidate-peer copy.
    // Its descriptor is closed immediately after the first positive sendmsg,
    // before any partial frame tail is written or an error can return.
    pub(crate) fn send_packet_transferring_descriptor(
      &self,
      packet: &[u8],
      descriptor: OwnedFd,
      deadline: Instant,
    ) -> io::Result<()> {
      let raw_descriptor = descriptor.as_raw_fd();
      self.send_packet_with_raw_descriptors_bounded(
        packet,
        &[raw_descriptor],
        FrameByteLimit::CONTROL,
        deadline,
        move || drop(descriptor),
      )
    }

    fn send_packet_with_raw_descriptors_bounded<F>(
      &self,
      packet: &[u8],
      descriptors: &[RawFd],
      byte_limit: FrameByteLimit,
      deadline: Instant,
      after_first_write: F,
    ) -> io::Result<()>
    where
      F: FnOnce(),
    {
      if packet.is_empty() {
        return Err(invalid_input("candidate packet must not be empty"));
      }
      if packet.len() > byte_limit.bytes() {
        return Err(invalid_input("candidate packet exceeds its frame bound"));
      }
      if descriptors.len() > MAX_DESCRIPTOR_COUNT {
        return Err(invalid_input(
          "candidate descriptor count exceeds protocol bound",
        ));
      }

      let payload_len = u32::try_from(packet.len()).map_err(|_| {
        invalid_input("candidate packet length exceeds frame encoding")
      })?;
      let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + packet.len());
      frame.extend_from_slice(&payload_len.to_be_bytes());
      frame.extend_from_slice(packet);

      let mut iov = libc::iovec {
        iov_base: frame.as_ptr().cast_mut().cast(),
        iov_len: frame.len(),
      };
      // SAFETY: zero is a valid initial state for msghdr.
      let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
      message.msg_iov = &mut iov;
      message.msg_iovlen = 1;

      let descriptor_payload_bytes = descriptor_bytes(descriptors.len())?;
      let control_bytes = if descriptors.is_empty() {
        0
      } else {
        cmsg_space(descriptor_payload_bytes)?
      };
      let mut control = aligned_control(control_bytes);
      if !descriptors.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control_bytes as _;

        // SAFETY: the aligned control allocation has CMSG_SPACE bytes and the
        // message points at it for the duration of sendmsg.
        unsafe {
          let cmsg = libc::CMSG_FIRSTHDR(&message);
          if cmsg.is_null() {
            return Err(io::Error::other(
              "failed to construct SCM_RIGHTS control message",
            ));
          }
          (*cmsg).cmsg_level = libc::SOL_SOCKET;
          (*cmsg).cmsg_type = libc::SCM_RIGHTS;
          (*cmsg).cmsg_len = cmsg_len(descriptor_payload_bytes)? as _;
          let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
          for (index, descriptor) in descriptors.iter().enumerate() {
            *data.add(index) = *descriptor;
          }
        }
      }

      #[cfg(any(target_os = "android", target_os = "linux"))]
      let flags = libc::MSG_NOSIGNAL;
      #[cfg(not(any(target_os = "android", target_os = "linux")))]
      let flags = 0;

      let first_written = loop {
        check_deadline(deadline)?;
        // SAFETY: message references the packet and optional aligned control
        // allocation, both of which remain alive across this call.
        let result =
          unsafe { libc::sendmsg(self.fd.as_raw_fd(), &message, flags) };
        if result >= 0 {
          break result as usize;
        }
        let error = io::Error::last_os_error();
        match error.kind() {
          io::ErrorKind::Interrupted => continue,
          io::ErrorKind::WouldBlock => {
            wait_for_io(self.fd.as_fd(), libc::POLLOUT, deadline)?;
          }
          _ => return Err(error),
        }
      };

      if first_written == 0 {
        return Err(write_zero());
      }
      after_first_write();
      let mut offset = first_written;
      while offset < frame.len() {
        let written = loop {
          check_deadline(deadline)?;
          // SAFETY: offset is bounded by frame.len(), so the remaining slice
          // is live for the duration of this no-ancillary send.
          let result = unsafe {
            libc::send(
              self.fd.as_raw_fd(),
              frame.as_ptr().add(offset).cast(),
              frame.len() - offset,
              flags,
            )
          };
          if result >= 0 {
            break result as usize;
          }
          let error = io::Error::last_os_error();
          match error.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => {
              wait_for_io(self.fd.as_fd(), libc::POLLOUT, deadline)?;
            }
            _ => return Err(error),
          }
        };
        if written == 0 {
          return Err(write_zero());
        }
        offset += written;
      }
      Ok(())
    }

    fn receive_packet_with_exact_descriptors(
      &self,
      expected_descriptor_count: usize,
      deadline: Instant,
    ) -> io::Result<ReceivedPacket> {
      // Do not expose frame bytes or received rights until EOF proves there is
      // no second frame. One caller-supplied monotonic deadline governs both.
      let packet = self.receive_one_frame(
        FrameByteLimit::CONTROL,
        expected_descriptor_count,
        deadline,
      )?;
      self.require_eof(deadline)?;
      Ok(packet)
    }

    fn receive_one_frame(
      &self,
      byte_limit: FrameByteLimit,
      expected_descriptor_count: usize,
      deadline: Instant,
    ) -> io::Result<ReceivedPacket> {
      receive_frame(
        self.fd.as_fd(),
        byte_limit,
        expected_descriptor_count,
        deadline,
      )
    }

    // @ref LLP 0019#parentsupervisor-transport-and-single-process-lifetime-cell
    // [implements] — The reusable transport exposes raw bytes for transcript
    // hashing only together with strict, byte-exact JCS validation. A later
    // role/state wrapper owns ordering, schema closure, and one batch deadline.
    pub(crate) fn receive_one_canonical_jcs_frame(
      &self,
      byte_limit: FrameByteLimit,
      expected_descriptor_count: usize,
      deadline: Instant,
    ) -> io::Result<ReceivedCanonicalJcsPacket> {
      let packet = self.receive_one_frame(
        byte_limit,
        expected_descriptor_count,
        deadline,
      )?;
      let value = parse_canonical_jcs(&packet.bytes)?;
      Ok(ReceivedCanonicalJcsPacket {
        raw_bytes: packet.bytes,
        value,
        descriptors: packet.descriptors,
      })
    }

    pub(crate) fn require_eof(&self, deadline: Instant) -> io::Result<()> {
      expect_eof(self.fd.as_fd(), deadline)
    }

    pub(crate) fn shutdown_write(&self) -> io::Result<()> {
      loop {
        // SAFETY: the endpoint owns a valid socket descriptor.
        let result =
          unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_WR) };
        if result == 0 {
          return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
          return Err(error);
        }
      }
    }
  }

  fn expect_eof(endpoint: BorrowedFd<'_>, deadline: Instant) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let mut ancillary = AncillaryState::new(0);
    let bytes_read = recv_chunk(endpoint, &mut byte, &mut ancillary, deadline)?;
    if bytes_read != 0 {
      return Err(invalid_data(
        "candidate channel contained bytes beyond its declared frame",
      ));
    }
    ancillary.finish()?;
    Ok(())
  }

  pub(crate) fn framed_stream_socketpair()
  -> io::Result<(FramedStreamEndpoint, FramedStreamEndpoint)> {
    let mut descriptors = [-1; 2];
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let socket_type =
      libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let socket_type = libc::SOCK_STREAM;

    // SAFETY: descriptors points to storage for the two socket descriptors.
    let result = unsafe {
      libc::socketpair(libc::AF_UNIX, socket_type, 0, descriptors.as_mut_ptr())
    };
    if result != 0 {
      return Err(io::Error::last_os_error());
    }

    // SAFETY: successful socketpair initialized both descriptors and transfers
    // their ownership to this function.
    let left = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: same as above for the second endpoint.
    let right = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
      set_cloexec(left.as_fd())?;
      set_nonblocking(left.as_fd())?;
      set_cloexec(right.as_fd())?;
      set_nonblocking(right.as_fd())?;
    }

    #[cfg(target_os = "macos")]
    {
      set_no_sigpipe(left.as_fd())?;
      set_no_sigpipe(right.as_fd())?;
    }

    Ok((
      FramedStreamEndpoint { fd: left },
      FramedStreamEndpoint { fd: right },
    ))
  }

  // @ref LLP 0019#parentsupervisor-transport-and-single-process-lifetime-cell
  // [implements] — A control frame is accepted only when its original bytes
  // are strict I-JSON and already equal to their RFC 8785 encoding. Parsing to
  // an ordinary map first would erase duplicate-key evidence.
  pub(crate) fn parse_canonical_jcs(packet: &[u8]) -> io::Result<Value> {
    let input = std::str::from_utf8(packet)
      .map_err(|_| invalid_data("candidate frame is not UTF-8 JSON"))?;
    let value = deno_runtime::deno_permissions::rev2::parse_strict_json(input)
      .map_err(|_| invalid_data("candidate frame is not strict I-JSON"))?;
    let canonical =
      deno_runtime::deno_permissions::rev2::canonical_json(&value)
        .map_err(|_| invalid_data("candidate frame is not canonical JCS"))?;
    if canonical.as_bytes() != packet {
      return Err(invalid_data("candidate frame is not canonical JCS"));
    }
    Ok(value)
  }

  fn receive_frame(
    endpoint: BorrowedFd<'_>,
    byte_limit: FrameByteLimit,
    expected_descriptor_count: usize,
    deadline: Instant,
  ) -> io::Result<ReceivedPacket> {
    if expected_descriptor_count > MAX_DESCRIPTOR_COUNT {
      return Err(invalid_input(
        "expected descriptor count exceeds protocol bound",
      ));
    }
    let mut ancillary = AncillaryState::new(expected_descriptor_count);
    let mut header = [0u8; FRAME_HEADER_BYTES];
    if expected_descriptor_count == 0 {
      recv_exact(endpoint, &mut header, &mut ancillary, deadline)?;
    } else {
      // SCM_RIGHTS is frozen to the first header byte, not merely the first
      // recvmsg that happens to cover some portion of the header. A one-byte
      // initial iovec makes a right attached to header bytes 2..4 observable
      // only by the next chunk, where AncillaryState rejects it as late.
      recv_exact(endpoint, &mut header[..1], &mut ancillary, deadline)?;
      recv_exact(endpoint, &mut header[1..], &mut ancillary, deadline)?;
    }
    let packet_len = u32::from_be_bytes(header) as usize;
    if packet_len == 0 || packet_len > byte_limit.bytes() {
      return Err(invalid_data(
        "candidate frame declared an invalid packet length",
      ));
    }
    let mut packet = vec![0u8; packet_len];
    recv_exact(endpoint, &mut packet, &mut ancillary, deadline)?;
    let descriptors = ancillary.finish()?;
    Ok(ReceivedPacket {
      bytes: packet,
      descriptors,
    })
  }

  fn recv_exact(
    endpoint: BorrowedFd<'_>,
    destination: &mut [u8],
    ancillary: &mut AncillaryState,
    deadline: Instant,
  ) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < destination.len() {
      let bytes_read =
        recv_chunk(endpoint, &mut destination[offset..], ancillary, deadline)?;
      if bytes_read == 0 {
        return Err(io::Error::new(
          io::ErrorKind::UnexpectedEof,
          "candidate channel closed inside its declared frame",
        ));
      }
      offset += bytes_read;
    }
    Ok(())
  }

  fn recv_chunk(
    endpoint: BorrowedFd<'_>,
    destination: &mut [u8],
    ancillary: &mut AncillaryState,
    deadline: Instant,
  ) -> io::Result<usize> {
    debug_assert!(!destination.is_empty());
    // Always provision the complete conservative bound, even when the
    // expected count is zero. See RECEIVE_CONTROL_BYTES above.
    let control_bytes = RECEIVE_CONTROL_BYTES;
    let mut iov = libc::iovec {
      iov_base: destination.as_mut_ptr().cast(),
      iov_len: destination.len(),
    };
    // SAFETY: zero is a valid initial state for msghdr.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.control.as_mut_ptr().cast();

    #[cfg(any(target_os = "android", target_os = "linux"))]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let flags = 0;

    let bytes_read = loop {
      check_deadline(deadline)?;
      message.msg_controllen = control_bytes as _;
      message.msg_flags = 0;
      // SAFETY: message owns writable payload and aligned ancillary buffers
      // for the complete duration of recvmsg.
      let result =
        unsafe { libc::recvmsg(endpoint.as_raw_fd(), &mut message, flags) };
      if result >= 0 {
        break result as usize;
      }
      let error = io::Error::last_os_error();
      match error.kind() {
        io::ErrorKind::Interrupted => continue,
        io::ErrorKind::WouldBlock => {
          wait_for_io(endpoint, libc::POLLIN, deadline)?;
        }
        _ => return Err(error),
      }
    };

    ancillary.absorb(&message)?;
    validate_message_flags(message.msg_flags)?;
    Ok(bytes_read)
  }

  fn validate_message_flags(flags: libc::c_int) -> io::Result<()> {
    if flags & libc::MSG_TRUNC != 0 {
      return Err(invalid_data("candidate frame data was truncated"));
    }
    if flags & libc::MSG_CTRUNC != 0 {
      return Err(invalid_data("candidate ancillary data was truncated"));
    }
    Ok(())
  }

  fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
      Err(timed_out())
    } else {
      Ok(())
    }
  }

  fn wait_for_io(
    descriptor: BorrowedFd<'_>,
    events: libc::c_short,
    deadline: Instant,
  ) -> io::Result<()> {
    loop {
      let timeout = poll_timeout(deadline)?;
      let mut pollfd = libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events,
        revents: 0,
      };
      // SAFETY: pollfd points to one initialized entry for this call.
      let result = unsafe { libc::poll(&mut pollfd, 1, timeout) };
      if result > 0 {
        if pollfd.revents & libc::POLLNVAL != 0 {
          return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        if pollfd.revents & (events | libc::POLLERR | libc::POLLHUP) != 0 {
          // The next send/recv reports the exact socket error or EOF.
          return Ok(());
        }
        continue;
      }
      if result == 0 {
        check_deadline(deadline)?;
        continue;
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn poll_timeout(deadline: Instant) -> io::Result<libc::c_int> {
    let remaining = deadline
      .checked_duration_since(Instant::now())
      .ok_or_else(timed_out)?;
    if remaining.is_zero() {
      return Err(timed_out());
    }
    let rounded_millis =
      remaining.as_nanos().saturating_add(999_999) / 1_000_000;
    Ok(rounded_millis.min(libc::c_int::MAX as u128) as libc::c_int)
  }

  struct AncillaryState {
    expected_count: usize,
    chunks_seen: usize,
    cmsg_count: usize,
    rights_cmsg_count: usize,
    descriptors: Vec<OwnedFd>,
    control: Vec<usize>,
  }

  impl AncillaryState {
    fn new(expected_count: usize) -> Self {
      Self {
        expected_count,
        chunks_seen: 0,
        cmsg_count: 0,
        rights_cmsg_count: 0,
        descriptors: Vec::new(),
        control: aligned_control(RECEIVE_CONTROL_BYTES),
      }
    }

    fn absorb(&mut self, message: &libc::msghdr) -> io::Result<()> {
      let control_start = message.msg_control as usize;
      let returned_control_len = message.msg_controllen as usize;
      let bounded_control_len = returned_control_len.min(RECEIVE_CONTROL_BYTES);
      let control_end = control_start
        .checked_add(bounded_control_len)
        .ok_or_else(|| invalid_data("candidate ancillary bounds overflow"))?;
      let minimum_cmsg_len = cmsg_len(0)?;
      let mut malformed = returned_control_len > RECEIVE_CONTROL_BYTES;
      let mut cloexec_error = None;
      let cmsg_count_before = self.cmsg_count;
      // CMSG traversal only needs the returned control pointer and its bounded
      // length. Never let a corrupt kernel length extend traversal past the
      // allocation owned by recv_chunk.
      // SAFETY: zero is a valid initial state for msghdr.
      let mut bounded_message: libc::msghdr = unsafe { std::mem::zeroed() };
      bounded_message.msg_control = message.msg_control;
      bounded_message.msg_controllen = bounded_control_len as _;

      // SAFETY: recvmsg populated the control allocation. Every header and
      // data range is checked against msg_controllen before it is read.
      unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&bounded_message);
        while !cmsg.is_null() {
          self.cmsg_count += 1;
          let cmsg_start = cmsg as usize;
          let header_end = cmsg_start.checked_add(size_of::<libc::cmsghdr>());
          if cmsg_start < control_start
            || header_end.is_none_or(|end| end > control_end)
          {
            malformed = true;
            break;
          }

          let declared_len = (*cmsg).cmsg_len as usize;
          if declared_len < minimum_cmsg_len {
            malformed = true;
            break;
          }
          let data_start = cmsg_start.checked_add(minimum_cmsg_len);
          if data_start.is_none_or(|start| start > control_end) {
            malformed = true;
            break;
          }

          let available_len = control_end - cmsg_start;
          let bounded_declared_len = declared_len.min(available_len);
          let cmsg_was_truncated = declared_len > available_len;
          malformed |= cmsg_was_truncated;

          let data_len = bounded_declared_len - minimum_cmsg_len;
          if (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
          {
            self.rights_cmsg_count += 1;
            if data_len % size_of::<RawFd>() != 0 {
              malformed = true;
            }
            let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
            for index in 0..(data_len / size_of::<RawFd>()) {
              let descriptor = OwnedFd::from_raw_fd(*data.add(index));
              #[cfg(not(any(target_os = "android", target_os = "linux")))]
              if let Err(error) = set_cloexec(descriptor.as_fd()) {
                cloexec_error.get_or_insert(error);
              }
              self.descriptors.push(descriptor);
            }
          }

          if cmsg_was_truncated {
            break;
          }
          cmsg = libc::CMSG_NXTHDR(&bounded_message, cmsg);
        }
      }

      let had_ancillary = self.cmsg_count != cmsg_count_before;
      let ancillary_was_late = self.chunks_seen != 0 && had_ancillary;
      self.chunks_seen += 1;

      // Every received right is owned before any error escapes, so all failure
      // paths close all descriptors observed by this process.
      if let Some(error) = cloexec_error {
        return Err(error);
      }
      if malformed {
        return Err(invalid_data("candidate ancillary data was malformed"));
      }
      if ancillary_was_late {
        return Err(invalid_data(
          "candidate ancillary data arrived after the first frame chunk",
        ));
      }
      Ok(())
    }

    fn finish(mut self) -> io::Result<Vec<OwnedFd>> {
      let ancillary_shape_is_exact = if self.expected_count == 0 {
        self.cmsg_count == 0 && self.rights_cmsg_count == 0
      } else {
        self.cmsg_count == 1 && self.rights_cmsg_count == 1
      };
      if !ancillary_shape_is_exact {
        return Err(invalid_data(
          "candidate frame did not contain the exact SCM_RIGHTS message",
        ));
      }
      if self.descriptors.len() != self.expected_count {
        return Err(invalid_data(
          "candidate frame contained the wrong descriptor count",
        ));
      }
      Ok(std::mem::take(&mut self.descriptors))
    }
  }

  fn descriptor_bytes(count: usize) -> io::Result<usize> {
    count
      .checked_mul(size_of::<RawFd>())
      .ok_or_else(|| invalid_input("candidate descriptor byte size overflow"))
  }

  fn cmsg_space(payload_bytes: usize) -> io::Result<usize> {
    let payload_bytes =
      libc::c_uint::try_from(payload_bytes).map_err(|_| {
        invalid_input("candidate ancillary payload exceeds platform bound")
      })?;
    // SAFETY: CMSG_SPACE performs only the platform alignment calculation.
    Ok(unsafe { libc::CMSG_SPACE(payload_bytes) as usize })
  }

  fn cmsg_len(payload_bytes: usize) -> io::Result<usize> {
    let payload_bytes =
      libc::c_uint::try_from(payload_bytes).map_err(|_| {
        invalid_input("candidate ancillary payload exceeds platform bound")
      })?;
    // SAFETY: CMSG_LEN performs only the platform alignment calculation.
    Ok(unsafe { libc::CMSG_LEN(payload_bytes) as usize })
  }

  fn aligned_control(byte_len: usize) -> Vec<usize> {
    vec![0; byte_len.div_ceil(size_of::<usize>())]
  }

  fn set_nonblocking(descriptor: BorrowedFd<'_>) -> io::Result<()> {
    let current_flags = loop {
      // SAFETY: F_GETFL reads status flags from a live descriptor.
      let result =
        unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
      if result >= 0 {
        break result;
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    };
    if current_flags & libc::O_NONBLOCK != 0 {
      return Ok(());
    }
    loop {
      // SAFETY: F_SETFL updates status flags on a live descriptor.
      let result = unsafe {
        libc::fcntl(
          descriptor.as_raw_fd(),
          libc::F_SETFL,
          current_flags | libc::O_NONBLOCK,
        )
      };
      if result == 0 {
        return Ok(());
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn set_cloexec(descriptor: BorrowedFd<'_>) -> io::Result<()> {
    let current_flags = loop {
      // SAFETY: F_GETFD reads flags from a live descriptor.
      let result =
        unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
      if result >= 0 {
        break result;
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    };
    if current_flags & libc::FD_CLOEXEC != 0 {
      return Ok(());
    }
    loop {
      // SAFETY: F_SETFD updates flags on a live descriptor.
      let result = unsafe {
        libc::fcntl(
          descriptor.as_raw_fd(),
          libc::F_SETFD,
          current_flags | libc::FD_CLOEXEC,
        )
      };
      if result == 0 {
        return Ok(());
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  #[cfg(target_os = "macos")]
  fn set_no_sigpipe(descriptor: BorrowedFd<'_>) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: enabled has the correct type and length for SO_NOSIGPIPE.
    let result = unsafe {
      libc::setsockopt(
        descriptor.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_NOSIGPIPE,
        ptr::from_ref(&enabled).cast(),
        size_of_val(&enabled) as libc::socklen_t,
      )
    };
    if result == 0 {
      Ok(())
    } else {
      Err(io::Error::last_os_error())
    }
  }

  fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
  }

  fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
  }

  fn write_zero() -> io::Error {
    io::Error::new(
      io::ErrorKind::WriteZero,
      "candidate frame transport made no write progress",
    )
  }

  fn timed_out() -> io::Error {
    io::Error::new(
      io::ErrorKind::TimedOut,
      "candidate frame transport deadline expired",
    )
  }

  #[cfg(test)]
  mod tests {
    use std::fs::File;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::ptr;
    use std::thread;
    use std::time::Duration;

    use super::*;

    #[test]
    fn stream_socketpair_and_received_descriptors_are_cloexec_and_ordered() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      assert_cloexec(sender.as_fd());
      assert_cloexec(receiver.as_fd());
      assert_nonblocking(sender.as_fd());
      assert_nonblocking(receiver.as_fd());

      let mut first = tempfile::tempfile().unwrap();
      let mut second = tempfile::tempfile().unwrap();
      first.write_all(b"first").unwrap();
      second.write_all(b"second").unwrap();
      first.seek(SeekFrom::Start(0)).unwrap();
      second.seek(SeekFrom::Start(0)).unwrap();
      sender
        .send_packet_with_descriptors(
          b"request",
          &[first.as_fd(), second.as_fd()],
          deadline(),
        )
        .unwrap();
      sender.shutdown_write().unwrap();

      let received = receiver
        .receive_packet_with_exact_descriptors(2, deadline())
        .unwrap();
      assert_eq!(received.bytes, b"request");
      assert_eq!(received.descriptors.len(), 2);
      assert_cloexec(received.descriptors[0].as_fd());
      assert_cloexec(received.descriptors[1].as_fd());

      let mut received_first =
        File::from(received.descriptors[0].try_clone().unwrap());
      let mut received_second =
        File::from(received.descriptors[1].try_clone().unwrap());
      let mut contents = String::new();
      received_first.read_to_string(&mut contents).unwrap();
      assert_eq!(contents, "first");
      contents.clear();
      received_second.read_to_string(&mut contents).unwrap();
      assert_eq!(contents, "second");
    }

    #[test]
    fn sole_peer_transfer_closes_the_sender_copy_before_receive() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let (read_end, write_end) = pipe_pair().unwrap();
      let transferred_raw = write_end.as_raw_fd();
      let final_deadline = deadline();

      sender
        .send_packet_transferring_descriptor(
          br#"{"schema":"spawn-result"}"#,
          write_end,
          final_deadline,
        )
        .unwrap();
      // SAFETY: F_GETFD does not mutate the descriptor table. No recvmsg has
      // run yet, so the transferred right cannot have reused this number.
      assert_eq!(unsafe { libc::fcntl(transferred_raw, libc::F_GETFD) }, -1);
      assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
      sender.shutdown_write().unwrap();

      let received = receiver
        .receive_one_canonical_jcs_frame(
          FrameByteLimit::CONTROL,
          1,
          final_deadline,
        )
        .unwrap();
      assert_eq!(received.value["schema"], "spawn-result");
      assert_eq!(received.descriptors.len(), 1);
      receiver.require_eof(final_deadline).unwrap();
      drop(received);
      assert_no_pipe_writer(read_end.as_fd());
    }

    #[test]
    fn missing_descriptors_are_rejected() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      sender
        .send_packet_with_descriptors(b"request", &[], deadline())
        .unwrap();
      sender.shutdown_write().unwrap();

      let error = receiver
        .receive_packet_with_exact_descriptors(1, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn extra_descriptors_are_rejected() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let first = tempfile::tempfile().unwrap();
      let second = tempfile::tempfile().unwrap();
      sender
        .send_packet_with_descriptors(
          b"request",
          &[first.as_fd(), second.as_fd()],
          deadline(),
        )
        .unwrap();
      sender.shutdown_write().unwrap();

      let error = receiver
        .receive_packet_with_exact_descriptors(1, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn response_descriptors_are_rejected_and_closed() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let (read_end, write_end) = pipe_pair().unwrap();
      sender
        .send_packet_with_descriptors(
          b"response",
          &[write_end.as_fd()],
          deadline(),
        )
        .unwrap();
      sender.shutdown_write().unwrap();

      let error = receiver
        .receive_packet_with_exact_descriptors(0, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      drop(write_end);
      assert_no_pipe_writer(read_end.as_fd());
    }

    #[test]
    fn late_ancillary_data_is_rejected_and_closed() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let (read_end, write_end) = pipe_pair().unwrap();
      send_raw(sender.as_fd(), &[0, 0, 0, 1]).unwrap();
      send_raw_with_descriptors(sender.as_fd(), b"x", &[write_end.as_fd()])
        .unwrap();
      sender.shutdown_write().unwrap();

      let error = receiver
        .receive_packet_with_exact_descriptors(1, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      drop(write_end);
      assert_no_pipe_writer(read_end.as_fd());
    }

    #[test]
    fn rights_attached_after_the_first_header_byte_are_rejected_and_closed() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let (read_end, write_end) = pipe_pair().unwrap();
      send_raw(sender.as_fd(), &[0]).unwrap();
      send_raw_with_descriptors(
        sender.as_fd(),
        &[0, 0, 1, b'x'],
        &[write_end.as_fd()],
      )
      .unwrap();
      sender.shutdown_write().unwrap();

      let error = receiver
        .receive_packet_with_exact_descriptors(1, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      drop(write_end);
      assert_no_pipe_writer(read_end.as_fd());
    }

    #[test]
    fn unexpected_ancillary_vector_is_rejected_and_closed() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let (first_read, first_write) = pipe_pair().unwrap();
      let (second_read, second_write) = pipe_pair().unwrap();
      sender
        .send_packet_with_descriptors(
          b"response",
          &[first_write.as_fd(), second_write.as_fd()],
          deadline(),
        )
        .unwrap();
      sender.shutdown_write().unwrap();

      let error = receiver
        .receive_packet_with_exact_descriptors(0, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      drop(first_write);
      drop(second_write);
      assert_no_pipe_writer(first_read.as_fd());
      assert_no_pipe_writer(second_read.as_fd());
    }

    #[test]
    fn truncation_flags_fail_closed() {
      for flag in [libc::MSG_TRUNC, libc::MSG_CTRUNC] {
        let error = validate_message_flags(flag).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      }
    }

    #[test]
    fn malformed_rights_length_still_owns_and_closes_returned_fds() {
      let (read_end, write_end) = pipe_pair().unwrap();
      // SAFETY: dup receives a live descriptor and returns a new owned one.
      let duplicated_raw = unsafe { libc::dup(write_end.as_raw_fd()) };
      assert!(duplicated_raw >= 0);
      // SAFETY: successful dup transferred ownership of duplicated_raw.
      let duplicated = unsafe { OwnedFd::from_raw_fd(duplicated_raw) };
      let transferred_raw = duplicated.into_raw_fd();

      let returned_len = cmsg_len(size_of::<RawFd>()).unwrap();
      let mut control =
        aligned_control(cmsg_space(size_of::<RawFd>()).unwrap());
      // SAFETY: zero is a valid initial state for msghdr.
      let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
      message.msg_control = control.as_mut_ptr().cast();
      message.msg_controllen = returned_len as _;
      // SAFETY: control is aligned and large enough for one returned right.
      unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        assert!(!cmsg.is_null());
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        // Deliberately claim one more fd than msg_controllen contains.
        (*cmsg).cmsg_len = (returned_len + size_of::<RawFd>()) as _;
        *libc::CMSG_DATA(cmsg).cast::<RawFd>() = transferred_raw;
      }

      let mut ancillary = AncillaryState::new(0);
      let error = ancillary.absorb(&message).unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      drop(ancillary);
      drop(write_end);
      assert_no_pipe_writer(read_end.as_fd());
    }

    #[test]
    fn receive_control_buffer_covers_supported_platform_maxima() {
      assert!(
        RECEIVE_CONTROL_BYTES
          >= cmsg_space(descriptor_bytes(XNU_UIPC_MAX_CMSG_FD).unwrap())
            .unwrap()
      );
      assert!(MAX_DESCRIPTOR_COUNT >= LINUX_SCM_MAX_FD);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_over_254_raw_rights_are_rejected_and_closed() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let (read_end, write_end) = pipe_pair().unwrap();
      // XNU's mbuf-level bound is 512 rights. Current 64-bit cmsg packing
      // admits 254 per raw cmsg, so two consecutive raw cmsgs exercise 508
      // installed duplicates—well above the portable authored sender bound.
      let rights = vec![write_end.as_fd(); 254];
      send_raw_with_descriptors(sender.as_fd(), &[0, 0], &rights).unwrap();
      send_raw_with_descriptors(sender.as_fd(), &[0, 1], &rights).unwrap();
      send_raw(sender.as_fd(), b"x").unwrap();
      sender.shutdown_write().unwrap();

      let error = receiver
        .receive_packet_with_exact_descriptors(0, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      drop(rights);
      drop(write_end);
      assert_no_pipe_writer(read_end.as_fd());
    }

    #[test]
    fn partial_header_and_payload_wait_within_deadline() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let sender_thread = thread::spawn(move || {
        send_raw(sender.as_fd(), &[0, 0]).unwrap();
        thread::sleep(Duration::from_millis(10));
        send_raw(sender.as_fd(), &[0, 4, b'a', b'b']).unwrap();
        thread::sleep(Duration::from_millis(10));
        send_raw(sender.as_fd(), b"cd").unwrap();
        sender.shutdown_write().unwrap();
      });

      let received = receiver
        .receive_packet_with_exact_descriptors(0, deadline())
        .unwrap();
      assert_eq!(received.bytes, b"abcd");
      sender_thread.join().unwrap();
    }

    #[test]
    fn missing_eof_times_out() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      sender
        .send_packet_with_descriptors(b"response", &[], deadline())
        .unwrap();
      let error = receiver
        .receive_packet_with_exact_descriptors(
          0,
          Instant::now() + Duration::from_millis(50),
        )
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::TimedOut);
      drop(sender);
    }

    #[test]
    fn blocked_send_times_out() {
      let (sender, _receiver) = framed_stream_socketpair().unwrap();
      fill_send_buffer(sender.as_fd());
      let error = sender
        .send_packet_with_descriptors(
          b"blocked",
          &[],
          Instant::now() + Duration::from_millis(50),
        )
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn premature_header_and_payload_eof_are_rejected() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      send_raw(sender.as_fd(), &[0, 0]).unwrap();
      sender.shutdown_write().unwrap();
      let error = receiver
        .receive_packet_with_exact_descriptors(0, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

      let (sender, receiver) = framed_stream_socketpair().unwrap();
      send_raw(sender.as_fd(), &[0, 0, 0, 4, b'a', b'b']).unwrap();
      sender.shutdown_write().unwrap();
      let error = receiver
        .receive_packet_with_exact_descriptors(0, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn bytes_beyond_declared_frame_are_rejected_before_eof() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      sender
        .send_packet_with_descriptors(b"first", &[], deadline())
        .unwrap();
      sender
        .send_packet_with_descriptors(b"second", &[], deadline())
        .unwrap();
      sender.shutdown_write().unwrap();

      let error = receiver
        .receive_packet_with_exact_descriptors(0, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn ordered_frames_are_received_before_explicit_eof() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let final_deadline = deadline();
      sender
        .send_packet_with_descriptors(
          br#"{"schema":"ready"}"#,
          &[],
          final_deadline,
        )
        .unwrap();
      sender
        .send_packet_with_descriptors(
          br#"{"schema":"response"}"#,
          &[],
          final_deadline,
        )
        .unwrap();
      sender.shutdown_write().unwrap();

      let ready = receiver
        .receive_one_canonical_jcs_frame(
          FrameByteLimit::CANDIDATE_READY,
          0,
          final_deadline,
        )
        .unwrap();
      assert_eq!(ready.raw_bytes, br#"{"schema":"ready"}"#);
      assert_eq!(ready.value["schema"], "ready");
      assert!(ready.descriptors.is_empty());
      let response = receiver
        .receive_one_canonical_jcs_frame(
          FrameByteLimit::CONTROL,
          0,
          final_deadline,
        )
        .unwrap();
      assert_eq!(response.raw_bytes, br#"{"schema":"response"}"#);
      assert_eq!(response.value["schema"], "response");
      assert!(response.descriptors.is_empty());
      receiver.require_eof(final_deadline).unwrap();
    }

    #[test]
    fn candidate_ready_uses_its_distinct_16_kib_bound() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let oversized_ready = vec![b'x'; MAX_CANDIDATE_READY_PACKET_BYTES + 1];
      send_raw(
        sender.as_fd(),
        &(oversized_ready.len() as u32).to_be_bytes(),
      )
      .unwrap();

      let error = receiver
        .receive_one_frame(FrameByteLimit::CANDIDATE_READY, 0, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);

      let (sender, _receiver) = framed_stream_socketpair().unwrap();
      let error = sender
        .send_packet_with_descriptors_bounded(
          &oversized_ready,
          &[],
          FrameByteLimit::CANDIDATE_READY,
          deadline(),
        )
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn control_json_requires_strict_byte_exact_jcs() {
      let value = parse_canonical_jcs(br#"{"a":1,"b":[true,null]}"#).unwrap();
      assert_eq!(value["a"], 1);

      for invalid in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"b":2,"a":1}"#,
        br#"{ "a":1}"#,
        br#"{"a":1.0}"#,
        br#"{"a":9007199254740992}"#,
        b"\xff",
      ] {
        let error = parse_canonical_jcs(invalid).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      }
    }

    #[test]
    fn canonical_frame_gate_closes_rights_on_json_refusal() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let (read_end, write_end) = pipe_pair().unwrap();
      let final_deadline = deadline();
      sender
        .send_packet_with_descriptors(
          br#"{"b":2,"a":1}"#,
          &[write_end.as_fd()],
          final_deadline,
        )
        .unwrap();

      let error = receiver
        .receive_one_canonical_jcs_frame(
          FrameByteLimit::CONTROL,
          1,
          final_deadline,
        )
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      drop(write_end);
      assert_no_pipe_writer(read_end.as_fd());
    }

    #[test]
    fn packet_bound_invalid_lengths_and_early_eof_are_rejected() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      let oversized = vec![0u8; MAX_CONTROL_PACKET_BYTES + 1];
      let error = sender
        .send_packet_with_descriptors(&oversized, &[], deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
      sender.shutdown_write().unwrap();
      let error = receiver
        .receive_packet_with_exact_descriptors(0, deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

      for header in [[0, 0, 0, 0], [0, 1, 0, 1]] {
        let (sender, receiver) = framed_stream_socketpair().unwrap();
        send_raw(sender.as_fd(), &header).unwrap();
        sender.shutdown_write().unwrap();
        let error = receiver
          .receive_packet_with_exact_descriptors(0, deadline())
          .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      }
    }

    #[test]
    fn public_receive_returns_only_after_peer_eof() {
      let (sender, receiver) = framed_stream_socketpair().unwrap();
      sender
        .send_packet_with_descriptors(b"response", &[], deadline())
        .unwrap();
      sender.shutdown_write().unwrap();
      let received = receiver
        .receive_packet_with_exact_descriptors(0, deadline())
        .unwrap();
      assert_eq!(received.bytes, b"response");
    }

    fn assert_cloexec(descriptor: BorrowedFd<'_>) {
      // SAFETY: F_GETFD reads flags from a live descriptor.
      let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
      assert!(flags >= 0);
      assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    fn assert_nonblocking(descriptor: BorrowedFd<'_>) {
      // SAFETY: F_GETFL reads status flags from a live descriptor.
      let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
      assert!(flags >= 0);
      assert_ne!(flags & libc::O_NONBLOCK, 0);
    }

    fn deadline() -> Instant {
      Instant::now() + Duration::from_secs(2)
    }

    fn pipe_pair() -> io::Result<(OwnedFd, OwnedFd)> {
      let mut descriptors = [-1; 2];
      // SAFETY: descriptors points to storage for two pipe descriptors.
      if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
      }
      // SAFETY: successful pipe initialized both owned descriptors.
      let read_end = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
      // SAFETY: same as above for the write endpoint.
      let write_end = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
      Ok((read_end, write_end))
    }

    fn send_raw(descriptor: BorrowedFd<'_>, bytes: &[u8]) -> io::Result<()> {
      let mut offset = 0usize;
      while offset < bytes.len() {
        // SAFETY: offset is bounded by bytes.len() and the remaining slice is
        // live for the duration of send.
        let result = unsafe {
          libc::send(
            descriptor.as_raw_fd(),
            bytes.as_ptr().add(offset).cast(),
            bytes.len() - offset,
            0,
          )
        };
        if result > 0 {
          offset += result as usize;
        } else if result == 0 {
          return Err(write_zero());
        } else {
          let error = io::Error::last_os_error();
          if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
          }
        }
      }
      Ok(())
    }

    fn send_raw_with_descriptors(
      socket: BorrowedFd<'_>,
      bytes: &[u8],
      descriptors: &[BorrowedFd<'_>],
    ) -> io::Result<()> {
      let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
      };
      let descriptor_payload_bytes = descriptor_bytes(descriptors.len())?;
      let control_bytes = cmsg_space(descriptor_payload_bytes)?;
      let mut control = aligned_control(control_bytes);
      // SAFETY: zero is a valid initial state for msghdr.
      let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
      message.msg_iov = &mut iov;
      message.msg_iovlen = 1;
      message.msg_control = control.as_mut_ptr().cast();
      message.msg_controllen = control_bytes as _;

      // SAFETY: control has enough aligned storage for all descriptors.
      unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        if cmsg.is_null() {
          return Err(io::Error::other("failed to build test control message"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = cmsg_len(descriptor_payload_bytes)? as _;
        let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
        for (index, descriptor) in descriptors.iter().enumerate() {
          *data.add(index) = descriptor.as_raw_fd();
        }
      }

      loop {
        // SAFETY: message references live payload and control allocations.
        let result = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, 0) };
        if result == bytes.len() as isize {
          return Ok(());
        }
        if result >= 0 {
          return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "test control message was partially sent",
          ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
          return Err(error);
        }
      }
    }

    fn assert_no_pipe_writer(read_end: BorrowedFd<'_>) {
      set_nonblocking(read_end).unwrap();
      let final_deadline = deadline();
      loop {
        let mut byte = 0u8;
        // SAFETY: byte is valid one-byte writable storage.
        let result = unsafe {
          libc::read(read_end.as_raw_fd(), ptr::from_mut(&mut byte).cast(), 1)
        };
        if result == 0 {
          return;
        }
        let error = io::Error::last_os_error();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(
          Instant::now() < final_deadline,
          "a rejected received descriptor leaked"
        );
        thread::sleep(Duration::from_millis(10));
      }
    }

    fn fill_send_buffer(descriptor: BorrowedFd<'_>) {
      let bytes = [0u8; 4096];
      loop {
        // SAFETY: bytes is readable for the complete send call.
        let result = unsafe {
          libc::send(
            descriptor.as_raw_fd(),
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
          )
        };
        if result > 0 {
          continue;
        }
        if result == 0 {
          panic!("socket send buffer stopped without EAGAIN");
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
          continue;
        }
        if error.kind() == io::ErrorKind::WouldBlock {
          return;
        }
        panic!("failed to fill socket send buffer: {error}");
      }
    }
  }
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> &[u8] {
  use std::os::unix::ffi::OsStrExt;
  value.as_bytes()
}

#[cfg(not(unix))]
fn os_bytes(value: &OsStr) -> &[u8] {
  value.to_str().map(str::as_bytes).unwrap_or_default()
}
