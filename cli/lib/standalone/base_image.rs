// Copyright 2018-2026 the Deno authors. MIT license.

//! Strict structural projection for the `denort` executable underlying an
//! Oden filesystem-parent standalone.
//!
//! This module intentionally understands only the frozen release formats. A
//! construct whose physical bytes cannot yet be accounted for is rejected as
//! unsupported instead of being omitted from the projection.

// @ref LLP 0019#denort-base-image-structural-projection-and-loaded-identity [implements] —
// The parent commitment binds a closed ELF64 or thin Mach-O projection while
// excluding only the exact, independently validated libsui embedding.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use thiserror::Error;

pub const DENORT_BASE_IMAGE_PROJECTION_SCHEMA: &str =
  "oden/capsec-denort-base-image-projection/1";
pub const DENORT_BASE_IMAGE_PROJECTION_DOMAIN: &str =
  "oden:capsec:denort-base-image-projection:1";

const ELF_LOAD_BYTES_DOMAIN: &str =
  "oden:capsec:denort-base-image-elf-load-bytes:1";
const MACHO_SEGMENT_BYTES_DOMAIN: &str =
  "oden:capsec:denort-base-image-macho-segment-bytes:1";
const MACHO_LINKEDIT_BYTES_DOMAIN: &str =
  "oden:capsec:denort-base-image-macho-linkedit-blob:1";
const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;

const ELF_HEADER_SIZE: usize = 64;
const ELF_PROGRAM_HEADER_MIN_SIZE: usize = 56;
const ELF_SECTION_HEADER_MIN_SIZE: usize = 64;
const ELF_PT_LOAD: u32 = 1;
const ELF_PT_NOTE: u32 = 4;
const ELF_PT_PHDR: u32 = 6;
const ELF_PF_R: u32 = 4;
const ELF_SUI_NOTE_TYPE: u32 = 0x5355_4901;
const ELF_SUI_OWNER: &[u8] = b"d3n0l4nd";

const MACHO_HEADER_SIZE: usize = 32;
const MACHO_MAGIC_64_LE: u32 = 0xfeed_facf;
const MACHO_FILETYPE_EXECUTE: u32 = 2;
const MACHO_CPU_X86_64: u32 = 0x0100_0007;
const MACHO_CPU_ARM64: u32 = 0x0100_000c;
const MACHO_LC_SEGMENT_64: u32 = 0x19;
const MACHO_LC_SYMTAB: u32 = 0x02;
const MACHO_LC_DYSYMTAB: u32 = 0x0b;
const MACHO_LC_CODE_SIGNATURE: u32 = 0x1d;
const MACHO_LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
const MACHO_LC_TWOLEVEL_HINTS: u32 = 0x16;
const MACHO_LC_DYLD_INFO: u32 = 0x22;
const MACHO_LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const MACHO_LC_FUNCTION_STARTS: u32 = 0x26;
const MACHO_LC_DATA_IN_CODE: u32 = 0x29;
const MACHO_LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
const MACHO_LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
const MACHO_LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const MACHO_LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const MACHO_LC_ATOM_INFO: u32 = 0x36;
const MACHO_LC_FUNCTION_VARIANTS: u32 = 0x37;
const MACHO_LC_FUNCTION_VARIANT_FIXUPS: u32 = 0x38;
const MACHO_SUI_SENTINEL: &[u8; 16] = b"<~sui-data~>\xef\xbe\xad\xde";
const MACHO_SEGMENT_COMMAND_SIZE: usize = 72;
const MACHO_SECTION_SIZE: usize = 80;
const MACHO_X86_64_PAGE_SIZE: u64 = 0x1000;
const MACHO_ARM64_PAGE_SIZE: u64 = 0x4000;
const MACHO_SEG_LINKEDIT: [u8; 16] = *b"__LINKEDIT\0\0\0\0\0\0";
const MACHO_SEG_SUI: [u8; 16] = *b"__SUI\0\0\0\0\0\0\0\0\0\0\0";
const MACHO_SEC_SUI: [u8; 16] = *b"d3n0l4nd\0\0\0\0\0\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenortBaseImageTarget {
  Aarch64AppleDarwin,
  X86_64AppleDarwin,
  Aarch64UnknownLinuxGnu,
  X86_64UnknownLinuxGnu,
}

// @ref LLP 0019#backend-status [constrained-by] — Public projection admits
// only the exact current two-target tuple; deferred physical-layout code is
// retained solely behind the private regression helper.
impl DenortBaseImageTarget {
  fn is_current_release_target(self) -> bool {
    matches!(self, Self::Aarch64AppleDarwin | Self::X86_64UnknownLinuxGnu)
  }

  fn architecture(self) -> &'static str {
    match self {
      Self::Aarch64AppleDarwin | Self::Aarch64UnknownLinuxGnu => "aarch64",
      Self::X86_64AppleDarwin | Self::X86_64UnknownLinuxGnu => "x86_64",
    }
  }

  fn expects_elf(self) -> bool {
    matches!(
      self,
      Self::Aarch64UnknownLinuxGnu | Self::X86_64UnknownLinuxGnu
    )
  }

  fn elf_machine(self) -> Option<u16> {
    match self {
      Self::Aarch64UnknownLinuxGnu => Some(183),
      Self::X86_64UnknownLinuxGnu => Some(62),
      _ => None,
    }
  }

  fn macho_cpu(self) -> Option<u32> {
    match self {
      Self::Aarch64AppleDarwin => Some(MACHO_CPU_ARM64),
      Self::X86_64AppleDarwin => Some(MACHO_CPU_X86_64),
      _ => None,
    }
  }
}

impl TryFrom<&str> for DenortBaseImageTarget {
  type Error = DenortBaseImageError;

  fn try_from(value: &str) -> Result<Self, Self::Error> {
    match value {
      "aarch64-apple-darwin" => Ok(Self::Aarch64AppleDarwin),
      "x86_64-unknown-linux-gnu" => Ok(Self::X86_64UnknownLinuxGnu),
      _ => Err(DenortBaseImageError::Unsupported(
        "target is outside the current Oden release matrix",
      )),
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub enum DenortBaseImageMode<'a> {
  Base,
  SuiEmbedded { standalone_data: &'a [u8] },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DenortBaseImageError {
  #[error("malformed denort base image: {0}")]
  Malformed(&'static str),
  #[error("ambiguous denort base image: {0}")]
  Ambiguous(&'static str),
  #[error("unsupported denort base image construct: {0}")]
  Unsupported(&'static str),
  #[error("denort base image target mismatch: {0}")]
  TargetMismatch(&'static str),
  #[error("denort base image arithmetic overflow: {0}")]
  Overflow(&'static str),
  #[error("denort base image range is outside the file: {0}")]
  OutOfFile(&'static str),
  #[error("denort base image canonicalization failed: {0}")]
  Canonical(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
/// A validated, canonical projection of a `denort` base image.
///
/// Projection records can only be obtained by parsing image bytes. Their
/// constituent fields are intentionally opaque to external callers, so a
/// caller cannot fabricate a digest-capable projection:
///
/// ```compile_fail
/// use deno_lib::standalone::base_image::ElfBaseImageProjection;
///
/// let _fabricated = ElfBaseImageProjection {
///   architecture: "x86_64",
///   format: "elf64-little-endian",
///   header_bytes: String::new(),
///   program_headers: Vec::new(),
///   schema: "oden/capsec-denort-base-image-projection/1",
/// };
/// ```
///
/// Parsed projection fields cannot be mutated outside this module either:
///
/// ```compile_fail
/// use deno_lib::standalone::base_image::DenortBaseImageProjection;
///
/// fn mutate(projection: &mut DenortBaseImageProjection) {
///   if let DenortBaseImageProjection::Elf(elf) = projection {
///     elf.header_bytes.clear();
///   }
/// }
/// ```
pub enum DenortBaseImageProjection {
  Elf(ElfBaseImageProjection),
  MachO(MachOBaseImageProjection),
}

impl DenortBaseImageProjection {
  pub fn canonical_json(&self) -> Result<String, DenortBaseImageError> {
    let value = serde_json::to_value(self).map_err(|_| {
      DenortBaseImageError::Canonical("projection serialization failed")
    })?;
    canonical_json(&value)
  }

  pub fn digest(&self) -> Result<String, DenortBaseImageError> {
    let canonical = self.canonical_json()?;
    framed_digest(DENORT_BASE_IMAGE_PROJECTION_DOMAIN, canonical.as_bytes())
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfBaseImageProjection {
  architecture: &'static str,
  format: &'static str,
  header_bytes: String,
  program_headers: Vec<ElfProgramHeaderProjection>,
  schema: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfProgramHeaderProjection {
  canonical_bytes: String,
  index: u64,
  normalization: Option<&'static str>,
  payload_byte_length: Option<u64>,
  payload_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOBaseImageProjection {
  architecture: &'static str,
  format: &'static str,
  header_bytes: String,
  load_commands: Vec<MachOLoadCommandProjection>,
  payloads: Vec<MachOPayloadProjection>,
  schema: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOLoadCommandProjection {
  canonical_bytes: String,
  index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOPayloadProjection {
  byte_length: u64,
  digest: String,
  kind: MachOPayloadKind,
  owner: String,
  ordinal: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MachOPayloadKind {
  Segment,
  Linkedit,
  LinkeditPadding,
}

pub fn project_denort_base_image(
  bytes: &[u8],
  target: DenortBaseImageTarget,
  mode: DenortBaseImageMode<'_>,
) -> Result<DenortBaseImageProjection, DenortBaseImageError> {
  if !target.is_current_release_target() {
    return Err(DenortBaseImageError::Unsupported(
      "target is outside the current Oden release matrix",
    ));
  }
  project_denort_base_image_layout(bytes, target, mode)
}

fn project_denort_base_image_layout(
  bytes: &[u8],
  target: DenortBaseImageTarget,
  mode: DenortBaseImageMode<'_>,
) -> Result<DenortBaseImageProjection, DenortBaseImageError> {
  if target.expects_elf() {
    project_elf(bytes, target, mode).map(DenortBaseImageProjection::Elf)
  } else {
    project_macho(bytes, target, mode).map(DenortBaseImageProjection::MachO)
  }
}

pub fn denort_base_image_projection_digest(
  bytes: &[u8],
  target: DenortBaseImageTarget,
  mode: DenortBaseImageMode<'_>,
) -> Result<String, DenortBaseImageError> {
  project_denort_base_image(bytes, target, mode)?.digest()
}

fn framed_digest(
  domain: &str,
  payload: &[u8],
) -> Result<String, DenortBaseImageError> {
  if domain.is_empty()
    || !domain.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
  {
    return Err(DenortBaseImageError::Canonical(
      "digest domain is not nonempty printable ASCII",
    ));
  }
  let mut digest = Sha256::new();
  digest.update(domain.as_bytes());
  digest.update([0]);
  digest.update(payload);
  Ok(format!(
    "sha256-{}",
    URL_SAFE_NO_PAD.encode(digest.finalize())
  ))
}

fn hbytes(domain: &str, bytes: &[u8]) -> Result<String, DenortBaseImageError> {
  framed_digest(domain, bytes)
}

fn canonical_json(value: &Value) -> Result<String, DenortBaseImageError> {
  fn write(
    value: &Value,
    output: &mut String,
  ) -> Result<(), DenortBaseImageError> {
    match value {
      Value::Null => output.push_str("null"),
      Value::Bool(value) => {
        output.push_str(if *value { "true" } else { "false" })
      }
      Value::Number(value) => {
        let Some(value) = value.as_u64() else {
          return Err(DenortBaseImageError::Canonical(
            "projection contains a non-unsigned integer",
          ));
        };
        if value > MAX_IJSON_INTEGER {
          return Err(DenortBaseImageError::Canonical(
            "projection integer exceeds the I-JSON safe range",
          ));
        }
        output.push_str(&value.to_string());
      }
      Value::String(value) => {
        output.push_str(&serde_json::to_string(value).map_err(|_| {
          DenortBaseImageError::Canonical("projection string encoding failed")
        })?)
      }
      Value::Array(values) => {
        output.push('[');
        for (index, value) in values.iter().enumerate() {
          if index != 0 {
            output.push(',');
          }
          write(value, output)?;
        }
        output.push(']');
      }
      Value::Object(object) => {
        output.push('{');
        let mut keys = object.keys().collect::<Vec<_>>();
        keys
          .sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
        for (index, key) in keys.into_iter().enumerate() {
          if index != 0 {
            output.push(',');
          }
          output.push_str(&serde_json::to_string(key).map_err(|_| {
            DenortBaseImageError::Canonical(
              "projection object-key encoding failed",
            )
          })?);
          output.push(':');
          write(&object[key], output)?;
        }
        output.push('}');
      }
    }
    Ok(())
  }

  let mut output = String::new();
  write(value, &mut output)?;
  Ok(output)
}

fn json_integer(value: usize) -> Result<u64, DenortBaseImageError> {
  let value = u64::try_from(value)
    .map_err(|_| DenortBaseImageError::Overflow("integer does not fit u64"))?;
  if value > MAX_IJSON_INTEGER {
    return Err(DenortBaseImageError::Unsupported(
      "projection integer exceeds the I-JSON safe range",
    ));
  }
  Ok(value)
}

fn checked_range(
  offset: u64,
  length: u64,
  file_len: usize,
  label: &'static str,
) -> Result<std::ops::Range<usize>, DenortBaseImageError> {
  let end = offset
    .checked_add(length)
    .ok_or(DenortBaseImageError::Overflow(label))?;
  let start = usize::try_from(offset)
    .map_err(|_| DenortBaseImageError::OutOfFile(label))?;
  let end =
    usize::try_from(end).map_err(|_| DenortBaseImageError::OutOfFile(label))?;
  if end > file_len {
    return Err(DenortBaseImageError::OutOfFile(label));
  }
  Ok(start..end)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DenortBaseImageError> {
  let end = offset
    .checked_add(2)
    .ok_or(DenortBaseImageError::Overflow("u16 field offset"))?;
  let value = bytes
    .get(offset..end)
    .ok_or(DenortBaseImageError::OutOfFile("u16 field"))?;
  Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DenortBaseImageError> {
  let end = offset
    .checked_add(4)
    .ok_or(DenortBaseImageError::Overflow("u32 field offset"))?;
  let value = bytes
    .get(offset..end)
    .ok_or(DenortBaseImageError::OutOfFile("u32 field"))?;
  Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DenortBaseImageError> {
  let end = offset
    .checked_add(8)
    .ok_or(DenortBaseImageError::Overflow("u64 field offset"))?;
  let value = bytes
    .get(offset..end)
    .ok_or(DenortBaseImageError::OutOfFile("u64 field"))?;
  Ok(u64::from_le_bytes([
    value[0], value[1], value[2], value[3], value[4], value[5], value[6],
    value[7],
  ]))
}

fn write_zero(bytes: &mut [u8], offset: usize, length: usize) {
  bytes[offset..offset + length].fill(0);
}

fn write_u32_field(
  bytes: &mut [u8],
  offset: usize,
  value: u32,
) -> Result<(), DenortBaseImageError> {
  let end = offset
    .checked_add(4)
    .ok_or(DenortBaseImageError::Overflow("u32 output field offset"))?;
  let field =
    bytes
      .get_mut(offset..end)
      .ok_or(DenortBaseImageError::Malformed(
        "u32 output field is truncated",
      ))?;
  field.copy_from_slice(&value.to_le_bytes());
  Ok(())
}

fn align_up(value: u64, alignment: u64) -> Result<u64, DenortBaseImageError> {
  if alignment == 0 || !alignment.is_power_of_two() {
    return Err(DenortBaseImageError::Malformed(
      "alignment is zero or not a power of two",
    ));
  }
  value
    .checked_add(alignment - 1)
    .map(|value| value & !(alignment - 1))
    .ok_or(DenortBaseImageError::Overflow("alignment"))
}

#[derive(Debug, Clone)]
struct ElfProgramHeader<'a> {
  raw: &'a [u8],
  index: usize,
  p_type: u32,
  flags: u32,
  offset: u64,
  vaddr: u64,
  paddr: u64,
  filesz: u64,
  memsz: u64,
  alignment: u64,
}

fn project_elf(
  bytes: &[u8],
  target: DenortBaseImageTarget,
  mode: DenortBaseImageMode<'_>,
) -> Result<ElfBaseImageProjection, DenortBaseImageError> {
  if bytes.len() < ELF_HEADER_SIZE {
    return Err(DenortBaseImageError::Malformed("ELF header is truncated"));
  }
  if bytes.get(..4) != Some(b"\x7fELF") {
    return Err(DenortBaseImageError::TargetMismatch(
      "Linux target does not contain an ELF image",
    ));
  }
  if bytes[4] != 2 {
    return Err(DenortBaseImageError::Unsupported("only ELF64 is accepted"));
  }
  if bytes[5] != 1 {
    return Err(DenortBaseImageError::Unsupported(
      "only little-endian ELF is accepted",
    ));
  }
  if bytes[6] != 1 || read_u32(bytes, 20)? != 1 {
    return Err(DenortBaseImageError::Malformed(
      "ELF version is not current",
    ));
  }
  if read_u16(bytes, 16)? != 3 {
    return Err(DenortBaseImageError::Unsupported(
      "Linux denort must be ET_DYN PIE",
    ));
  }
  let expected_machine =
    target
      .elf_machine()
      .ok_or(DenortBaseImageError::TargetMismatch(
        "Darwin target was routed to ELF",
      ))?;
  if read_u16(bytes, 18)? != expected_machine {
    return Err(DenortBaseImageError::TargetMismatch(
      "ELF e_machine does not match the selected target",
    ));
  }
  if read_u16(bytes, 52)? as usize != ELF_HEADER_SIZE {
    return Err(DenortBaseImageError::Unsupported(
      "ELF header size is not the frozen ELF64 size",
    ));
  }
  validate_elf_section_header_table(bytes)?;

  let program_header_offset = read_u64(bytes, 32)?;
  let entry_size = read_u16(bytes, 54)? as usize;
  let entry_count = read_u16(bytes, 56)? as usize;
  if entry_size < ELF_PROGRAM_HEADER_MIN_SIZE {
    return Err(DenortBaseImageError::Malformed(
      "ELF program-header entries are shorter than ELF64",
    ));
  }
  if entry_count == 0 {
    return Err(DenortBaseImageError::Malformed(
      "ELF has no program headers",
    ));
  }
  if entry_count == 0xffff {
    return Err(DenortBaseImageError::Unsupported(
      "extended ELF program-header counts are not accepted",
    ));
  }
  let table_length = entry_size.checked_mul(entry_count).ok_or(
    DenortBaseImageError::Overflow("ELF program-header table length"),
  )?;
  let table_range = checked_range(
    program_header_offset,
    u64::try_from(table_length).map_err(|_| {
      DenortBaseImageError::Overflow("ELF program-header table length")
    })?,
    bytes.len(),
    "ELF program-header table",
  )?;
  if table_range.start == 0 {
    return Err(DenortBaseImageError::Malformed(
      "ELF program-header table has zero offset",
    ));
  }

  let mut headers = Vec::with_capacity(entry_count);
  let mut pt_phdr_count = 0usize;
  for index in 0..entry_count {
    let offset = table_range
      .start
      .checked_add(index.checked_mul(entry_size).ok_or(
        DenortBaseImageError::Overflow("ELF program-header entry offset"),
      )?)
      .ok_or(DenortBaseImageError::Overflow(
        "ELF program-header entry offset",
      ))?;
    let raw = bytes
      .get(offset..offset + entry_size)
      .ok_or(DenortBaseImageError::OutOfFile("ELF program-header entry"))?;
    let header = ElfProgramHeader {
      raw,
      index,
      p_type: read_u32(raw, 0)?,
      flags: read_u32(raw, 4)?,
      offset: read_u64(raw, 8)?,
      vaddr: read_u64(raw, 16)?,
      paddr: read_u64(raw, 24)?,
      filesz: read_u64(raw, 32)?,
      memsz: read_u64(raw, 40)?,
      alignment: read_u64(raw, 48)?,
    };
    if header.p_type == ELF_PT_PHDR {
      pt_phdr_count += 1;
    }
    if header.filesz != 0 {
      checked_range(
        header.offset,
        header.filesz,
        bytes.len(),
        "ELF program-header file range",
      )?;
    }
    if header.p_type == ELF_PT_LOAD {
      if header.filesz > header.memsz {
        return Err(DenortBaseImageError::Malformed(
          "ELF PT_LOAD filesz exceeds memsz",
        ));
      }
      if header.alignment > 1 {
        if !header.alignment.is_power_of_two() {
          return Err(DenortBaseImageError::Malformed(
            "ELF PT_LOAD alignment is not a power of two",
          ));
        }
        if header.offset % header.alignment != header.vaddr % header.alignment {
          return Err(DenortBaseImageError::Malformed(
            "ELF PT_LOAD offset and address alignment disagree",
          ));
        }
      }
    }
    headers.push(header);
  }
  if pt_phdr_count > 1 {
    return Err(DenortBaseImageError::Ambiguous(
      "ELF contains multiple PT_PHDR entries",
    ));
  }

  let mut sui_records = Vec::new();
  for header in headers.iter().filter(|header| header.p_type == ELF_PT_NOTE) {
    let range = checked_range(
      header.offset,
      header.filesz,
      bytes.len(),
      "ELF PT_NOTE range",
    )?;
    for payload in parse_elf_sui_records(&bytes[range])? {
      sui_records.push((header.index, payload));
    }
  }

  let retained_count =
    match mode {
      DenortBaseImageMode::Base => {
        if !sui_records.is_empty() {
          return Err(DenortBaseImageError::Ambiguous(
            "base ELF unexpectedly contains an SUI note",
          ));
        }
        entry_count
      }
      DenortBaseImageMode::SuiEmbedded { standalone_data } => {
        let [(sui_header_index, sui_payload)] = sui_records.as_slice() else {
          return Err(DenortBaseImageError::Ambiguous(
            "embedded ELF must contain exactly one SUI note",
          ));
        };
        if *sui_payload != standalone_data {
          return Err(DenortBaseImageError::Malformed(
            "ELF SUI note payload does not equal the expected standalone bytes",
          ));
        }
        if entry_count < 3 {
          return Err(DenortBaseImageError::Malformed(
            "embedded ELF lacks retained program headers",
          ));
        }
        let retained_count = entry_count - 2;
        let appended_load = headers.get(retained_count).ok_or(
          DenortBaseImageError::Malformed("embedded ELF lacks SUI PT_LOAD"),
        )?;
        let appended_note = headers.get(retained_count + 1).ok_or(
          DenortBaseImageError::Malformed("embedded ELF lacks SUI PT_NOTE"),
        )?;
        if *sui_header_index != retained_count + 1
          || appended_load.p_type != ELF_PT_LOAD
          || appended_note.p_type != ELF_PT_NOTE
        {
          return Err(DenortBaseImageError::Malformed(
            "ELF SUI PT_LOAD/PT_NOTE are not the final exact pair",
          ));
        }
        validate_embedded_elf_geometry(
          bytes,
          &headers,
          retained_count,
          program_header_offset,
          entry_size,
          standalone_data,
        )?;
        retained_count
      }
    };

  let first_load = headers[..retained_count]
    .iter()
    .find(|header| header.p_type == ELF_PT_LOAD)
    .ok_or(DenortBaseImageError::Malformed(
      "ELF has no retained PT_LOAD",
    ))?;
  let load_bias = i128::from(first_load.vaddr) - i128::from(first_load.offset);
  validate_elf_program_header_reference(
    &headers,
    program_header_offset,
    entry_size,
    entry_count,
    load_bias,
  )?;

  let mut canonical_header = bytes[..ELF_HEADER_SIZE].to_vec();
  write_zero(&mut canonical_header, 32, 8);
  write_zero(&mut canonical_header, 40, 8);
  write_zero(&mut canonical_header, 56, 2);
  write_zero(&mut canonical_header, 60, 2);

  let mut program_headers = Vec::with_capacity(retained_count);
  for (retained_index, header) in headers[..retained_count].iter().enumerate() {
    let mut canonical = header.raw.to_vec();
    let normalization = if header.p_type == ELF_PT_PHDR {
      write_zero(&mut canonical, 8, 40);
      Some("program-header-table")
    } else {
      None
    };
    let (payload_byte_length, payload_digest) = if header.p_type == ELF_PT_LOAD
    {
      if header.filesz > MAX_IJSON_INTEGER {
        return Err(DenortBaseImageError::Unsupported(
          "ELF PT_LOAD length exceeds the I-JSON safe range",
        ));
      }
      (Some(header.filesz), Some(hash_elf_load(bytes, header)?))
    } else {
      (None, None)
    };
    program_headers.push(ElfProgramHeaderProjection {
      canonical_bytes: URL_SAFE_NO_PAD.encode(canonical),
      index: json_integer(retained_index)?,
      normalization,
      payload_byte_length,
      payload_digest,
    });
  }

  Ok(ElfBaseImageProjection {
    architecture: target.architecture(),
    format: "elf64-little-endian",
    header_bytes: URL_SAFE_NO_PAD.encode(canonical_header),
    program_headers,
    schema: DENORT_BASE_IMAGE_PROJECTION_SCHEMA,
  })
}

fn validate_elf_section_header_table(
  bytes: &[u8],
) -> Result<(), DenortBaseImageError> {
  let table_offset = read_u64(bytes, 40)?;
  let entry_size = read_u16(bytes, 58)? as usize;
  let entry_count = read_u16(bytes, 60)? as usize;
  let string_table_index = read_u16(bytes, 62)? as usize;

  match (table_offset == 0, entry_count == 0) {
    (true, true) => {
      if string_table_index != 0 {
        return Err(DenortBaseImageError::Malformed(
          "ELF without a section-header table has a section-name index",
        ));
      }
      if entry_size != 0 && entry_size < ELF_SECTION_HEADER_MIN_SIZE {
        return Err(DenortBaseImageError::Malformed(
          "ELF section-header entries are shorter than ELF64",
        ));
      }
      return Ok(());
    }
    (true, false) | (false, true) => {
      return Err(DenortBaseImageError::Malformed(
        "ELF section-header offset and count must both be zero or nonzero",
      ));
    }
    (false, false) => {}
  }

  if entry_size < ELF_SECTION_HEADER_MIN_SIZE {
    return Err(DenortBaseImageError::Malformed(
      "ELF section-header entries are shorter than ELF64",
    ));
  }
  if string_table_index == 0xffff {
    return Err(DenortBaseImageError::Unsupported(
      "extended ELF section-name indices are not accepted",
    ));
  }
  if string_table_index != 0 && string_table_index >= entry_count {
    return Err(DenortBaseImageError::Malformed(
      "ELF section-name index is outside the section-header table",
    ));
  }
  let table_length = entry_size.checked_mul(entry_count).ok_or(
    DenortBaseImageError::Overflow("ELF section-header table length"),
  )?;
  checked_range(
    table_offset,
    u64::try_from(table_length).map_err(|_| {
      DenortBaseImageError::Overflow("ELF section-header table length")
    })?,
    bytes.len(),
    "ELF section-header table",
  )?;
  Ok(())
}

fn validate_elf_program_header_reference(
  headers: &[ElfProgramHeader<'_>],
  table_offset: u64,
  entry_size: usize,
  entry_count: usize,
  load_bias: i128,
) -> Result<(), DenortBaseImageError> {
  let table_length = entry_size
    .checked_mul(entry_count)
    .and_then(|length| u64::try_from(length).ok())
    .ok_or(DenortBaseImageError::Overflow(
      "ELF program-header reference length",
    ))?;
  let table_end = table_offset.checked_add(table_length).ok_or(
    DenortBaseImageError::Overflow("ELF program-header reference end"),
  )?;
  if !headers.iter().any(|header| {
    if header.p_type != ELF_PT_LOAD {
      return false;
    }
    header
      .offset
      .checked_add(header.filesz)
      .is_some_and(|end| header.offset <= table_offset && end >= table_end)
  }) {
    return Err(DenortBaseImageError::Malformed(
      "ELF program-header table is not covered by a retained PT_LOAD",
    ));
  }
  if let Some(pt_phdr) =
    headers.iter().find(|header| header.p_type == ELF_PT_PHDR)
  {
    let expected_vaddr = i128::from(table_offset)
      .checked_add(load_bias)
      .ok_or(DenortBaseImageError::Overflow("ELF PT_PHDR address"))?;
    if expected_vaddr < 0 || expected_vaddr > i128::from(u64::MAX) {
      return Err(DenortBaseImageError::Overflow("ELF PT_PHDR address"));
    }
    let expected_vaddr = expected_vaddr as u64;
    if pt_phdr.offset != table_offset
      || pt_phdr.vaddr != expected_vaddr
      || pt_phdr.paddr != expected_vaddr
      || pt_phdr.filesz != table_length
      || pt_phdr.memsz != table_length
    {
      return Err(DenortBaseImageError::Malformed(
        "ELF PT_PHDR does not describe the observed program-header table",
      ));
    }
  }
  Ok(())
}

fn validate_embedded_elf_geometry(
  bytes: &[u8],
  headers: &[ElfProgramHeader<'_>],
  retained_count: usize,
  program_header_offset: u64,
  entry_size: usize,
  standalone_data: &[u8],
) -> Result<(), DenortBaseImageError> {
  let appended_load =
    headers
      .get(retained_count)
      .ok_or(DenortBaseImageError::Malformed(
        "embedded ELF lacks SUI PT_LOAD",
      ))?;
  let appended_note =
    headers
      .get(retained_count + 1)
      .ok_or(DenortBaseImageError::Malformed(
        "embedded ELF lacks SUI PT_NOTE",
      ))?;
  let expected_note = build_elf_sui_note(standalone_data)?;
  let table_length = headers
    .len()
    .checked_mul(entry_size)
    .and_then(|length| u64::try_from(length).ok())
    .ok_or(DenortBaseImageError::Overflow(
      "embedded ELF program-header table",
    ))?;
  let table_end = program_header_offset.checked_add(table_length).ok_or(
    DenortBaseImageError::Overflow("embedded ELF program-header table end"),
  )?;
  let note_offset = align_up(table_end, 4)?;
  let note_length = u64::try_from(expected_note.len())
    .map_err(|_| DenortBaseImageError::Overflow("ELF SUI note length"))?;
  let note_end = note_offset
    .checked_add(note_length)
    .ok_or(DenortBaseImageError::Overflow("ELF SUI note end"))?;

  if program_header_offset % 4096 != 0
    || appended_load.offset != program_header_offset
    || appended_load.flags != ELF_PF_R
    || appended_load.alignment != 4096
    || appended_load.filesz != note_end - program_header_offset
    || appended_load.memsz != appended_load.filesz
  {
    return Err(DenortBaseImageError::Malformed(
      "embedded ELF SUI PT_LOAD geometry is not exact",
    ));
  }
  if appended_note.flags != ELF_PF_R
    || appended_note.offset != note_offset
    || appended_note.filesz != note_length
    || appended_note.memsz != note_length
    || appended_note.alignment != 4
  {
    return Err(DenortBaseImageError::Malformed(
      "embedded ELF SUI PT_NOTE geometry is not exact",
    ));
  }

  let first_load = headers[..retained_count]
    .iter()
    .find(|header| header.p_type == ELF_PT_LOAD)
    .ok_or(DenortBaseImageError::Malformed(
      "embedded ELF has no retained PT_LOAD",
    ))?;
  let bias = i128::from(first_load.vaddr) - i128::from(first_load.offset);
  let expected_load_vaddr =
    i128::from(program_header_offset).checked_add(bias).ok_or(
      DenortBaseImageError::Overflow("embedded ELF SUI PT_LOAD address"),
    )?;
  let expected_note_vaddr = i128::from(note_offset).checked_add(bias).ok_or(
    DenortBaseImageError::Overflow("embedded ELF SUI PT_NOTE address"),
  )?;
  if expected_load_vaddr < 0
    || expected_load_vaddr > i128::from(u64::MAX)
    || expected_note_vaddr < 0
    || expected_note_vaddr > i128::from(u64::MAX)
  {
    return Err(DenortBaseImageError::Overflow(
      "embedded ELF SUI virtual address",
    ));
  }
  let expected_load_vaddr = expected_load_vaddr as u64;
  let expected_note_vaddr = expected_note_vaddr as u64;
  if appended_load.vaddr != expected_load_vaddr
    || appended_load.paddr != expected_load_vaddr
    || appended_note.vaddr != expected_note_vaddr
    || appended_note.paddr != expected_note_vaddr
  {
    return Err(DenortBaseImageError::Malformed(
      "embedded ELF SUI virtual-address bias is not exact",
    ));
  }

  let mut maximum_file_end = 0u64;
  let mut maximum_memory_end = 0u64;
  for header in headers[..retained_count]
    .iter()
    .filter(|header| header.p_type == ELF_PT_LOAD)
  {
    maximum_file_end =
      maximum_file_end.max(header.offset.checked_add(header.filesz).ok_or(
        DenortBaseImageError::Overflow("retained ELF PT_LOAD file end"),
      )?);
    maximum_memory_end =
      maximum_memory_end.max(header.vaddr.checked_add(header.memsz).ok_or(
        DenortBaseImageError::Overflow("retained ELF PT_LOAD memory end"),
      )?);
  }
  let maximum_memory_end = align_up(maximum_memory_end, 4096)?;
  if program_header_offset < maximum_file_end
    || expected_load_vaddr < maximum_memory_end
  {
    return Err(DenortBaseImageError::Malformed(
      "embedded ELF SUI region overlaps a retained PT_LOAD",
    ));
  }

  let gap = checked_range(
    table_end,
    note_offset - table_end,
    bytes.len(),
    "embedded ELF table-to-note gap",
  )?;
  if bytes[gap].iter().any(|byte| *byte != 0) {
    return Err(DenortBaseImageError::Malformed(
      "embedded ELF table-to-note padding is nonzero",
    ));
  }
  let note_range = checked_range(
    note_offset,
    note_length,
    bytes.len(),
    "embedded ELF SUI note",
  )?;
  if bytes[note_range] != expected_note {
    return Err(DenortBaseImageError::Malformed(
      "embedded ELF SUI note bytes are not canonical",
    ));
  }
  Ok(())
}

fn build_elf_sui_note(
  standalone_data: &[u8],
) -> Result<Vec<u8>, DenortBaseImageError> {
  let descriptor_length = 2usize
    .checked_add(ELF_SUI_OWNER.len())
    .and_then(|length| length.checked_add(standalone_data.len()))
    .ok_or(DenortBaseImageError::Overflow("ELF SUI descriptor length"))?;
  let descriptor_length = u32::try_from(descriptor_length).map_err(|_| {
    DenortBaseImageError::Unsupported("ELF SUI descriptor exceeds u32")
  })?;
  let mut note = Vec::new();
  note.extend_from_slice(&4u32.to_le_bytes());
  note.extend_from_slice(&descriptor_length.to_le_bytes());
  note.extend_from_slice(&ELF_SUI_NOTE_TYPE.to_le_bytes());
  note.extend_from_slice(b"SUI\0");
  note.extend_from_slice(&(ELF_SUI_OWNER.len() as u16).to_le_bytes());
  note.extend_from_slice(ELF_SUI_OWNER);
  note.extend_from_slice(standalone_data);
  let padded_length = usize::try_from(align_up(note.len() as u64, 4)?)
    .map_err(|_| DenortBaseImageError::Overflow("ELF SUI note padding"))?;
  note.resize(padded_length, 0);
  Ok(note)
}

fn parse_elf_sui_records(
  note_segment: &[u8],
) -> Result<Vec<&[u8]>, DenortBaseImageError> {
  let mut position = 0usize;
  let mut records = Vec::new();
  while position < note_segment.len() {
    if note_segment.len() - position < 12 {
      if note_segment[position..].iter().all(|byte| *byte == 0) {
        break;
      }
      return Err(DenortBaseImageError::Malformed(
        "ELF PT_NOTE has a truncated record header",
      ));
    }
    let name_length = read_u32(note_segment, position)? as u64;
    let descriptor_length = read_u32(note_segment, position + 4)? as u64;
    let note_type = read_u32(note_segment, position + 8)?;
    position += 12;
    let name_range = checked_range(
      position as u64,
      name_length,
      note_segment.len(),
      "ELF note name",
    )?;
    let name = &note_segment[name_range.clone()];
    position = usize::try_from(align_up(name_range.end as u64, 4)?)
      .map_err(|_| DenortBaseImageError::Overflow("ELF note name padding"))?;
    let descriptor_range = checked_range(
      position as u64,
      descriptor_length,
      note_segment.len(),
      "ELF note descriptor",
    )?;
    let descriptor = &note_segment[descriptor_range.clone()];
    position = usize::try_from(align_up(descriptor_range.end as u64, 4)?)
      .map_err(|_| {
        DenortBaseImageError::Overflow("ELF note descriptor padding")
      })?;
    if position > note_segment.len() {
      return Err(DenortBaseImageError::OutOfFile(
        "ELF note descriptor padding",
      ));
    }

    let looks_like_sui = note_type == ELF_SUI_NOTE_TYPE || name == b"SUI\0";
    if !looks_like_sui {
      continue;
    }
    if note_type != ELF_SUI_NOTE_TYPE || name != b"SUI\0" {
      return Err(DenortBaseImageError::Malformed(
        "ELF SUI note name/type pair is incomplete",
      ));
    }
    if descriptor.len() < 2 {
      return Err(DenortBaseImageError::Malformed(
        "ELF SUI descriptor is truncated",
      ));
    }
    let owner_length = read_u16(descriptor, 0)? as usize;
    let owner_end = 2usize
      .checked_add(owner_length)
      .ok_or(DenortBaseImageError::Overflow("ELF SUI owner length"))?;
    if owner_end > descriptor.len()
      || owner_length != ELF_SUI_OWNER.len()
      || &descriptor[2..owner_end] != ELF_SUI_OWNER
    {
      return Err(DenortBaseImageError::Malformed(
        "ELF SUI descriptor owner is not d3n0l4nd",
      ));
    }
    records.push(&descriptor[owner_end..]);
  }
  Ok(records)
}

fn hash_elf_load(
  bytes: &[u8],
  header: &ElfProgramHeader<'_>,
) -> Result<String, DenortBaseImageError> {
  let range = checked_range(
    header.offset,
    header.filesz,
    bytes.len(),
    "ELF PT_LOAD payload",
  )?;
  let normalized_ranges = [32..40, 40..48, 56..58, 60..62];
  let mut digest = Sha256::new();
  digest.update(ELF_LOAD_BYTES_DOMAIN.as_bytes());
  digest.update([0]);
  let mut cursor = range.start;
  for normalized in normalized_ranges {
    let start = normalized.start.max(range.start);
    let end = normalized.end.min(range.end);
    if start >= end {
      continue;
    }
    digest.update(&bytes[cursor..start]);
    digest.update(vec![0; end - start]);
    cursor = end;
  }
  digest.update(&bytes[cursor..range.end]);
  Ok(format!(
    "sha256-{}",
    URL_SAFE_NO_PAD.encode(digest.finalize())
  ))
}

#[derive(Debug, Clone)]
struct MachOLoadCommand<'a> {
  raw: &'a [u8],
  original_index: usize,
  command: u32,
}

#[derive(Debug, Clone)]
struct MachOSegment {
  command_index: usize,
  segname: [u8; 16],
  vmaddr: u64,
  vmsize: u64,
  fileoff: u64,
  filesize: u64,
  maxprot: u32,
  initprot: u32,
  flags: u32,
  sections: Vec<MachOSection>,
}

#[derive(Debug, Clone)]
struct MachOSection {
  sectname: [u8; 16],
  segname: [u8; 16],
  address: u64,
  size: u64,
  offset: u32,
  alignment: u32,
  relocation_offset: u32,
  relocation_count: u32,
  flags: u32,
  reserved1: u32,
  reserved2: u32,
  reserved3: u32,
}

#[derive(Debug, Clone)]
struct MachOTypedRange {
  start: usize,
  end: usize,
  owner: String,
  ordinal: u64,
  alias_role: MachOTypedAliasRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MachOTypedAliasRole {
  None,
  Export,
  ExportsTrie,
}

#[derive(Debug, Clone, Copy)]
struct MachOX86SuiRange {
  sentinel_start: usize,
  payload_end: usize,
}

fn project_macho(
  bytes: &[u8],
  target: DenortBaseImageTarget,
  mode: DenortBaseImageMode<'_>,
) -> Result<MachOBaseImageProjection, DenortBaseImageError> {
  if bytes.len() < MACHO_HEADER_SIZE {
    return Err(DenortBaseImageError::Malformed(
      "Mach-O header is truncated",
    ));
  }
  let magic = read_u32(bytes, 0)?;
  if magic != MACHO_MAGIC_64_LE {
    if matches!(magic, 0xcafe_babe | 0xbeba_feca | 0xcafe_babf | 0xbfba_feca) {
      return Err(DenortBaseImageError::Unsupported(
        "fat Mach-O images are not accepted",
      ));
    }
    if matches!(magic, 0xcffa_edfe | 0xfeed_face | 0xcefa_edfe) {
      return Err(DenortBaseImageError::Unsupported(
        "only little-endian 64-bit Mach-O is accepted",
      ));
    }
    return Err(DenortBaseImageError::TargetMismatch(
      "Darwin target does not contain a thin little-endian Mach-O image",
    ));
  }
  let expected_cpu =
    target
      .macho_cpu()
      .ok_or(DenortBaseImageError::TargetMismatch(
        "Linux target was routed to Mach-O",
      ))?;
  let cpu = read_u32(bytes, 4)?;
  if cpu != expected_cpu {
    return Err(DenortBaseImageError::TargetMismatch(
      "Mach-O CPU type does not match the selected target",
    ));
  }
  let expected_cpu_subtype = if cpu == MACHO_CPU_X86_64 { 3 } else { 0 };
  if read_u32(bytes, 8)? != expected_cpu_subtype {
    return Err(DenortBaseImageError::TargetMismatch(
      "Mach-O CPU subtype does not match the selected target",
    ));
  }
  if read_u32(bytes, 12)? != MACHO_FILETYPE_EXECUTE {
    return Err(DenortBaseImageError::Unsupported(
      "Darwin denort must be a thin MH_EXECUTE image",
    ));
  }
  let command_count = usize::try_from(read_u32(bytes, 16)?)
    .map_err(|_| DenortBaseImageError::Overflow("Mach-O command count"))?;
  let commands_size = usize::try_from(read_u32(bytes, 20)?)
    .map_err(|_| DenortBaseImageError::Overflow("Mach-O commands size"))?;
  if command_count == 0 || commands_size == 0 {
    return Err(DenortBaseImageError::Malformed(
      "Mach-O has no load commands",
    ));
  }
  if command_count > commands_size / 8 {
    return Err(DenortBaseImageError::Malformed(
      "Mach-O ncmds exceeds the number of command headers in sizeofcmds",
    ));
  }
  if read_u32(bytes, 28)? != 0 {
    return Err(DenortBaseImageError::Malformed(
      "Mach-O 64-bit reserved header field is nonzero",
    ));
  }
  let commands_end = MACHO_HEADER_SIZE.checked_add(commands_size).ok_or(
    DenortBaseImageError::Overflow("Mach-O load-command array end"),
  )?;
  if commands_end > bytes.len() {
    return Err(DenortBaseImageError::OutOfFile("Mach-O load-command array"));
  }

  let mut commands = Vec::with_capacity(command_count);
  let mut position = MACHO_HEADER_SIZE;
  for original_index in 0..command_count {
    if position.checked_add(8).is_none_or(|end| end > commands_end) {
      return Err(DenortBaseImageError::Malformed(
        "Mach-O load-command header is truncated",
      ));
    }
    let command = read_u32(bytes, position)?;
    let command_size = usize::try_from(read_u32(bytes, position + 4)?)
      .map_err(|_| DenortBaseImageError::Overflow("Mach-O command size"))?;
    if command_size < 8 || command_size % 8 != 0 {
      return Err(DenortBaseImageError::Malformed(
        "Mach-O cmdsize is shorter than its header or not 8-byte aligned",
      ));
    }
    let end = position
      .checked_add(command_size)
      .ok_or(DenortBaseImageError::Overflow("Mach-O command end"))?;
    if end > commands_end {
      return Err(DenortBaseImageError::OutOfFile("Mach-O load command"));
    }
    commands.push(MachOLoadCommand {
      raw: &bytes[position..end],
      original_index,
      command,
    });
    position = end;
  }
  if position != commands_end {
    return Err(DenortBaseImageError::Ambiguous(
      "Mach-O ncmds and sizeofcmds do not describe the same command array",
    ));
  }

  let mut segments = Vec::new();
  let mut segment_by_command = vec![None; command_count];
  for command in &commands {
    if command.command == MACHO_LC_SEGMENT_64 {
      let segment = parse_macho_segment(command)?;
      segment_by_command[command.original_index] = Some(segments.len());
      segments.push(segment);
    }
  }
  if segments.is_empty() {
    return Err(DenortBaseImageError::Malformed(
      "Mach-O has no LC_SEGMENT_64 commands",
    ));
  }

  let code_signature_commands = commands
    .iter()
    .filter(|command| command.command == MACHO_LC_CODE_SIGNATURE)
    .collect::<Vec<_>>();
  if code_signature_commands.len() > 1 {
    return Err(DenortBaseImageError::Ambiguous(
      "Mach-O contains multiple LC_CODE_SIGNATURE commands",
    ));
  }
  let sui_segment_commands = segments
    .iter()
    .filter(|segment| segment.segname == MACHO_SEG_SUI)
    .map(|segment| segment.command_index)
    .collect::<Vec<_>>();
  if sui_segment_commands.len() > 1 {
    return Err(DenortBaseImageError::Ambiguous(
      "Mach-O contains multiple __SUI segments",
    ));
  }

  let mut removed_commands = BTreeSet::new();
  if let Some(command) = code_signature_commands.first() {
    removed_commands.insert(command.original_index);
  }

  let mut x86_sui = None;
  match (cpu, mode) {
    (MACHO_CPU_ARM64, DenortBaseImageMode::Base) => {
      if !sui_segment_commands.is_empty() {
        return Err(DenortBaseImageError::Ambiguous(
          "base arm64 Mach-O unexpectedly contains an __SUI segment",
        ));
      }
    }
    (MACHO_CPU_ARM64, DenortBaseImageMode::SuiEmbedded { standalone_data }) => {
      let [command_index] = sui_segment_commands.as_slice() else {
        return Err(DenortBaseImageError::Ambiguous(
          "embedded arm64 Mach-O must contain exactly one __SUI segment",
        ));
      };
      removed_commands.insert(*command_index);
      let segment_index = segment_by_command[*command_index].ok_or(
        DenortBaseImageError::Malformed("__SUI command is not a segment"),
      )?;
      validate_arm64_sui_segment(
        bytes,
        &segments[segment_index],
        standalone_data,
      )?;
    }
    (MACHO_CPU_X86_64, DenortBaseImageMode::Base) => {
      if !sui_segment_commands.is_empty() {
        return Err(DenortBaseImageError::Malformed(
          "x86_64 Mach-O uses no __SUI segment",
        ));
      }
      if find_all(bytes, MACHO_SUI_SENTINEL).next().is_some() {
        return Err(DenortBaseImageError::Ambiguous(
          "base x86_64 Mach-O contains the reserved SUI sentinel",
        ));
      }
    }
    (
      MACHO_CPU_X86_64,
      DenortBaseImageMode::SuiEmbedded { standalone_data },
    ) => {
      if !sui_segment_commands.is_empty() {
        return Err(DenortBaseImageError::Malformed(
          "x86_64 Mach-O uses no __SUI segment",
        ));
      }
      let mut positions = find_all(bytes, MACHO_SUI_SENTINEL);
      let Some(sentinel_start) = positions.next() else {
        return Err(DenortBaseImageError::Ambiguous(
          "embedded x86_64 Mach-O must contain exactly one SUI sentinel",
        ));
      };
      if positions.next().is_some() {
        return Err(DenortBaseImageError::Ambiguous(
          "embedded x86_64 Mach-O must contain exactly one SUI sentinel",
        ));
      }
      x86_sui = Some(validate_x86_sui_payload(
        bytes,
        sentinel_start,
        standalone_data,
      )?);
    }
    _ => {
      return Err(DenortBaseImageError::TargetMismatch(
        "Mach-O CPU is outside the selected release target",
      ));
    }
  }

  let mut retained_commands = Vec::new();
  for command in &commands {
    if removed_commands.contains(&command.original_index) {
      continue;
    }
    retained_commands.push(command);
  }

  let retained_linkedit = segments
    .iter()
    .filter(|segment| {
      segment.segname == MACHO_SEG_LINKEDIT
        && !removed_commands.contains(&segment.command_index)
    })
    .collect::<Vec<_>>();
  let [linkedit] = retained_linkedit.as_slice() else {
    return Err(DenortBaseImageError::Ambiguous(
      "Mach-O must contain exactly one retained __LINKEDIT segment",
    ));
  };
  let linkedit_range = checked_range(
    linkedit.fileoff,
    linkedit.filesize,
    bytes.len(),
    "Mach-O __LINKEDIT range",
  )?;
  if linkedit_range.end != bytes.len() {
    return Err(DenortBaseImageError::Unsupported(
      "this projector requires __LINKEDIT to end at EOF",
    ));
  }

  if cpu == MACHO_CPU_ARM64 {
    if let DenortBaseImageMode::SuiEmbedded { .. } = mode {
      let sui_command = *sui_segment_commands.first().ok_or(
        DenortBaseImageError::Malformed("embedded arm64 Mach-O lacks __SUI"),
      )?;
      let sui_segment_index = segment_by_command
        .get(sui_command)
        .and_then(|index| *index)
        .ok_or(DenortBaseImageError::Malformed(
          "embedded arm64 __SUI command was not parsed as a segment",
        ))?;
      let sui = segments.get(sui_segment_index).ok_or(
        DenortBaseImageError::Malformed(
          "embedded arm64 __SUI segment index is invalid",
        ),
      )?;
      validate_arm64_sui_linkedit_relation(sui, linkedit)?;
    }
  }

  let code_signature_range =
    if let Some(command) = code_signature_commands.first() {
      if command.raw.len() != 16 {
        return Err(DenortBaseImageError::Malformed(
          "LC_CODE_SIGNATURE has an unexpected command size",
        ));
      }
      let range = checked_range(
        read_u32(command.raw, 8)? as u64,
        read_u32(command.raw, 12)? as u64,
        bytes.len(),
        "Mach-O code-signature blob",
      )?;
      if range.is_empty()
        || range.start < linkedit_range.start
        || range.end != linkedit_range.end
      {
        return Err(DenortBaseImageError::Malformed(
          "Mach-O code-signature blob is not the unique __LINKEDIT suffix",
        ));
      }
      Some(range)
    } else {
      None
    };

  let suffix_start = code_signature_range
    .as_ref()
    .map_or(linkedit_range.end, |range| range.start);
  let semantic_linkedit_end = if let Some(x86_sui) = x86_sui {
    if x86_sui.sentinel_start < linkedit_range.start
      || x86_sui.payload_end > suffix_start
    {
      return Err(DenortBaseImageError::Malformed(
        "x86_64 SUI payload is outside the __LINKEDIT suffix",
      ));
    }
    if bytes[x86_sui.payload_end..suffix_start]
      .iter()
      .any(|byte| *byte != 0)
    {
      return Err(DenortBaseImageError::Malformed(
        "x86_64 SUI-to-signature alignment contains nonzero bytes",
      ));
    }
    x86_sui.sentinel_start
  } else {
    suffix_start
  };

  let validated_empty_data_in_code = validate_macho_command_relationships(
    bytes,
    &retained_commands,
    linkedit_range.start,
    semantic_linkedit_end,
    x86_sui,
  )?;

  validate_macho_segment_layout(bytes, &segments, commands_end, cpu)?;

  let earliest_section = earliest_file_backed_section(
    bytes,
    &segments,
    &removed_commands,
    commands_end,
  )?;
  let mut payloads = project_macho_segment_payloads(
    bytes,
    &segments,
    &removed_commands,
    earliest_section,
  )?;

  let mut typed_ranges = Vec::new();
  let mut load_commands = Vec::with_capacity(retained_commands.len());
  let mut segment_ordinal = 0usize;
  for (retained_index, command) in retained_commands.iter().enumerate() {
    let mut canonical = command.raw.to_vec();
    canonicalize_macho_command(
      bytes,
      command,
      retained_index,
      segment_ordinal,
      &segment_by_command,
      &segments,
      linkedit,
      x86_sui,
      validated_empty_data_in_code,
      &mut canonical,
      &mut typed_ranges,
    )?;
    if command.command == MACHO_LC_SEGMENT_64 {
      segment_ordinal += 1;
    }
    load_commands.push(MachOLoadCommandProjection {
      canonical_bytes: URL_SAFE_NO_PAD.encode(canonical),
      index: json_integer(retained_index)?,
    });
  }

  typed_ranges.sort_by(|left, right| {
    left
      .start
      .cmp(&right.start)
      .then_with(|| left.end.cmp(&right.end))
      .then_with(|| left.owner.as_bytes().cmp(right.owner.as_bytes()))
      .then_with(|| left.ordinal.cmp(&right.ordinal))
  });
  append_macho_linkedit_partition(
    bytes,
    linkedit_range.start,
    semantic_linkedit_end,
    &typed_ranges,
    &mut payloads,
  )?;

  let mut payload_identities = BTreeSet::new();
  for payload in &payloads {
    if !payload_identities.insert((
      payload.kind,
      payload.owner.clone(),
      payload.ordinal,
    )) {
      return Err(DenortBaseImageError::Ambiguous(
        "duplicate Mach-O payload kind/owner/ordinal",
      ));
    }
  }

  let mut canonical_header = bytes[..MACHO_HEADER_SIZE].to_vec();
  write_zero(&mut canonical_header, 16, 4);
  write_zero(&mut canonical_header, 20, 4);
  Ok(MachOBaseImageProjection {
    architecture: target.architecture(),
    format: "mach-o-64-little-endian",
    header_bytes: URL_SAFE_NO_PAD.encode(canonical_header),
    load_commands,
    payloads,
    schema: DENORT_BASE_IMAGE_PROJECTION_SCHEMA,
  })
}

fn validate_macho_command_relationships(
  bytes: &[u8],
  commands: &[&MachOLoadCommand<'_>],
  linkedit_start: usize,
  linkedit_end: usize,
  x86_sui: Option<MachOX86SuiRange>,
) -> Result<Option<usize>, DenortBaseImageError> {
  let mut symtabs = commands
    .iter()
    .enumerate()
    .filter(|(_, command)| command.command == MACHO_LC_SYMTAB);
  let Some((_, symtab)) = symtabs.next() else {
    return Err(DenortBaseImageError::Ambiguous(
      "Mach-O must contain exactly one LC_SYMTAB command",
    ));
  };
  if symtabs.next().is_some() {
    return Err(DenortBaseImageError::Ambiguous(
      "Mach-O must contain exactly one LC_SYMTAB command",
    ));
  }
  require_command_size(symtab, 24, "LC_SYMTAB")?;

  let symbol_offset = read_u32(symtab.raw, 8)? as u64;
  let symbol_count = read_u32(symtab.raw, 12)? as u64;
  let string_offset = read_u32(symtab.raw, 16)? as u64;
  let raw_string_size = read_u32(symtab.raw, 20)? as u64;
  if let Some(x86_sui) = x86_sui {
    let string_offset_usize = usize::try_from(string_offset).map_err(|_| {
      DenortBaseImageError::OutOfFile("Mach-O string table offset")
    })?;
    if string_offset_usize >= x86_sui.sentinel_start {
      return Err(DenortBaseImageError::Malformed(
        "x86_64 SUI sentinel does not follow the semantic string table",
      ));
    }
    let patched_end = string_offset.checked_add(raw_string_size).ok_or(
      DenortBaseImageError::Overflow("x86_64 patched string table end"),
    )?;
    if patched_end
      != u64::try_from(x86_sui.payload_end)
        .map_err(|_| DenortBaseImageError::Overflow("x86_64 SUI payload end"))?
    {
      return Err(DenortBaseImageError::Malformed(
        "x86_64 LC_SYMTAB.strsize does not end at the SUI payload end",
      ));
    }
  }

  let mut data_in_code_commands = Vec::new();
  let mut anchored_empty = Vec::new();
  for (index, command) in commands
    .iter()
    .enumerate()
    .filter(|(_, command)| command.command == MACHO_LC_DATA_IN_CODE)
  {
    require_command_size(command, 16, "LC_DATA_IN_CODE")?;
    let offset = read_u32(command.raw, 8)? as u64;
    let size = read_u32(command.raw, 12)? as u64;
    data_in_code_commands.push(index);
    if size == 0 && offset != 0 {
      anchored_empty.push((index, offset));
    }
  }
  let Some(&(data_index, data_offset)) = anchored_empty.first() else {
    return Ok(None);
  };
  if anchored_empty.len() != 1 || data_in_code_commands.len() != 1 {
    return Err(DenortBaseImageError::Ambiguous(
      "anchored empty LC_DATA_IN_CODE must be the unique command of its type",
    ));
  }

  let mut function_starts = commands
    .iter()
    .enumerate()
    .filter(|(_, command)| command.command == MACHO_LC_FUNCTION_STARTS);
  let Some((function_index, function_command)) = function_starts.next() else {
    return Err(DenortBaseImageError::Malformed(
      "anchored empty LC_DATA_IN_CODE lacks unique preceding function starts",
    ));
  };
  if function_starts.next().is_some() || function_index + 1 != data_index {
    return Err(DenortBaseImageError::Malformed(
      "anchored empty LC_DATA_IN_CODE lacks unique preceding function starts",
    ));
  }
  require_command_size(function_command, 16, "LC_FUNCTION_STARTS")?;
  let function_offset = read_u32(function_command.raw, 8)? as u64;
  let function_size = read_u32(function_command.raw, 12)? as u64;
  if function_offset == 0 || function_size == 0 {
    return Err(DenortBaseImageError::Malformed(
      "anchored empty LC_DATA_IN_CODE follows empty function starts",
    ));
  }
  let function_range = checked_range(
    function_offset,
    function_size,
    bytes.len(),
    "Mach-O function-starts payload",
  )?;

  let symbol_length =
    symbol_count
      .checked_mul(16)
      .ok_or(DenortBaseImageError::Overflow(
        "Mach-O symbol-table payload length",
      ))?;
  if symbol_offset == 0 || symbol_length == 0 {
    return Err(DenortBaseImageError::Malformed(
      "anchored empty LC_DATA_IN_CODE lacks a positive symbol table",
    ));
  }
  let symbol_range = checked_range(
    symbol_offset,
    symbol_length,
    bytes.len(),
    "Mach-O symbol-table payload",
  )?;
  let data_offset = usize::try_from(data_offset).map_err(|_| {
    DenortBaseImageError::OutOfFile("empty Mach-O data-in-code anchor")
  })?;
  if function_range.start < linkedit_start
    || function_range.end > linkedit_end
    || symbol_range.start < linkedit_start
    || symbol_range.end > linkedit_end
  {
    return Err(DenortBaseImageError::Malformed(
      "anchored empty LC_DATA_IN_CODE relation is outside retained __LINKEDIT",
    ));
  }
  if function_range.end != data_offset || symbol_range.start != data_offset {
    return Err(DenortBaseImageError::Malformed(
      "anchored empty LC_DATA_IN_CODE is not the function/symbol boundary",
    ));
  }
  Ok(Some(data_index))
}

fn append_macho_linkedit_partition(
  bytes: &[u8],
  linkedit_start: usize,
  linkedit_end: usize,
  typed_ranges: &[MachOTypedRange],
  payloads: &mut Vec<MachOPayloadProjection>,
) -> Result<(), DenortBaseImageError> {
  if linkedit_end < linkedit_start || linkedit_end > bytes.len() {
    return Err(DenortBaseImageError::OutOfFile(
      "semantic Mach-O __LINKEDIT range",
    ));
  }

  let mut typed_identities = BTreeSet::new();
  for range in typed_ranges {
    if !typed_identities.insert((range.owner.clone(), range.ordinal)) {
      return Err(DenortBaseImageError::Ambiguous(
        "duplicate Mach-O typed payload owner/ordinal",
      ));
    }
  }

  let mut cursor = linkedit_start;
  let mut padding_index = 0u64;
  let mut range_index = 0usize;
  while range_index < typed_ranges.len() {
    let range = &typed_ranges[range_index];
    if range.start < linkedit_start || range.end > linkedit_end {
      return Err(DenortBaseImageError::OutOfFile(
        "typed Mach-O payload is outside semantic __LINKEDIT",
      ));
    }
    if range.start < cursor {
      return Err(DenortBaseImageError::Unsupported(
        "partial overlap between Mach-O typed payload ranges",
      ));
    }
    if range.start > cursor {
      append_macho_linkedit_padding(
        bytes,
        cursor,
        range.start,
        padding_index,
        payloads,
      )?;
      padding_index = padding_index
        .checked_add(1)
        .ok_or(DenortBaseImageError::Overflow("Mach-O padding ordinal"))?;
    }

    let mut group_end = range_index + 1;
    while group_end < typed_ranges.len()
      && typed_ranges[group_end].start == range.start
      && typed_ranges[group_end].end == range.end
    {
      group_end += 1;
    }
    let group = &typed_ranges[range_index..group_end];
    if group.len() > 1 {
      let valid_alias = group.len() == 2
        && matches!(
          (group[0].alias_role, group[1].alias_role),
          (
            MachOTypedAliasRole::Export,
            MachOTypedAliasRole::ExportsTrie
          ) | (
            MachOTypedAliasRole::ExportsTrie,
            MachOTypedAliasRole::Export
          )
        );
      if !valid_alias {
        return Err(DenortBaseImageError::Unsupported(
          "only an exact export/exports-trie Mach-O alias is accepted",
        ));
      }
    }

    for typed in group {
      let payload = &bytes[typed.start..typed.end];
      payloads.push(MachOPayloadProjection {
        byte_length: json_integer(payload.len())?,
        digest: hbytes(MACHO_LINKEDIT_BYTES_DOMAIN, payload)?,
        kind: MachOPayloadKind::Linkedit,
        owner: typed.owner.clone(),
        ordinal: typed.ordinal,
      });
    }
    cursor = range.end;
    range_index = group_end;
  }

  if cursor < linkedit_end {
    append_macho_linkedit_padding(
      bytes,
      cursor,
      linkedit_end,
      padding_index,
      payloads,
    )?;
  }
  Ok(())
}

fn append_macho_linkedit_padding(
  bytes: &[u8],
  start: usize,
  end: usize,
  padding_index: u64,
  payloads: &mut Vec<MachOPayloadProjection>,
) -> Result<(), DenortBaseImageError> {
  if start >= end {
    return Err(DenortBaseImageError::Malformed(
      "Mach-O padding helper received an empty or reversed range",
    ));
  }
  let padding = bytes
    .get(start..end)
    .ok_or(DenortBaseImageError::OutOfFile("Mach-O __LINKEDIT padding"))?;
  if padding.iter().any(|byte| *byte != 0) {
    return Err(DenortBaseImageError::Malformed(
      "uncovered Mach-O __LINKEDIT bytes are nonzero",
    ));
  }
  payloads.push(MachOPayloadProjection {
    byte_length: json_integer(padding.len())?,
    digest: hbytes(MACHO_LINKEDIT_BYTES_DOMAIN, padding)?,
    kind: MachOPayloadKind::LinkeditPadding,
    owner: format!("padding/{padding_index}"),
    ordinal: 0,
  });
  Ok(())
}

fn parse_macho_segment(
  command: &MachOLoadCommand<'_>,
) -> Result<MachOSegment, DenortBaseImageError> {
  if command.raw.len() < MACHO_SEGMENT_COMMAND_SIZE {
    return Err(DenortBaseImageError::Malformed(
      "LC_SEGMENT_64 is truncated",
    ));
  }
  let section_count = usize::try_from(read_u32(command.raw, 64)?)
    .map_err(|_| DenortBaseImageError::Overflow("Mach-O section count"))?;
  let expected_size = MACHO_SEGMENT_COMMAND_SIZE
    .checked_add(
      section_count
        .checked_mul(MACHO_SECTION_SIZE)
        .ok_or(DenortBaseImageError::Overflow("Mach-O section table size"))?,
    )
    .ok_or(DenortBaseImageError::Overflow(
      "Mach-O segment command size",
    ))?;
  if command.raw.len() != expected_size {
    return Err(DenortBaseImageError::Malformed(
      "LC_SEGMENT_64 cmdsize does not exactly match nsects",
    ));
  }
  let mut segname = [0; 16];
  segname.copy_from_slice(&command.raw[8..24]);
  let mut sections = Vec::with_capacity(section_count);
  for index in 0..section_count {
    let offset = MACHO_SEGMENT_COMMAND_SIZE + index * MACHO_SECTION_SIZE;
    let raw = &command.raw[offset..offset + MACHO_SECTION_SIZE];
    let mut sectname = [0; 16];
    sectname.copy_from_slice(&raw[..16]);
    let mut section_segname = [0; 16];
    section_segname.copy_from_slice(&raw[16..32]);
    sections.push(MachOSection {
      sectname,
      segname: section_segname,
      address: read_u64(raw, 32)?,
      size: read_u64(raw, 40)?,
      offset: read_u32(raw, 48)?,
      alignment: read_u32(raw, 52)?,
      relocation_offset: read_u32(raw, 56)?,
      relocation_count: read_u32(raw, 60)?,
      flags: read_u32(raw, 64)?,
      reserved1: read_u32(raw, 68)?,
      reserved2: read_u32(raw, 72)?,
      reserved3: read_u32(raw, 76)?,
    });
  }
  Ok(MachOSegment {
    command_index: command.original_index,
    segname,
    vmaddr: read_u64(command.raw, 24)?,
    vmsize: read_u64(command.raw, 32)?,
    fileoff: read_u64(command.raw, 40)?,
    filesize: read_u64(command.raw, 48)?,
    maxprot: read_u32(command.raw, 56)?,
    initprot: read_u32(command.raw, 60)?,
    flags: read_u32(command.raw, 68)?,
    sections,
  })
}

fn find_all<'a>(
  haystack: &'a [u8],
  needle: &'a [u8],
) -> impl Iterator<Item = usize> + 'a {
  haystack
    .windows(needle.len())
    .enumerate()
    .filter_map(move |(index, value)| (value == needle).then_some(index))
}

fn validate_x86_sui_payload(
  bytes: &[u8],
  sentinel_start: usize,
  standalone_data: &[u8],
) -> Result<MachOX86SuiRange, DenortBaseImageError> {
  let length_offset = sentinel_start
    .checked_add(MACHO_SUI_SENTINEL.len())
    .ok_or(DenortBaseImageError::Overflow("x86_64 SUI length offset"))?;
  let declared_length = read_u64(bytes, length_offset)?;
  let expected_length = u64::try_from(standalone_data.len())
    .map_err(|_| DenortBaseImageError::Overflow("x86_64 SUI payload"))?;
  if declared_length != expected_length {
    return Err(DenortBaseImageError::Malformed(
      "x86_64 SUI length does not equal expected standalone length",
    ));
  }
  let payload_start = length_offset
    .checked_add(8)
    .ok_or(DenortBaseImageError::Overflow("x86_64 SUI payload start"))?;
  let payload_end = payload_start
    .checked_add(standalone_data.len())
    .ok_or(DenortBaseImageError::Overflow("x86_64 SUI payload end"))?;
  if bytes.get(payload_start..payload_end) != Some(standalone_data) {
    return Err(DenortBaseImageError::Malformed(
      "x86_64 SUI payload differs from expected standalone bytes",
    ));
  }
  Ok(MachOX86SuiRange {
    sentinel_start,
    payload_end,
  })
}

fn validate_arm64_sui_segment(
  bytes: &[u8],
  segment: &MachOSegment,
  standalone_data: &[u8],
) -> Result<(), DenortBaseImageError> {
  if segment.sections.len() != 1
    || segment.maxprot != 1
    || segment.initprot != 1
    || segment.flags != 0
  {
    return Err(DenortBaseImageError::Malformed(
      "arm64 __SUI segment command shape is not exact",
    ));
  }
  let standalone_length = u64::try_from(standalone_data.len())
    .map_err(|_| DenortBaseImageError::Overflow("arm64 SUI payload"))?;
  let expected_extent = align_up(standalone_length.max(0x4000), 0x10000)?;
  if segment.filesize != expected_extent || segment.vmsize != expected_extent {
    return Err(DenortBaseImageError::Malformed(
      "arm64 __SUI extent is not the canonical libsui extent",
    ));
  }
  let section = &segment.sections[0];
  if section.sectname != MACHO_SEC_SUI
    || section.segname != MACHO_SEG_SUI
    || section.address != segment.vmaddr
    || u64::from(section.offset) != segment.fileoff
    || section.size != standalone_length
    || section.alignment != if standalone_data.len() < 16 { 0 } else { 4 }
    || section.relocation_offset != 0
    || section.relocation_count != 0
    || section.flags != 0
    || section.reserved1 != 0
    || section.reserved2 != 0
    || section.reserved3 != 0
  {
    return Err(DenortBaseImageError::Malformed(
      "arm64 __SUI section shape is not exact",
    ));
  }
  let range = checked_range(
    segment.fileoff,
    segment.filesize,
    bytes.len(),
    "arm64 __SUI segment payload",
  )?;
  let payload_end = range
    .start
    .checked_add(standalone_data.len())
    .ok_or(DenortBaseImageError::Overflow("arm64 SUI payload end"))?;
  if bytes.get(range.start..payload_end) != Some(standalone_data)
    || bytes[payload_end..range.end].iter().any(|byte| *byte != 0)
  {
    return Err(DenortBaseImageError::Malformed(
      "arm64 __SUI payload or zero padding is not exact",
    ));
  }
  Ok(())
}

fn validate_arm64_sui_linkedit_relation(
  sui: &MachOSegment,
  linkedit: &MachOSegment,
) -> Result<(), DenortBaseImageError> {
  let expected_fileoff = sui
    .fileoff
    .checked_add(sui.filesize)
    .ok_or(DenortBaseImageError::Overflow("arm64 __SUI file extent"))?;
  let expected_vmaddr = sui
    .vmaddr
    .checked_add(sui.vmsize)
    .ok_or(DenortBaseImageError::Overflow("arm64 __SUI VM extent"))?;
  if linkedit.fileoff != expected_fileoff || linkedit.vmaddr != expected_vmaddr
  {
    return Err(DenortBaseImageError::Malformed(
      "arm64 __SUI does not immediately precede shifted __LINKEDIT",
    ));
  }
  Ok(())
}

fn validate_macho_segment_layout(
  bytes: &[u8],
  segments: &[MachOSegment],
  commands_end: usize,
  cpu: u32,
) -> Result<(), DenortBaseImageError> {
  let page_size = if cpu == MACHO_CPU_ARM64 {
    MACHO_ARM64_PAGE_SIZE
  } else {
    MACHO_X86_64_PAGE_SIZE
  };
  let mut file_backed_segments = Vec::new();
  let mut ordinary_bias = None;
  for segment in segments {
    if segment.filesize > segment.vmsize {
      return Err(DenortBaseImageError::Malformed(
        "Mach-O segment filesize exceeds vmsize",
      ));
    }
    let range = checked_range(
      segment.fileoff,
      segment.filesize,
      bytes.len(),
      "Mach-O segment file range",
    )?;
    if !range.is_empty() {
      if segment.fileoff % page_size != 0 || segment.vmaddr % page_size != 0 {
        return Err(DenortBaseImageError::Malformed(
          "Mach-O file-backed segment start is not target-page aligned",
        ));
      }
      file_backed_segments.push((segment, range.clone()));
    }
    let vm_end = segment
      .vmaddr
      .checked_add(segment.vmsize)
      .ok_or(DenortBaseImageError::Overflow("Mach-O segment VM end"))?;
    let mut maximum_file_extent = None::<u64>;
    let mut maximum_vm_extent = segment.filesize;
    for section in &segment.sections {
      if section.segname != segment.segname {
        return Err(DenortBaseImageError::Malformed(
          "Mach-O section segname differs from its segment",
        ));
      }
      let section_vm_end = section
        .address
        .checked_add(section.size)
        .ok_or(DenortBaseImageError::Overflow("Mach-O section VM end"))?;
      if section.address < segment.vmaddr || section_vm_end > vm_end {
        return Err(DenortBaseImageError::Malformed(
          "Mach-O section VM range is outside its segment",
        ));
      }
      maximum_vm_extent = maximum_vm_extent.max(
        section_vm_end
          .checked_sub(segment.vmaddr)
          .ok_or(DenortBaseImageError::Overflow("Mach-O section VM extent"))?,
      );
      if section.alignment >= 64 {
        return Err(DenortBaseImageError::Unsupported(
          "Mach-O section alignment exponent is too large",
        ));
      }
      if is_file_backed_section(section) {
        let section_range = checked_range(
          u64::from(section.offset),
          section.size,
          bytes.len(),
          "Mach-O section file range",
        )?;
        if section_range.start < range.start || section_range.end > range.end {
          return Err(DenortBaseImageError::Malformed(
            "Mach-O section file range is outside its segment",
          ));
        }
        let section_file_delta = u64::from(section.offset)
          .checked_sub(segment.fileoff)
          .ok_or(DenortBaseImageError::Malformed(
            "Mach-O section file offset precedes its segment",
          ))?;
        let section_vm_delta = section
          .address
          .checked_sub(segment.vmaddr)
          .ok_or(DenortBaseImageError::Malformed(
            "Mach-O section address precedes its segment",
          ))?;
        if section_file_delta != section_vm_delta {
          return Err(DenortBaseImageError::Malformed(
            "Mach-O section file and VM offsets have different segment bias",
          ));
        }
        maximum_file_extent = Some(maximum_file_extent.unwrap_or(0).max(
          section_file_delta.checked_add(section.size).ok_or(
            DenortBaseImageError::Overflow("Mach-O section file extent"),
          )?,
        ));
        let alignment = 1u64 << section.alignment;
        if u64::from(section.offset) % alignment != 0 {
          return Err(DenortBaseImageError::Malformed(
            "Mach-O section offset violates its alignment",
          ));
        }
      }
    }

    if !range.is_empty()
      && segment.segname != MACHO_SEG_LINKEDIT
      && segment.segname != MACHO_SEG_SUI
    {
      let maximum_file_extent =
        maximum_file_extent.ok_or(DenortBaseImageError::Unsupported(
          "Mach-O ordinary file-backed segment has no file-backed section",
        ))?;
      let expected_filesize = align_up(maximum_file_extent, page_size)?;
      let expected_vmsize = align_up(maximum_vm_extent, page_size)?;
      if segment.filesize != expected_filesize
        || segment.vmsize != expected_vmsize
      {
        return Err(DenortBaseImageError::Malformed(
          "Mach-O ordinary segment extents are not exact page-rounded section extents",
        ));
      }
      let bias = segment.vmaddr.checked_sub(segment.fileoff).ok_or(
        DenortBaseImageError::Malformed(
          "Mach-O ordinary segment VM address precedes its file offset",
        ),
      )?;
      if ordinary_bias
        .replace(bias)
        .is_some_and(|value| value != bias)
      {
        return Err(DenortBaseImageError::Malformed(
          "Mach-O ordinary file-backed segments do not share one VM/file bias",
        ));
      }
    }

    if segment.segname == MACHO_SEG_LINKEDIT
      && (segment.vmsize != segment.filesize || !segment.sections.is_empty())
    {
      return Err(DenortBaseImageError::Malformed(
        "Mach-O __LINKEDIT VM extent or section shape is not exact",
      ));
    }
  }
  let Some((last_segment, _)) = file_backed_segments.last() else {
    return Err(DenortBaseImageError::Malformed(
      "Mach-O has no file-backed segment",
    ));
  };
  if last_segment.segname != MACHO_SEG_LINKEDIT {
    return Err(DenortBaseImageError::Malformed(
      "Mach-O __LINKEDIT is not the final file-backed segment command",
    ));
  }

  let mut file_cursor = 0usize;
  let mut vm_cursor = None;
  for (segment, range) in file_backed_segments {
    if range.start != file_cursor {
      return Err(DenortBaseImageError::Malformed(
        "Mach-O file-backed segments are not contiguous in command order",
      ));
    }
    if vm_cursor.is_some_and(|expected| segment.vmaddr != expected) {
      return Err(DenortBaseImageError::Malformed(
        "Mach-O file-backed segments are not contiguous in VM command order",
      ));
    }
    file_cursor = range.end;
    vm_cursor = Some(
      segment
        .vmaddr
        .checked_add(segment.vmsize)
        .ok_or(DenortBaseImageError::Overflow("Mach-O segment VM end"))?,
    );
  }
  if file_cursor != bytes.len() {
    return Err(DenortBaseImageError::Unsupported(
      "Mach-O contains bytes outside file-backed segments",
    ));
  }
  if commands_end > file_cursor {
    return Err(DenortBaseImageError::OutOfFile(
      "Mach-O load-command prefix",
    ));
  }
  Ok(())
}

fn is_file_backed_section(section: &MachOSection) -> bool {
  let section_type = section.flags & 0xff;
  section.size != 0
    && section.offset != 0
    && !matches!(section_type, 0x1 | 0xc | 0x12)
}

fn earliest_file_backed_section(
  bytes: &[u8],
  segments: &[MachOSegment],
  removed_commands: &BTreeSet<usize>,
  commands_end: usize,
) -> Result<usize, DenortBaseImageError> {
  let earliest = segments
    .iter()
    .filter(|segment| !removed_commands.contains(&segment.command_index))
    .flat_map(|segment| &segment.sections)
    .filter(|section| is_file_backed_section(section))
    .map(|section| section.offset as usize)
    .min()
    .ok_or(DenortBaseImageError::Unsupported(
      "Mach-O has no retained file-backed section boundary",
    ))?;
  if earliest < commands_end {
    return Err(DenortBaseImageError::Malformed(
      "Mach-O load commands overlap the earliest file-backed section",
    ));
  }
  if bytes[commands_end..earliest].iter().any(|byte| *byte != 0) {
    return Err(DenortBaseImageError::Malformed(
      "Mach-O command-capacity gap is nonzero",
    ));
  }
  Ok(earliest)
}

fn project_macho_segment_payloads(
  bytes: &[u8],
  segments: &[MachOSegment],
  removed_commands: &BTreeSet<usize>,
  earliest_section: usize,
) -> Result<Vec<MachOPayloadProjection>, DenortBaseImageError> {
  let mut payloads = Vec::new();
  let mut owner_occurrences = BTreeMap::<String, u64>::new();
  for segment in segments {
    if removed_commands.contains(&segment.command_index)
      || segment.segname == MACHO_SEG_LINKEDIT
    {
      continue;
    }
    let range = checked_range(
      segment.fileoff,
      segment.filesize,
      bytes.len(),
      "Mach-O retained segment payload",
    )?;
    let payload_start = range.start.max(earliest_section.min(range.end));
    let payload = &bytes[payload_start..range.end];
    let owner = format!("segment/{}", URL_SAFE_NO_PAD.encode(segment.segname));
    let ordinal = *owner_occurrences.entry(owner.clone()).or_default();
    let next_ordinal =
      ordinal
        .checked_add(1)
        .ok_or(DenortBaseImageError::Overflow(
          "Mach-O segment-owner ordinal",
        ))?;
    owner_occurrences.insert(owner.clone(), next_ordinal);
    payloads.push(MachOPayloadProjection {
      byte_length: json_integer(payload.len())?,
      digest: hbytes(MACHO_SEGMENT_BYTES_DOMAIN, payload)?,
      kind: MachOPayloadKind::Segment,
      owner,
      ordinal,
    });
  }
  Ok(payloads)
}

#[allow(clippy::too_many_arguments)]
fn canonicalize_macho_command(
  bytes: &[u8],
  command: &MachOLoadCommand<'_>,
  retained_index: usize,
  segment_ordinal: usize,
  segment_by_command: &[Option<usize>],
  segments: &[MachOSegment],
  linkedit: &MachOSegment,
  x86_sui: Option<MachOX86SuiRange>,
  validated_empty_data_in_code: Option<usize>,
  canonical: &mut [u8],
  typed_ranges: &mut Vec<MachOTypedRange>,
) -> Result<(), DenortBaseImageError> {
  let owner = |field: &str| format!("load-command/{retained_index}/{field}");
  match command.command {
    MACHO_LC_SEGMENT_64 => {
      let segment = &segments[segment_by_command[command.original_index]
        .ok_or(DenortBaseImageError::Malformed(
          "retained LC_SEGMENT_64 was not parsed",
        ))?];
      if std::ptr::eq(segment, linkedit) {
        write_zero(canonical, 24, 32);
      }
      for (section_index, section) in segment.sections.iter().enumerate() {
        let relocation_field_offset =
          MACHO_SEGMENT_COMMAND_SIZE + section_index * MACHO_SECTION_SIZE + 56;
        if section.relocation_count == 0 {
          if section.relocation_offset != 0 {
            return Err(DenortBaseImageError::Malformed(
              "Mach-O section has reloff without relocations",
            ));
          }
          continue;
        }
        let byte_length = u64::from(section.relocation_count)
          .checked_mul(8)
          .ok_or(DenortBaseImageError::Overflow(
            "Mach-O section relocation byte length",
          ))?;
        add_macho_typed_range(
          bytes,
          u64::from(section.relocation_offset),
          byte_length,
          owner(&format!(
            "section-relocations/{segment_ordinal}/{section_index}"
          )),
          typed_ranges,
        )?;
        write_zero(canonical, relocation_field_offset, 4);
      }
    }
    MACHO_LC_SYMTAB => {
      require_command_size(command, 24, "LC_SYMTAB")?;
      let symbol_offset = read_u32(command.raw, 8)? as u64;
      let symbol_count = read_u32(command.raw, 12)? as u64;
      let string_offset = read_u32(command.raw, 16)? as u64;
      let raw_string_size = read_u32(command.raw, 20)? as u64;
      add_macho_counted_range(
        bytes,
        symbol_offset,
        symbol_count,
        16,
        owner("symbols"),
        typed_ranges,
      )?;
      let semantic_string_size = if let Some(x86_sui) = x86_sui {
        let string_offset_usize =
          usize::try_from(string_offset).map_err(|_| {
            DenortBaseImageError::OutOfFile("Mach-O string table offset")
          })?;
        if string_offset_usize > x86_sui.sentinel_start {
          return Err(DenortBaseImageError::Malformed(
            "x86_64 SUI sentinel precedes the string table",
          ));
        }
        let patched_end = string_offset.checked_add(raw_string_size).ok_or(
          DenortBaseImageError::Overflow("x86_64 patched string table end"),
        )?;
        if patched_end
          != u64::try_from(x86_sui.payload_end).map_err(|_| {
            DenortBaseImageError::Overflow("x86_64 SUI payload end")
          })?
        {
          return Err(DenortBaseImageError::Malformed(
            "x86_64 LC_SYMTAB.strsize does not end at the SUI payload end",
          ));
        }
        u64::try_from(x86_sui.sentinel_start - string_offset_usize).map_err(
          |_| DenortBaseImageError::Overflow("Mach-O semantic string size"),
        )?
      } else {
        raw_string_size
      };
      add_macho_typed_range(
        bytes,
        string_offset,
        semantic_string_size,
        owner("strings"),
        typed_ranges,
      )?;
      write_zero(canonical, 8, 4);
      write_zero(canonical, 16, 4);
      write_u32_field(
        canonical,
        20,
        u32::try_from(semantic_string_size).map_err(|_| {
          DenortBaseImageError::Overflow("Mach-O semantic string size")
        })?,
      )?;
    }
    MACHO_LC_DYSYMTAB => {
      require_command_size(command, 80, "LC_DYSYMTAB")?;
      for (offset_field, count_field, element_size, field) in [
        (32, 36, 8, "toc"),
        (40, 44, 56, "module-table"),
        (48, 52, 4, "extrefs"),
        (56, 60, 4, "indirect-symbols"),
        (64, 68, 8, "external-relocations"),
        (72, 76, 8, "local-relocations"),
      ] {
        add_macho_counted_range(
          bytes,
          read_u32(command.raw, offset_field)? as u64,
          read_u32(command.raw, count_field)? as u64,
          element_size,
          owner(field),
          typed_ranges,
        )?;
        write_zero(canonical, offset_field, 4);
      }
    }
    MACHO_LC_DYLD_INFO | MACHO_LC_DYLD_INFO_ONLY => {
      require_command_size(command, 48, "LC_DYLD_INFO")?;
      for (offset_field, field) in [
        (8, "rebase"),
        (16, "bind"),
        (24, "weak-bind"),
        (32, "lazy-bind"),
        (40, "export"),
      ] {
        add_macho_typed_range_with_alias(
          bytes,
          read_u32(command.raw, offset_field)? as u64,
          read_u32(command.raw, offset_field + 4)? as u64,
          owner(field),
          if field == "export" {
            MachOTypedAliasRole::Export
          } else {
            MachOTypedAliasRole::None
          },
          false,
          typed_ranges,
        )?;
        write_zero(canonical, offset_field, 4);
      }
    }
    MACHO_LC_TWOLEVEL_HINTS => {
      require_command_size(command, 16, "LC_TWOLEVEL_HINTS")?;
      add_macho_counted_range(
        bytes,
        read_u32(command.raw, 8)? as u64,
        read_u32(command.raw, 12)? as u64,
        4,
        owner("two-level-hints"),
        typed_ranges,
      )?;
      write_zero(canonical, 8, 4);
    }
    command_type if macho_linkedit_data_owner(command_type).is_some() => {
      require_command_size(command, 16, "linkedit_data_command")?;
      let field = macho_linkedit_data_owner(command_type).ok_or(
        DenortBaseImageError::Malformed(
          "recognized linkedit command lacks a frozen owner",
        ),
      )?;
      add_macho_typed_range_with_alias(
        bytes,
        read_u32(command.raw, 8)? as u64,
        read_u32(command.raw, 12)? as u64,
        owner(field),
        if field == "exports-trie" {
          MachOTypedAliasRole::ExportsTrie
        } else {
          MachOTypedAliasRole::None
        },
        command_type == MACHO_LC_DATA_IN_CODE
          && validated_empty_data_in_code == Some(retained_index),
        typed_ranges,
      )?;
      write_zero(canonical, 8, 4);
    }
    command_type if is_safe_macho_command(command_type) => {}
    _ => {
      return Err(DenortBaseImageError::Unsupported(
        "Mach-O load command is outside the closed recognized table",
      ));
    }
  }
  Ok(())
}

fn require_command_size(
  command: &MachOLoadCommand<'_>,
  expected: usize,
  _name: &'static str,
) -> Result<(), DenortBaseImageError> {
  if command.raw.len() != expected {
    return Err(DenortBaseImageError::Malformed(
      "recognized Mach-O load command has an unexpected cmdsize",
    ));
  }
  Ok(())
}

fn add_macho_counted_range(
  bytes: &[u8],
  offset: u64,
  count: u64,
  element_size: u64,
  owner: String,
  ranges: &mut Vec<MachOTypedRange>,
) -> Result<(), DenortBaseImageError> {
  let length =
    count
      .checked_mul(element_size)
      .ok_or(DenortBaseImageError::Overflow(
        "Mach-O counted payload length",
      ))?;
  add_macho_typed_range(bytes, offset, length, owner, ranges)
}

fn add_macho_typed_range(
  bytes: &[u8],
  offset: u64,
  length: u64,
  owner: String,
  ranges: &mut Vec<MachOTypedRange>,
) -> Result<(), DenortBaseImageError> {
  add_macho_typed_range_with_alias(
    bytes,
    offset,
    length,
    owner,
    MachOTypedAliasRole::None,
    false,
    ranges,
  )
}

fn add_macho_typed_range_with_alias(
  bytes: &[u8],
  offset: u64,
  length: u64,
  owner: String,
  alias_role: MachOTypedAliasRole,
  allow_nonzero_empty: bool,
  ranges: &mut Vec<MachOTypedRange>,
) -> Result<(), DenortBaseImageError> {
  if length == 0 {
    // ld64 anchors an empty LC_DATA_IN_CODE at the following table even
    // though the command names no bytes. The one accepted anchor has already
    // been tied to the exact function-starts/symbol-table boundary above.
    if offset != 0 && !allow_nonzero_empty {
      return Err(DenortBaseImageError::Unsupported(
        "zero-length Mach-O typed payload has a nonzero offset",
      ));
    }
    checked_range(offset, 0, bytes.len(), "empty Mach-O typed payload")?;
    return Ok(());
  }
  if offset == 0 {
    return Err(DenortBaseImageError::Malformed(
      "nonempty Mach-O typed payload has zero offset",
    ));
  }
  let range =
    checked_range(offset, length, bytes.len(), "Mach-O typed payload")?;
  ranges.push(MachOTypedRange {
    start: range.start,
    end: range.end,
    owner,
    ordinal: 0,
    alias_role,
  });
  Ok(())
}

fn macho_linkedit_data_owner(command: u32) -> Option<&'static str> {
  match command {
    MACHO_LC_SEGMENT_SPLIT_INFO => Some("segment-split-info"),
    MACHO_LC_FUNCTION_STARTS => Some("function-starts"),
    MACHO_LC_DATA_IN_CODE => Some("data-in-code"),
    MACHO_LC_DYLIB_CODE_SIGN_DRS => Some("code-sign-drs"),
    MACHO_LC_LINKER_OPTIMIZATION_HINT => Some("linker-optimization-hint"),
    MACHO_LC_DYLD_EXPORTS_TRIE => Some("exports-trie"),
    MACHO_LC_DYLD_CHAINED_FIXUPS => Some("chained-fixups"),
    MACHO_LC_ATOM_INFO => Some("atom-info"),
    MACHO_LC_FUNCTION_VARIANTS => Some("function-variants"),
    MACHO_LC_FUNCTION_VARIANT_FIXUPS => Some("function-variant-fixups"),
    _ => None,
  }
}

fn is_safe_macho_command(command: u32) -> bool {
  matches!(
    command,
    // Thread state and dylib/dylinker commands carry no __LINKEDIT ranges.
    0x04
      | 0x05
      | 0x0c
      | 0x0d
      | 0x0e
      | 0x0f
      | 0x10
      | 0x12
      | 0x13
      | 0x14
      | 0x15
      | 0x1a
      | 0x1b
      | 0x20
      | 0x24
      | 0x25
      | 0x27
      | 0x2a
      | 0x2d
      | 0x2f
      | 0x30
      | 0x32
      | 0x8000_0018
      | 0x8000_001c
      | 0x8000_001f
      | 0x8000_0023
      | 0x8000_0028
  )
}

#[cfg(test)]
mod tests {
  use std::sync::Mutex;

  use super::*;

  static MACHO_LIBSUI_LOCK: Mutex<()> = Mutex::new(());

  // Retain regression coverage for the already-implemented deferred physical
  // layouts without routing them through the public current-target gate.
  fn project_denort_base_image(
    bytes: &[u8],
    target: DenortBaseImageTarget,
    mode: DenortBaseImageMode<'_>,
  ) -> Result<DenortBaseImageProjection, DenortBaseImageError> {
    project_denort_base_image_layout(bytes, target, mode)
  }

  fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
  }

  fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
  }

  fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
  }

  fn name16(value: &[u8]) -> [u8; 16] {
    assert!(value.len() <= 16);
    let mut name = [0; 16];
    name[..value.len()].copy_from_slice(value);
    name
  }

  fn write_elf_phdr(
    bytes: &mut [u8],
    index: usize,
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    alignment: u64,
  ) {
    let start = ELF_HEADER_SIZE + index * ELF_PROGRAM_HEADER_MIN_SIZE;
    put_u32(bytes, start, p_type);
    put_u32(bytes, start + 4, flags);
    put_u64(bytes, start + 8, offset);
    put_u64(bytes, start + 16, vaddr);
    put_u64(bytes, start + 24, vaddr);
    put_u64(bytes, start + 32, filesz);
    put_u64(bytes, start + 40, memsz);
    put_u64(bytes, start + 48, alignment);
  }

  fn elf_base(machine: u16) -> Vec<u8> {
    let mut bytes = vec![0; 0x200];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, machine);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 32, ELF_HEADER_SIZE as u64);
    put_u16(&mut bytes, 52, ELF_HEADER_SIZE as u16);
    put_u16(&mut bytes, 54, ELF_PROGRAM_HEADER_MIN_SIZE as u16);
    put_u16(&mut bytes, 56, 2);
    put_u16(&mut bytes, 58, 64);
    write_elf_phdr(
      &mut bytes,
      0,
      ELF_PT_PHDR,
      ELF_PF_R,
      ELF_HEADER_SIZE as u64,
      ELF_HEADER_SIZE as u64,
      (2 * ELF_PROGRAM_HEADER_MIN_SIZE) as u64,
      (2 * ELF_PROGRAM_HEADER_MIN_SIZE) as u64,
      8,
    );
    let file_len = bytes.len() as u64;
    write_elf_phdr(
      &mut bytes,
      1,
      ELF_PT_LOAD,
      5,
      0,
      0,
      file_len,
      file_len,
      0x1000,
    );
    bytes[0x180..0x188].copy_from_slice(b"oden-elf");
    bytes
  }

  fn elf_base_with_section_table(machine: u16) -> Vec<u8> {
    let mut bytes = elf_base(machine);
    bytes.extend_from_slice(b"\0.shstrtab\0");
    bytes.resize(0x210, 0);
    let section_table_offset = bytes.len();
    bytes.resize(section_table_offset + 2 * ELF_SECTION_HEADER_MIN_SIZE, 0);
    put_u64(&mut bytes, 40, section_table_offset as u64);
    put_u16(&mut bytes, 58, ELF_SECTION_HEADER_MIN_SIZE as u16);
    put_u16(&mut bytes, 60, 2);
    put_u16(&mut bytes, 62, 1);

    let string_table = section_table_offset + ELF_SECTION_HEADER_MIN_SIZE;
    put_u32(&mut bytes, string_table, 1);
    put_u32(&mut bytes, string_table + 4, 3);
    put_u64(&mut bytes, string_table + 24, 0x200);
    put_u64(&mut bytes, string_table + 32, 11);
    put_u64(&mut bytes, string_table + 48, 1);
    bytes
  }

  fn macho_segment_command(
    segname: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    sections: &[([u8; 16], [u8; 16], u64, u64, u32, u32)],
  ) -> Vec<u8> {
    let mut command =
      vec![0; MACHO_SEGMENT_COMMAND_SIZE + sections.len() * MACHO_SECTION_SIZE];
    put_u32(&mut command, 0, MACHO_LC_SEGMENT_64);
    let command_len = command.len() as u32;
    put_u32(&mut command, 4, command_len);
    command[8..24].copy_from_slice(&segname);
    put_u64(&mut command, 24, vmaddr);
    put_u64(&mut command, 32, vmsize);
    put_u64(&mut command, 40, fileoff);
    put_u64(&mut command, 48, filesize);
    put_u32(&mut command, 56, 5);
    put_u32(&mut command, 60, 5);
    put_u32(&mut command, 64, sections.len() as u32);
    for (
      index,
      (sectname, section_segname, address, size, offset, alignment),
    ) in sections.iter().enumerate()
    {
      let start = MACHO_SEGMENT_COMMAND_SIZE + index * MACHO_SECTION_SIZE;
      command[start..start + 16].copy_from_slice(sectname);
      command[start + 16..start + 32].copy_from_slice(section_segname);
      put_u64(&mut command, start + 32, *address);
      put_u64(&mut command, start + 40, *size);
      put_u32(&mut command, start + 48, *offset);
      put_u32(&mut command, start + 52, *alignment);
    }
    command
  }

  fn macho_base(cpu: u32) -> Vec<u8> {
    let vm_base = 0x1_0000_0000;
    let linkedit_start = if cpu == MACHO_CPU_ARM64 {
      0x4000
    } else {
      0x2000
    };
    let text_name = name16(b"__TEXT");
    let text = macho_segment_command(
      text_name,
      vm_base,
      linkedit_start,
      0,
      linkedit_start,
      &[(
        name16(b"__text"),
        text_name,
        vm_base + 0x1000,
        16,
        0x1000,
        4,
      )],
    );
    let mut symtab = vec![0; 24];
    put_u32(&mut symtab, 0, MACHO_LC_SYMTAB);
    put_u32(&mut symtab, 4, 24);
    put_u32(&mut symtab, 16, linkedit_start as u32);
    put_u32(&mut symtab, 20, 8);
    let mut linkedit = macho_segment_command(
      MACHO_SEG_LINKEDIT,
      vm_base + linkedit_start,
      8,
      linkedit_start,
      8,
      &[],
    );
    put_u32(&mut linkedit, 56, 1);
    put_u32(&mut linkedit, 60, 1);

    let commands = [text, symtab, linkedit];
    let commands_size = commands.iter().map(Vec::len).sum::<usize>();
    let mut bytes = vec![0; linkedit_start as usize + 8];
    put_u32(&mut bytes, 0, MACHO_MAGIC_64_LE);
    put_u32(&mut bytes, 4, cpu);
    put_u32(&mut bytes, 8, if cpu == MACHO_CPU_X86_64 { 3 } else { 0 });
    put_u32(&mut bytes, 12, MACHO_FILETYPE_EXECUTE);
    put_u32(&mut bytes, 16, commands.len() as u32);
    put_u32(&mut bytes, 20, commands_size as u32);
    put_u32(&mut bytes, 24, 0x0020_0085);
    let mut position = MACHO_HEADER_SIZE;
    for command in commands {
      bytes[position..position + command.len()].copy_from_slice(&command);
      position += command.len();
    }
    bytes[0x1000..0x1010].copy_from_slice(b"oden-macho-text!");
    bytes[linkedit_start as usize..].copy_from_slice(b"\0oden\0x\0");
    bytes
  }

  fn macho_symtab_command_offset() -> usize {
    MACHO_HEADER_SIZE + MACHO_SEGMENT_COMMAND_SIZE + MACHO_SECTION_SIZE
  }

  fn macho_linkedit_command_offset() -> usize {
    macho_symtab_command_offset() + 24
  }

  fn insert_macho_commands_before_linkedit(
    mut bytes: Vec<u8>,
    commands: &[Vec<u8>],
  ) -> Vec<u8> {
    let insertion_offset = macho_linkedit_command_offset();
    let inserted_size = commands.iter().map(Vec::len).sum::<usize>();
    let linkedit_end = insertion_offset + MACHO_SEGMENT_COMMAND_SIZE;
    assert!(commands.iter().all(|command| command.len() % 8 == 0));
    assert!(linkedit_end + inserted_size <= 0x1000);
    bytes.copy_within(
      insertion_offset..linkedit_end,
      insertion_offset + inserted_size,
    );
    let mut position = insertion_offset;
    for command in commands {
      bytes[position..position + command.len()].copy_from_slice(command);
      position += command.len();
    }
    let command_count = read_u32(&bytes, 16).unwrap();
    let commands_size = read_u32(&bytes, 20).unwrap();
    put_u32(&mut bytes, 16, command_count + commands.len() as u32);
    put_u32(&mut bytes, 20, commands_size + inserted_size as u32);
    bytes
  }

  fn macho_dyld_info_export_command(offset: u32, size: u32) -> Vec<u8> {
    let mut command = vec![0; 48];
    put_u32(&mut command, 0, MACHO_LC_DYLD_INFO_ONLY);
    put_u32(&mut command, 4, 48);
    put_u32(&mut command, 40, offset);
    put_u32(&mut command, 44, size);
    command
  }

  fn macho_linkedit_data_command(
    command_type: u32,
    offset: u32,
    size: u32,
  ) -> Vec<u8> {
    let mut command = vec![0; 16];
    put_u32(&mut command, 0, command_type);
    put_u32(&mut command, 4, 16);
    put_u32(&mut command, 8, offset);
    put_u32(&mut command, 12, size);
    command
  }

  fn macho_exact_export_alias_base() -> Vec<u8> {
    let mut bytes = macho_base(MACHO_CPU_X86_64);
    let symtab_offset = macho_symtab_command_offset();
    bytes[symtab_offset + 8..symtab_offset + 24].fill(0);
    insert_macho_commands_before_linkedit(
      bytes,
      &[
        macho_dyld_info_export_command(0x2000, 8),
        macho_linkedit_data_command(MACHO_LC_DYLD_EXPORTS_TRIE, 0x2000, 8),
      ],
    )
  }

  fn macho_zero_linkedit_padding_base() -> Vec<u8> {
    let mut bytes = macho_base(MACHO_CPU_X86_64);
    bytes.resize(0x2020, 0);
    bytes[0x2000..].fill(0);

    let symtab_offset = macho_symtab_command_offset();
    put_u32(&mut bytes, symtab_offset + 8, 0x2001);
    put_u32(&mut bytes, symtab_offset + 12, 1);
    put_u32(&mut bytes, symtab_offset + 16, 0x2012);
    put_u32(&mut bytes, symtab_offset + 20, 4);
    for (index, byte) in bytes[0x2001..0x2011].iter_mut().enumerate() {
      *byte = (index + 1) as u8;
    }
    bytes[0x2012..0x2016].copy_from_slice(b"\0a\0b");

    let linkedit_offset = macho_linkedit_command_offset();
    put_u64(&mut bytes, linkedit_offset + 32, 0x20);
    put_u64(&mut bytes, linkedit_offset + 48, 0x20);
    bytes
  }

  fn macho_two_ordinary_segment_base() -> Vec<u8> {
    let vm_base = 0x1_0000_0000;
    let data_name = name16(b"__DATA");
    let data = macho_segment_command(
      data_name,
      vm_base + 0x2000,
      0x1000,
      0x2000,
      0x1000,
      &[(name16(b"__data"), data_name, vm_base + 0x2000, 1, 0x2000, 0)],
    );
    let mut bytes = macho_base(MACHO_CPU_X86_64);
    let linkedit_bytes = bytes[0x2000..0x2008].to_vec();
    bytes.resize(0x3008, 0);
    bytes[0x2000..].fill(0);
    bytes[0x2000] = 0xaa;
    bytes[0x3000..0x3008].copy_from_slice(&linkedit_bytes);
    put_u32(&mut bytes, macho_symtab_command_offset() + 16, 0x3000);

    let mut bytes = insert_macho_commands_before_linkedit(bytes, &[data]);
    let linkedit = macho_linkedit_command_offset()
      + MACHO_SEGMENT_COMMAND_SIZE
      + MACHO_SECTION_SIZE;
    put_u64(&mut bytes, linkedit + 24, vm_base + 0x3000);
    put_u64(&mut bytes, linkedit + 32, 8);
    put_u64(&mut bytes, linkedit + 40, 0x3000);
    put_u64(&mut bytes, linkedit + 48, 8);
    bytes
  }

  fn libsui_embed_elf(base: &[u8], standalone: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    libsui::Elf::new(base)
      .append("d3n0l4nd", standalone, &mut output)
      .unwrap();
    output
  }

  fn libsui_embed_macho(base: &[u8], standalone: &[u8]) -> Vec<u8> {
    // libsui 0.16.3 uses a process-id-only temporary name when removing an
    // x86_64 macOS signature, so parallel calls in one test process race.
    let _guard = MACHO_LIBSUI_LOCK.lock().unwrap();
    let mut output = Vec::new();
    libsui::Macho::from(base.to_vec())
      .unwrap()
      .write_section("d3n0l4nd", standalone.to_vec())
      .unwrap()
      .build(&mut output)
      .unwrap();
    output
  }

  fn project_x86_macho_base(bytes: &[u8]) -> MachOBaseImageProjection {
    let DenortBaseImageProjection::MachO(projection) =
      project_denort_base_image(
        bytes,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      )
      .unwrap()
    else {
      panic!("x86_64 Mach-O fixture produced a non-Mach-O projection");
    };
    projection
  }

  #[test]
  fn public_target_gate_accepts_exact_two_and_refuses_deferred_targets() {
    assert_eq!(
      DenortBaseImageTarget::try_from("aarch64-apple-darwin").unwrap(),
      DenortBaseImageTarget::Aarch64AppleDarwin
    );
    assert_eq!(
      DenortBaseImageTarget::try_from("x86_64-unknown-linux-gnu").unwrap(),
      DenortBaseImageTarget::X86_64UnknownLinuxGnu
    );
    for target in ["x86_64-apple-darwin", "aarch64-unknown-linux-gnu"] {
      assert!(
        DenortBaseImageTarget::try_from(target).is_err(),
        "accepted deferred target string {target}"
      );
    }

    assert!(
      super::project_denort_base_image(
        &macho_base(MACHO_CPU_ARM64),
        DenortBaseImageTarget::Aarch64AppleDarwin,
        DenortBaseImageMode::Base,
      )
      .is_ok()
    );
    assert!(
      super::project_denort_base_image(
        &elf_base(62),
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::Base,
      )
      .is_ok()
    );

    for (bytes, target) in [
      (
        macho_base(MACHO_CPU_X86_64),
        DenortBaseImageTarget::X86_64AppleDarwin,
      ),
      (elf_base(183), DenortBaseImageTarget::Aarch64UnknownLinuxGnu),
    ] {
      assert!(matches!(
        super::project_denort_base_image(
          &bytes,
          target,
          DenortBaseImageMode::Base,
        ),
        Err(DenortBaseImageError::Unsupported(
          "target is outside the current Oden release matrix"
        ))
      ));
    }
  }

  #[test]
  fn elf_projection_is_stable_across_exact_libsui_embedding() {
    let standalone = b"standalone-elf-fixture";
    for (machine, target) in [
      (183, DenortBaseImageTarget::Aarch64UnknownLinuxGnu),
      (62, DenortBaseImageTarget::X86_64UnknownLinuxGnu),
    ] {
      let base = elf_base(machine);
      let embedded = libsui_embed_elf(&base, standalone);
      let base_projection =
        project_denort_base_image(&base, target, DenortBaseImageMode::Base)
          .unwrap();
      let embedded_projection = project_denort_base_image(
        &embedded,
        target,
        DenortBaseImageMode::SuiEmbedded {
          standalone_data: standalone,
        },
      )
      .unwrap();
      assert_eq!(base_projection, embedded_projection);
      assert_eq!(
        base_projection.digest().unwrap(),
        embedded_projection.digest().unwrap()
      );
    }
  }

  #[test]
  fn elf_section_table_is_bounded_and_normalizes_across_embedding() {
    let standalone = b"standalone-elf-section-table-fixture";
    let base = elf_base_with_section_table(62);
    let embedded = libsui_embed_elf(&base, standalone);
    let base_projection = project_denort_base_image(
      &base,
      DenortBaseImageTarget::X86_64UnknownLinuxGnu,
      DenortBaseImageMode::Base,
    )
    .unwrap();
    let embedded_projection = project_denort_base_image(
      &embedded,
      DenortBaseImageTarget::X86_64UnknownLinuxGnu,
      DenortBaseImageMode::SuiEmbedded {
        standalone_data: standalone,
      },
    )
    .unwrap();
    assert_eq!(base_projection, embedded_projection);

    let mut missing_offset = base.clone();
    put_u64(&mut missing_offset, 40, 0);
    assert!(matches!(
      project_denort_base_image(
        &missing_offset,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "ELF section-header offset and count must both be zero or nonzero"
      ))
    ));

    let mut missing_count = base.clone();
    put_u16(&mut missing_count, 60, 0);
    assert!(matches!(
      project_denort_base_image(
        &missing_count,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "ELF section-header offset and count must both be zero or nonzero"
      ))
    ));

    let mut short_entry = base.clone();
    put_u16(&mut short_entry, 58, 63);
    assert!(matches!(
      project_denort_base_image(
        &short_entry,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "ELF section-header entries are shorter than ELF64"
      ))
    ));

    let mut bad_name_index = base.clone();
    put_u16(&mut bad_name_index, 62, 2);
    assert!(matches!(
      project_denort_base_image(
        &bad_name_index,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "ELF section-name index is outside the section-header table"
      ))
    ));

    let mut out_of_file = base;
    put_u64(&mut out_of_file, 40, u64::MAX - 32);
    assert!(matches!(
      project_denort_base_image(
        &out_of_file,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Overflow(_))
        | Err(DenortBaseImageError::OutOfFile(_))
    ));

    let mut no_table_with_name_index = elf_base(62);
    put_u16(&mut no_table_with_name_index, 62, 1);
    assert!(matches!(
      project_denort_base_image(
        &no_table_with_name_index,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "ELF without a section-header table has a section-name index"
      ))
    ));
  }

  #[test]
  fn macho_projection_is_stable_across_exact_libsui_embedding() {
    let standalone = b"standalone-macho-fixture";
    for (cpu, target) in [
      (MACHO_CPU_ARM64, DenortBaseImageTarget::Aarch64AppleDarwin),
      (MACHO_CPU_X86_64, DenortBaseImageTarget::X86_64AppleDarwin),
    ] {
      let base = macho_base(cpu);
      let embedded = libsui_embed_macho(&base, standalone);
      let base_projection =
        project_denort_base_image(&base, target, DenortBaseImageMode::Base)
          .unwrap();
      let embedded_projection = project_denort_base_image(
        &embedded,
        target,
        DenortBaseImageMode::SuiEmbedded {
          standalone_data: standalone,
        },
      )
      .unwrap();
      assert_eq!(base_projection, embedded_projection);
      assert_eq!(
        base_projection.digest().unwrap(),
        embedded_projection.digest().unwrap()
      );
    }
  }

  #[test]
  fn macho_exact_export_alias_emits_both_rows_and_retains_sizes() {
    let projection = project_x86_macho_base(&macho_exact_export_alias_base());
    let linkedit = projection
      .payloads
      .iter()
      .filter(|payload| payload.kind != MachOPayloadKind::Segment)
      .collect::<Vec<_>>();
    assert_eq!(linkedit.len(), 2);
    assert_eq!(linkedit[0].owner, "load-command/2/export");
    assert_eq!(linkedit[1].owner, "load-command/3/exports-trie");
    assert_eq!(linkedit[0].ordinal, 0);
    assert_eq!(linkedit[1].ordinal, 0);
    assert_eq!(linkedit[0].byte_length, 8);
    assert_eq!(linkedit[1].byte_length, 8);
    assert_eq!(linkedit[0].digest, linkedit[1].digest);

    let dyld = URL_SAFE_NO_PAD
      .decode(&projection.load_commands[2].canonical_bytes)
      .unwrap();
    assert_eq!(read_u32(&dyld, 40).unwrap(), 0);
    assert_eq!(read_u32(&dyld, 44).unwrap(), 8);
    let exports_trie = URL_SAFE_NO_PAD
      .decode(&projection.load_commands[3].canonical_bytes)
      .unwrap();
    assert_eq!(read_u32(&exports_trie, 8).unwrap(), 0);
    assert_eq!(read_u32(&exports_trie, 12).unwrap(), 8);
  }

  #[test]
  fn macho_empty_data_in_code_anchor_is_canonicalized_without_a_row() {
    let bytes = insert_macho_commands_before_linkedit(
      macho_zero_linkedit_padding_base(),
      &[
        macho_linkedit_data_command(MACHO_LC_FUNCTION_STARTS, 0x2000, 1),
        macho_linkedit_data_command(MACHO_LC_DATA_IN_CODE, 0x2001, 0),
      ],
    );
    let projection = project_x86_macho_base(&bytes);
    assert!(
      projection
        .payloads
        .iter()
        .all(|payload| !payload.owner.ends_with("/data-in-code"))
    );
    let data_in_code = URL_SAFE_NO_PAD
      .decode(&projection.load_commands[3].canonical_bytes)
      .unwrap();
    assert_eq!(read_u32(&data_in_code, 8).unwrap(), 0);
    assert_eq!(read_u32(&data_in_code, 12).unwrap(), 0);

    let invalid = insert_macho_commands_before_linkedit(
      macho_base(MACHO_CPU_X86_64),
      &[macho_linkedit_data_command(
        MACHO_LC_FUNCTION_STARTS,
        0x2000,
        0,
      )],
    );
    assert!(matches!(
      project_denort_base_image(
        &invalid,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Unsupported(
        "zero-length Mach-O typed payload has a nonzero offset"
      ))
    ));
  }

  #[test]
  fn macho_empty_data_in_code_anchor_requires_exact_closed_relation() {
    let make = |middle: Option<Vec<u8>>, function_size: u32| {
      let mut commands = vec![macho_linkedit_data_command(
        MACHO_LC_FUNCTION_STARTS,
        0x2000,
        function_size,
      )];
      if let Some(middle) = middle {
        commands.push(middle);
      }
      commands.push(macho_linkedit_data_command(
        MACHO_LC_DATA_IN_CODE,
        0x2001,
        0,
      ));
      insert_macho_commands_before_linkedit(
        macho_zero_linkedit_padding_base(),
        &commands,
      )
    };

    let wrong_function_end = make(None, 2);
    assert!(matches!(
      project_denort_base_image(
        &wrong_function_end,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "anchored empty LC_DATA_IN_CODE is not the function/symbol boundary"
      ))
    ));

    let not_immediate = make(
      Some(macho_linkedit_data_command(
        MACHO_LC_FUNCTION_VARIANTS,
        0,
        0,
      )),
      1,
    );
    assert!(matches!(
      project_denort_base_image(
        &not_immediate,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "anchored empty LC_DATA_IN_CODE lacks unique preceding function starts"
      ))
    ));

    let mut wrong_symbol_start = make(None, 1);
    put_u32(
      &mut wrong_symbol_start,
      macho_symtab_command_offset() + 8,
      0x2002,
    );
    assert!(matches!(
      project_denort_base_image(
        &wrong_symbol_start,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "anchored empty LC_DATA_IN_CODE is not the function/symbol boundary"
      ))
    ));

    let duplicate = insert_macho_commands_before_linkedit(
      macho_zero_linkedit_padding_base(),
      &[
        macho_linkedit_data_command(MACHO_LC_FUNCTION_STARTS, 0x2000, 1),
        macho_linkedit_data_command(MACHO_LC_DATA_IN_CODE, 0x2001, 0),
        macho_linkedit_data_command(MACHO_LC_DATA_IN_CODE, 0, 0),
      ],
    );
    assert!(matches!(
      project_denort_base_image(
        &duplicate,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Ambiguous(
        "anchored empty LC_DATA_IN_CODE must be the unique command of its type"
      ))
    ));
  }

  #[test]
  fn macho_requires_one_symtab_and_exact_x86_sentinel_relation() {
    let mut missing = macho_base(MACHO_CPU_X86_64);
    put_u32(&mut missing, macho_symtab_command_offset(), 0x1b);
    assert!(matches!(
      project_denort_base_image(
        &missing,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Ambiguous(
        "Mach-O must contain exactly one LC_SYMTAB command"
      ))
    ));

    let base = macho_base(MACHO_CPU_X86_64);
    let duplicate_command = base
      [macho_symtab_command_offset()..macho_linkedit_command_offset()]
      .to_vec();
    let duplicate =
      insert_macho_commands_before_linkedit(base, &[duplicate_command]);
    assert!(matches!(
      project_denort_base_image(
        &duplicate,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Ambiguous(
        "Mach-O must contain exactly one LC_SYMTAB command"
      ))
    ));

    let standalone = b"x86-sentinel-relation";
    let mut embedded =
      libsui_embed_macho(&macho_base(MACHO_CPU_X86_64), standalone);
    let string_size_offset = macho_symtab_command_offset() + 20;
    let string_size = read_u32(&embedded, string_size_offset).unwrap();
    put_u32(&mut embedded, string_size_offset, string_size - 1);
    assert!(matches!(
      project_denort_base_image(
        &embedded,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::SuiEmbedded {
          standalone_data: standalone,
        },
      ),
      Err(DenortBaseImageError::Malformed(
        "x86_64 LC_SYMTAB.strsize does not end at the SUI payload end"
      ))
    ));
  }

  #[test]
  fn macho_zero_linkedit_gaps_emit_maximal_padding_rows() {
    let projection =
      project_x86_macho_base(&macho_zero_linkedit_padding_base());
    let text_owner =
      format!("segment/{}", URL_SAFE_NO_PAD.encode(name16(b"__TEXT")));
    let rows = projection
      .payloads
      .iter()
      .map(|payload| {
        (
          payload.kind,
          payload.owner.as_str(),
          payload.ordinal,
          payload.byte_length,
        )
      })
      .collect::<Vec<_>>();
    assert_eq!(
      rows,
      [
        (MachOPayloadKind::Segment, text_owner.as_str(), 0, 0x1000,),
        (MachOPayloadKind::LinkeditPadding, "padding/0", 0, 1),
        (MachOPayloadKind::Linkedit, "load-command/1/symbols", 0, 16,),
        (MachOPayloadKind::LinkeditPadding, "padding/1", 0, 1),
        (MachOPayloadKind::Linkedit, "load-command/1/strings", 0, 4,),
        (MachOPayloadKind::LinkeditPadding, "padding/2", 0, 10),
      ]
    );
  }

  #[test]
  fn macho_nonzero_linkedit_gaps_refuse() {
    for offset in [0x2000, 0x2011, 0x2016] {
      let mut bytes = macho_zero_linkedit_padding_base();
      bytes[offset] = 1;
      assert!(matches!(
        project_denort_base_image(
          &bytes,
          DenortBaseImageTarget::X86_64AppleDarwin,
          DenortBaseImageMode::Base,
        ),
        Err(DenortBaseImageError::Malformed(
          "uncovered Mach-O __LINKEDIT bytes are nonzero"
        ))
      ));
    }
  }

  #[test]
  fn macho_partial_and_non_export_aliases_refuse() {
    let mut partial = macho_exact_export_alias_base();
    let exports_command = macho_linkedit_command_offset() + 48;
    put_u32(&mut partial, exports_command + 8, 0x2001);
    put_u32(&mut partial, exports_command + 12, 7);
    assert!(matches!(
      project_denort_base_image(
        &partial,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Unsupported(
        "partial overlap between Mach-O typed payload ranges"
      ))
    ));

    let mut other_alias = macho_exact_export_alias_base();
    put_u32(&mut other_alias, exports_command, MACHO_LC_FUNCTION_STARTS);
    assert!(matches!(
      project_denort_base_image(
        &other_alias,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Unsupported(
        "only an exact export/exports-trie Mach-O alias is accepted"
      ))
    ));
  }

  #[test]
  fn macho_duplicate_segment_owners_use_occurrence_ordinals() {
    let vm_base = 0x1_0000_0000;
    let aux_name = name16(b"__AUX");
    let bytes = insert_macho_commands_before_linkedit(
      macho_base(MACHO_CPU_X86_64),
      &[
        macho_segment_command(aux_name, vm_base + 0x3000, 0, 0, 0, &[]),
        macho_segment_command(aux_name, vm_base + 0x4000, 0, 0, 0, &[]),
      ],
    );
    let projection = project_x86_macho_base(&bytes);
    let segments = projection
      .payloads
      .iter()
      .filter(|payload| payload.kind == MachOPayloadKind::Segment)
      .map(|payload| {
        (payload.owner.as_str(), payload.ordinal, payload.byte_length)
      })
      .collect::<Vec<_>>();
    let text_owner =
      format!("segment/{}", URL_SAFE_NO_PAD.encode(name16(b"__TEXT")));
    let aux_owner = format!("segment/{}", URL_SAFE_NO_PAD.encode(aux_name));
    assert_eq!(
      segments,
      [
        (text_owner.as_str(), 0, 0x1000),
        (aux_owner.as_str(), 0, 0),
        (aux_owner.as_str(), 1, 0),
      ]
    );
  }

  #[test]
  fn macho_vm_layout_mutations_refuse_before_normalization() {
    let vm_base = 0x1_0000_0000;

    let mut section_bias = macho_base(MACHO_CPU_X86_64);
    let section_address = MACHO_HEADER_SIZE + MACHO_SEGMENT_COMMAND_SIZE + 32;
    put_u64(&mut section_bias, section_address, vm_base + 0x1001);
    assert!(matches!(
      project_denort_base_image(
        &section_bias,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "Mach-O section file and VM offsets have different segment bias"
      ))
    ));

    let mut rounded_extent = macho_base(MACHO_CPU_X86_64);
    put_u64(&mut rounded_extent, MACHO_HEADER_SIZE + 32, 0x3000);
    put_u64(
      &mut rounded_extent,
      macho_linkedit_command_offset() + 24,
      vm_base + 0x3000,
    );
    assert!(matches!(
      project_denort_base_image(
        &rounded_extent,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "Mach-O ordinary segment extents are not exact page-rounded section extents"
      ))
    ));

    let mut linkedit_extent = macho_base(MACHO_CPU_X86_64);
    put_u64(
      &mut linkedit_extent,
      macho_linkedit_command_offset() + 32,
      9,
    );
    assert!(matches!(
      project_denort_base_image(
        &linkedit_extent,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "Mach-O __LINKEDIT VM extent or section shape is not exact"
      ))
    ));

    let mut vm_overlap = macho_base(MACHO_CPU_X86_64);
    put_u64(
      &mut vm_overlap,
      macho_linkedit_command_offset() + 24,
      vm_base + 0x1000,
    );
    assert!(matches!(
      project_denort_base_image(
        &vm_overlap,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "Mach-O file-backed segments are not contiguous in VM command order"
      ))
    ));

    let mut common_bias = macho_two_ordinary_segment_base();
    let data_command = macho_linkedit_command_offset();
    put_u64(&mut common_bias, data_command + 24, vm_base + 0x3000);
    put_u64(
      &mut common_bias,
      data_command + MACHO_SEGMENT_COMMAND_SIZE + 32,
      vm_base + 0x3000,
    );
    assert!(matches!(
      project_denort_base_image(
        &common_bias,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base,
      ),
      Err(DenortBaseImageError::Malformed(
        "Mach-O ordinary file-backed segments do not share one VM/file bias"
      ))
    ));
  }

  #[test]
  fn projection_digest_is_nul_framed_hjcs() {
    let projection = project_denort_base_image(
      &elf_base(62),
      DenortBaseImageTarget::X86_64UnknownLinuxGnu,
      DenortBaseImageMode::Base,
    )
    .unwrap();
    let canonical = projection.canonical_json().unwrap();
    let mut expected = Sha256::new();
    expected.update(DENORT_BASE_IMAGE_PROJECTION_DOMAIN.as_bytes());
    expected.update([0]);
    expected.update(canonical.as_bytes());
    assert_eq!(
      projection.digest().unwrap(),
      format!("sha256-{}", URL_SAFE_NO_PAD.encode(expected.finalize()))
    );
    let value: Value = serde_json::from_str(&canonical).unwrap();
    assert_eq!(value["schema"], DENORT_BASE_IMAGE_PROJECTION_SCHEMA);
    assert_eq!(value.as_object().unwrap().len(), 5);
  }

  #[test]
  fn retained_payload_changes_projection_digest() {
    let mut elf = elf_base(62);
    let first = denort_base_image_projection_digest(
      &elf,
      DenortBaseImageTarget::X86_64UnknownLinuxGnu,
      DenortBaseImageMode::Base,
    )
    .unwrap();
    elf[0x180] ^= 1;
    let second = denort_base_image_projection_digest(
      &elf,
      DenortBaseImageTarget::X86_64UnknownLinuxGnu,
      DenortBaseImageMode::Base,
    )
    .unwrap();
    assert_ne!(first, second);

    let mut macho = macho_base(MACHO_CPU_ARM64);
    let first = denort_base_image_projection_digest(
      &macho,
      DenortBaseImageTarget::Aarch64AppleDarwin,
      DenortBaseImageMode::Base,
    )
    .unwrap();
    macho[0x1000] ^= 1;
    let second = denort_base_image_projection_digest(
      &macho,
      DenortBaseImageTarget::Aarch64AppleDarwin,
      DenortBaseImageMode::Base,
    )
    .unwrap();
    assert_ne!(first, second);
  }

  #[test]
  fn rejects_format_type_and_target_mismatches() {
    let elf = elf_base(62);
    assert!(matches!(
      project_denort_base_image(
        &elf,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base
      ),
      Err(DenortBaseImageError::TargetMismatch(_))
    ));
    let macho = macho_base(MACHO_CPU_X86_64);
    assert!(matches!(
      project_denort_base_image(
        &macho,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::Base
      ),
      Err(DenortBaseImageError::TargetMismatch(_))
    ));

    let mut executable_elf = elf.clone();
    put_u16(&mut executable_elf, 16, 2);
    assert!(matches!(
      project_denort_base_image(
        &executable_elf,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::Base
      ),
      Err(DenortBaseImageError::Unsupported(_))
    ));

    let mut fat_macho = macho.clone();
    fat_macho[..4].copy_from_slice(&0xcafe_babeu32.to_le_bytes());
    assert!(matches!(
      project_denort_base_image(
        &fat_macho,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base
      ),
      Err(DenortBaseImageError::Unsupported(_))
    ));
    assert!(matches!(
      project_denort_base_image(
        &macho,
        DenortBaseImageTarget::Aarch64AppleDarwin,
        DenortBaseImageMode::Base
      ),
      Err(DenortBaseImageError::TargetMismatch(_))
    ));

    let mut wrong_subtype = macho.clone();
    put_u32(&mut wrong_subtype, 8, 0);
    assert!(matches!(
      project_denort_base_image(
        &wrong_subtype,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base
      ),
      Err(DenortBaseImageError::TargetMismatch(_))
    ));

    let mut big_endian = macho;
    put_u32(&mut big_endian, 0, 0xcffa_edfe);
    assert!(matches!(
      project_denort_base_image(
        &big_endian,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base
      ),
      Err(DenortBaseImageError::Unsupported(_))
    ));
  }

  #[test]
  fn rejects_wrong_or_ambiguous_sui_embeddings() {
    let standalone = b"standalone-data";
    let elf_once = libsui_embed_elf(&elf_base(62), standalone);
    assert!(matches!(
      project_denort_base_image(
        &elf_once,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::SuiEmbedded {
          standalone_data: b"different"
        }
      ),
      Err(DenortBaseImageError::Malformed(_))
    ));
    let elf_twice = libsui_embed_elf(&elf_once, standalone);
    assert!(matches!(
      project_denort_base_image(
        &elf_twice,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::SuiEmbedded {
          standalone_data: standalone
        }
      ),
      Err(DenortBaseImageError::Ambiguous(_))
    ));

    let macho_once =
      libsui_embed_macho(&macho_base(MACHO_CPU_X86_64), standalone);
    assert!(matches!(
      project_denort_base_image(
        &macho_once,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::SuiEmbedded {
          standalone_data: b"different"
        }
      ),
      Err(DenortBaseImageError::Malformed(_))
    ));
    let macho_twice = libsui_embed_macho(&macho_once, standalone);
    assert!(matches!(
      project_denort_base_image(
        &macho_twice,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::SuiEmbedded {
          standalone_data: standalone
        }
      ),
      Err(DenortBaseImageError::Ambiguous(_))
    ));
  }

  #[test]
  fn malformed_ranges_and_command_tables_fail_closed() {
    let mut elf = elf_base(62);
    put_u64(&mut elf, 32, u64::MAX - 8);
    assert!(matches!(
      project_denort_base_image(
        &elf,
        DenortBaseImageTarget::X86_64UnknownLinuxGnu,
        DenortBaseImageMode::Base
      ),
      Err(DenortBaseImageError::Overflow(_))
        | Err(DenortBaseImageError::OutOfFile(_))
    ));

    let mut macho = macho_base(MACHO_CPU_X86_64);
    put_u32(&mut macho, MACHO_HEADER_SIZE + 4, 7);
    assert!(matches!(
      project_denort_base_image(
        &macho,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base
      ),
      Err(DenortBaseImageError::Malformed(_))
    ));
  }

  #[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "linux", target_arch = "x86_64"),
  ))]
  #[test]
  fn current_target_denort_is_stable_across_exact_libsui_embedding() {
    let path = match std::env::var_os("ODEN_DENORT_BASE_IMAGE_FIXTURE") {
      Some(path) => path,
      None => {
        let message = "current-target denort fixture not provided; required invocation: /tmp/oden-disk-guard.sh env ODEN_REQUIRE_DENORT_BASE_IMAGE_FIXTURE=1 ODEN_DENORT_BASE_IMAGE_FIXTURE=/absolute/path/to/denort cargo test -p deno_lib --lib current_target_denort_is_stable_across_exact_libsui_embedding -- --nocapture";
        if std::env::var("ODEN_REQUIRE_DENORT_BASE_IMAGE_FIXTURE")
          .is_ok_and(|value| value == "1")
        {
          panic!("required {message}");
        }
        eprintln!("SKIPPED: {message}");
        return;
      }
    };
    let base = std::fs::read(&path).unwrap_or_else(|error| {
      panic!("failed to read denort fixture {path:?}: {error}")
    });
    let standalone = b"oden-current-target-denort-projection-fixture";

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let target = DenortBaseImageTarget::Aarch64AppleDarwin;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let target = DenortBaseImageTarget::X86_64UnknownLinuxGnu;

    #[cfg(target_os = "macos")]
    let embedded = libsui_embed_macho(&base, standalone);
    #[cfg(target_os = "linux")]
    let embedded = libsui_embed_elf(&base, standalone);

    let base_projection =
      project_denort_base_image(&base, target, DenortBaseImageMode::Base)
        .unwrap_or_else(|error| {
          panic!("current-target base denort projection refused: {error}")
        });
    let embedded_projection = project_denort_base_image(
      &embedded,
      target,
      DenortBaseImageMode::SuiEmbedded {
        standalone_data: standalone,
      },
    )
    .unwrap_or_else(|error| {
      panic!("current-target embedded denort projection refused: {error}")
    });
    assert_eq!(base_projection, embedded_projection);
    assert_eq!(
      base_projection.digest().unwrap(),
      embedded_projection.digest().unwrap()
    );
  }

  #[test]
  fn unsupported_macho_semantics_are_explicit_errors() {
    let mut command = vec![0; 8];
    put_u32(&mut command, 0, 0x7fff_fffe);
    put_u32(&mut command, 4, 8);
    let unknown_command = insert_macho_commands_before_linkedit(
      macho_base(MACHO_CPU_X86_64),
      &[command],
    );
    assert!(matches!(
      project_denort_base_image(
        &unknown_command,
        DenortBaseImageTarget::X86_64AppleDarwin,
        DenortBaseImageMode::Base
      ),
      Err(DenortBaseImageError::Unsupported(
        "Mach-O load command is outside the closed recognized table"
      ))
    ));
  }
}
