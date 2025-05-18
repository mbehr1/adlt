/// TODOs:
/// [] check whether extracted files have proper metadata (time...)
use lazy_static::lazy_static;

use cached::proc_macro::cached;
use regex::Regex;
use slog::{info, warn};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek},
    mem::MaybeUninit,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};
use tempfile::TempDir;

use crate::utils::seekablechain::SeekableChain;

use super::cloneable_seekable_reader::{CloneableSeekableReader, HasLength};

#[cfg(feature = "libarchive")]
use compress_tools::{
    list_archive_files, ArchiveContents, ArchiveIterator, ArchiveIteratorBuilder,
};
#[cfg(all(feature = "libarchive", target_os = "windows"))]
const S_IFDIR: u16 = 16384;

#[cfg(all(feature = "libarchive", target_os = "macos"))]
const S_IFDIR: u16 = 16384;

#[cfg(all(
    feature = "libarchive",
    not(target_os = "windows"),
    not(target_os = "macos")
))]
const S_IFDIR: u32 = 16384;

#[cfg(feature = "libarchive")]
use std::{
    io::{BufWriter, Write},
    path::Component,
};

// pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// parse an "archive_glob" like foo.zip/**/*.dlt into the archive (foo.zip) and the glob part (**/*.dlt)
///
/// Two formats are supported:
///  - foo.zip/... and
///  - foo.zip!/...
///
/// The functions does this by checking whether any ancestor the of path does exist.
/// So it's not a parsing of it but needs a real file on disk.
///
/// If the path does and exist and is a supported archive then that file with the
/// global wildcard pattern "**/*" is returned.
///
/// Take care: you cannot rely solely on glob_pattern.matches but have to compare against
/// glob_patter.as_str() as well! (as e.g. the "glob_pattern" can be a filename with [] inside)
pub fn archive_get_path_and_glob(path: &Path) -> Option<(PathBuf, glob::Pattern)> {
    if !path.exists() {
        if path.as_os_str().to_string_lossy().contains("!/") {
            // split into those 2 parts:
            let path = path.as_os_str().to_string_lossy();
            let parts: Vec<&str> = path.splitn(2, "!/").collect();
            if parts.len() == 2 {
                let archive = Path::new(parts[0]);
                let glob_pattern = parts[1];
                if archive.exists() && !archive.is_dir() && archive_is_supported_filename(archive) {
                    if let Ok(glob_pattern) = glob::Pattern::new(glob_pattern) {
                        return Some((archive.to_path_buf(), glob_pattern));
                    } else if let Ok(glob_pattern) =
                        glob::Pattern::new(&glob::Pattern::escape(glob_pattern))
                    {
                        return Some((archive.to_path_buf(), glob_pattern));
                    }
                }
            }
        }

        // check whether any of the parents is a zip file
        for parent in path.ancestors().skip(1) {
            if parent.exists() {
                if !parent.is_dir() && archive_is_supported_filename(parent) {
                    let glob_pattern = path
                        .display()
                        .to_string()
                        .split_off(parent.display().to_string().len() + 1);
                    if !glob_pattern.is_empty() {
                        if let Ok(glob_pattern) = glob::Pattern::new(&glob_pattern) {
                            return Some((parent.to_path_buf(), glob_pattern));
                        }
                    }
                }
                break;
            }
        }
        None
    } else if archive_is_supported_filename(path) {
        Some((path.to_path_buf(), glob::Pattern::new("**/*").unwrap()))
    } else {
        None
    }
}

pub fn archive_supported_fileexts() -> &'static [&'static str] {
    if cfg!(feature = "libarchive") {
        &[
            ".zip", ".zip.001", ".7z", ".7z.001", ".rar", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz",
            ".bz2",
        ]
    } else {
        &[".zip", ".zip.001"]
    }
}

pub fn archive_is_supported_filename(file_path: &Path) -> bool {
    let file_name = file_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    let is_supported = archive_supported_fileexts()
        .iter()
        .any(|ext| file_name.ends_with(ext));
    if !is_supported {
        // check for multi volume zip files:
        if is_part_of_multi_volume_archive(file_path) {
            return true;
        }
    }
    is_supported
}

lazy_static! {
    static ref RE_ARCHIVE_MULTI_VOL: Regex = if cfg!(feature = "libarchive") {
        Regex::new(r"(.+)(\.zip|\.7z)\.\d\d\d$").unwrap()
    } else {
        Regex::new(r"(.+)(\.zip)\.\d\d\d$").unwrap()
    };
}

pub fn is_part_of_multi_volume_archive(file_name: &Path) -> bool {
    if let Some(file_name) = file_name.file_name() {
        let file_name = file_name.to_str().unwrap_or("");
        RE_ARCHIVE_MULTI_VOL.is_match(file_name)
    } else {
        false
    }
}

pub fn search_dir_for_multi_volume_archive(any_part: &Path) -> Vec<PathBuf> {
    if let Some(captures) =
        RE_ARCHIVE_MULTI_VOL.captures(&any_part.file_name().unwrap_or_default().to_string_lossy())
    {
        let any_prefix = captures.get(1).unwrap().as_str();
        let any_ext = captures.get(2).unwrap().as_str();
        let mut multi_vols = Vec::new();
        if let Some(parent) = any_part.parent() {
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.flatten() {
                    if let Some(file_name) = entry.file_name().to_str() {
                        if let Some(captures) = RE_ARCHIVE_MULTI_VOL.captures(file_name) {
                            let prefix = captures.get(1).unwrap().as_str();
                            let ext = captures.get(2).unwrap().as_str();
                            if prefix == any_prefix && ext == any_ext {
                                multi_vols.push(entry.path());
                            }
                        }
                    }
                }
            }
            multi_vols.sort();
        }
        multi_vols
    } else {
        Vec::new()
    }
}

/// group the file names by the multi volume archive name patterns
///
/// so that file names within one group belong to the same multi volume archive
/// and are in the right order.
/// For zip files the patterns are prefix.zip.\d\d\d e.g. .zip.001, .zip.002, ...
/// For 7z files the patterns are prefix.7z.\d\d\d e.g. .7z.001, .7z.002, ...
/// For multi volumes the file names are sorted and duplicates removed.
///
pub fn group_by_archive_multi_vol(filenames: Vec<String>) -> Vec<Vec<String>> {
    let mut groups: Vec<Vec<String>> = Vec::with_capacity(filenames.len());
    for filename in filenames {
        if let Some(captures) = RE_ARCHIVE_MULTI_VOL.captures(&filename) {
            let prefix = captures.get(1).unwrap().as_str();
            let ext = captures.get(2).unwrap().as_str();
            let group = groups.iter_mut().find(|g| {
                // has same prefix and is multi vol:
                let first = g.first().unwrap(); // are always none empty
                if let Some(first_captures) = RE_ARCHIVE_MULTI_VOL.captures(first) {
                    let first_prefix = first_captures.get(1).unwrap().as_str();
                    let first_ext = first_captures.get(2).unwrap().as_str();
                    first_prefix == prefix && first_ext == ext
                } else {
                    false
                }
            });
            if let Some(group) = group {
                group.push(filename);
            } else {
                groups.push(vec![filename]);
            }
        } else {
            groups.push(vec![filename]);
        }
    }
    // sort all groups with more than 1 entry:
    for group in &mut groups {
        if group.len() > 1 {
            group.sort();
            group.dedup();
        }
    }
    groups
}

#[cached(
    size = 100,
    time = 60,
    time_refresh = true,
    result = true,
    key = "String",
    convert = r#"{ _cache_key.to_string() }"#
)]
pub fn list_archive_contents_cached(
    source: impl Read + Seek + super::cloneable_seekable_reader::HasLength,
    _cache_key: &str,
) -> Result<Vec<String>, std::io::Error> {
    list_archive_contents(source)
}

pub fn list_archive_contents<RS: Read + Seek + super::cloneable_seekable_reader::HasLength>(
    source: RS,
) -> Result<Vec<String>, std::io::Error> {
    // try ZipArchive first:
    let source = CloneableSeekableReader::new(source);

    if let Ok(zip_archive) = zip::ZipArchive::new(source.clone()) {
        return Ok(zip_archive.file_names().map(|s| s.to_string()).collect());
    }

    #[cfg(feature = "libarchive")]
    {
        // println!("list_archive_contents: fallback to libarchive");
        // fallback to libarchive:
        let contents = list_archive_files(source).map_err(std::io::Error::other)?;
        Ok(contents)
    }
    #[cfg(not(feature = "libarchive"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no libarchive support or corrupt zip file",
        ))
    }
}

/// return files and directory type similar to read_dir
/// from a list of files with abs paths e.g. from list_archive_contents.
pub fn archive_contents_read_dir<'a>(
    archive_contents: &'a [String],
    path: &str,
) -> impl Iterator<Item = (String, &'static str)> + 'a {
    let prefix = if path.is_empty() || path.ends_with('/') {
        path.to_owned()
    } else {
        format!("{}/", path)
    };
    //println!("using prefix:'{}'", prefix);
    // we dont want an empty, "." or ".." dir to be returned, so mark them as returned here.
    // we use the hashset for duplicate detection as well
    let mut hash_returned_dirs = std::collections::HashSet::from(["", ".", ".."]);
    archive_contents.iter().filter_map(move |cand_path| {
        if cand_path.starts_with(&prefix) {
            let rest = &cand_path[prefix.len()..];
            // println!("using rest:'{}'", rest);
            if !rest.contains('/') && !rest.is_empty() {
                Some((rest.to_owned(), "file"))
            } else {
                // we do want the dir as well...
                if let Some(rest) = rest.strip_suffix('/') {
                    // it's a dir:
                    if !rest.contains('/') {
                        let dir_name = &rest[..rest.len()];
                        if !hash_returned_dirs.contains(dir_name) {
                            hash_returned_dirs.insert(dir_name);
                            Some((dir_name.to_owned(), "dir"))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    // not ending with /, so a file but in sub dir
                    // return the first dir part
                    if let Some((first, _rem)) = rest.split_once('/') {
                        let dir_name = first;
                        if !hash_returned_dirs.contains(dir_name) {
                            hash_returned_dirs.insert(dir_name);
                            Some((dir_name.to_owned(), "dir"))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            }
        } else {
            None
        }
    })
}

pub fn archive_contents_metadata(
    archive_contents: &[String],
    path: &str,
) -> std::io::Result<(&'static str, usize)> {
    let dir_contents = archive_contents_read_dir(archive_contents, path);
    let count = dir_contents.count();
    if count > 0 {
        Ok(("dir", count))
    } else {
        // is it a file in the list?
        if archive_contents.iter().any(|f| f == path) {
            if !path.ends_with('/') {
                Ok(("file", 42))
            } else {
                Ok(("dir", 0))
            }
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("file or dir not found: {}", path),
            ))
        }
    }
}

#[cfg(feature = "libarchive")]
struct UnzippedEntryReader<RS: Read + Seek> {
    archive: ArchiveIterator<RS>,
    file_name: String,
    file_size: usize,
    read_size: usize,
    data: Vec<u8>, // from last read the remaining data
}

#[cfg(feature = "libarchive")]
impl<RS: Read + Seek> Read for UnzippedEntryReader<RS> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        /*println!(
            "UnzippedEntryReader({}).read(buf.len={})",
            self.file_name,
            buf.len()
        );*/
        if self.read_size >= self.file_size {
            return Ok(0); // at end
        }

        // read from data?
        if !self.data.is_empty() {
            let to_copy = std::cmp::min(self.data.len(), buf.len());
            buf[..to_copy].copy_from_slice(&self.data[..to_copy]);
            self.read_size += to_copy;
            self.data = self.data.split_off(to_copy);
            return Ok(to_copy);
        }

        // we expect more data, read from archive:
        for content in &mut self.archive {
            match content {
                ArchiveContents::DataChunk(mut data) => {
                    //println!("UnzippedEntryReader read: data: {}", data.len());
                    let to_copy = std::cmp::min(data.len(), buf.len());
                    buf[..to_copy].copy_from_slice(&data[..to_copy]);
                    self.read_size += to_copy;
                    self.data = data.split_off(to_copy);
                    return Ok(to_copy);
                }
                ArchiveContents::EndOfEntry => {
                    return Ok(0); // at end
                }
                ArchiveContents::Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Error reading file {}: {}", self.file_name, e),
                    ));
                }
                _ => {}
            }
        }
        // should not happen...
        println!(
            "UnzippedEntryReader.read(): unexpected end of archive {}/{} of {}",
            self.read_size, self.file_size, self.file_name
        );
        // todo better return an error here!
        Ok(0)
    }
}

// for extraction we do want to provide a
// Read+Seek interface
// or just Read and if Seek is needed the
// LowMarkBufReader (to support just limited Seek within a buffer) can be used
// but as we do want to support zip files in zip files... we need full Seek+Read

// we extract only two way:
// 1. single file Read only
// 2. every thing else (Read+Seek or multiple files) extracted to a temp dir
//
// reason: only the single file is possibel without full extraction.
// multiple files: we cannot guarantee that the 2nd file can be read before the 1st one
// read+seek: not offered by libarchive

/// extract a single file from the archive to a Read interface
///
/// take care: Read / no Seek interface! Use extract_to_dir for Read+Seek
#[cfg(feature = "libarchive")]
pub fn extract_to_reader<'a, RS: Read + Seek + 'a>(
    source: RS,
    file: &str,
) -> Result<impl Read + 'a, compress_tools::Error> {
    let file_name = file.to_string();
    let mut archive = ArchiveIteratorBuilder::new(source)
        .filter(move |str, _stat| str == file_name)
        .build()?;

    // check whether the file is in the archive:
    // and determine the size
    let mut file_name = None;
    let mut file_size = 0usize;

    for content in &mut archive {
        if let ArchiveContents::StartOfEntry(name, stat) = content {
            if stat.st_mode & S_IFDIR == S_IFDIR {
                // ignoring! (unexpected anyhow)
            } else if stat.st_size >= 0 {
                file_name = Some(name);
                file_size = stat.st_size as usize;
                break; // rest part of iterator
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("file {} has negative size", name),
                )
                .into());
            }
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("file {:?} has unexpected content", file_name),
            )
            .into());
        }
    }
    if let Some(file_name) = file_name {
        let unzipped_reader = UnzippedEntryReader {
            archive,
            file_name,
            file_size,
            read_size: 0,
            data: Vec::new(),
        };
        Ok(unzipped_reader)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("file {} not found in archive", file),
        )
        .into())
    }
}

// from compress-tools-rs (not public yet)
#[cfg(feature = "libarchive")]
fn sanitize_destination_path(dest: &Path) -> Result<&Path, std::io::Error> {
    let dest = dest.strip_prefix("/").unwrap_or(dest);

    dest.components()
        .find(|c| c == &Component::ParentDir)
        .map_or(Ok(dest), |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cannot use relative destination directory",
            ))
        })
}

/// extract all files from the archive to a target directory
///
/// # Arguments
/// * `source`: the archive to extract
/// * `target_dir`: the directory to extract the files to
/// * `files_filter``: if Some, only extract the files with the given paths/names
///
/// # Returns
/// Returns list of the extracted files (relative names to target_dir)
///
/// # Note
/// Any files in the target dir will be overwritten!
pub fn extract_to_dir<RS: Read + Seek + HasLength>(
    source: RS,
    target_dir: &Path,
    files_filter: Option<Vec<String>>,
    rename_map: &HashMap<String, String>, // from -> to
    shall_cancel: &Arc<AtomicBool>,
) -> Result<Vec<PathBuf>, std::io::Error> {
    // skip existing files from files_filter: (but report as extracted)
    // this is intended for extracting some files into the same tempdir with one tempdir per archive
    let mut extracted: Vec<PathBuf> = Vec::new();

    let files_filter = if let Some(files) = files_filter {
        let mut files_filter = Vec::with_capacity(files.len());
        for file in files {
            let new_file_name = if let Some(new_file_name) = rename_map.get(&file) {
                new_file_name
            } else {
                &file
            };
            let target_file = target_dir.join(new_file_name);
            if !target_file.exists() {
                files_filter.push(file); // need the unmapped name here
            } else {
                extracted.push(new_file_name.into());
            }
        }
        Some(files_filter)
    } else {
        None
    };

    // try first with zip lib...
    let source = CloneableSeekableReader::new(source);
    if let Ok(mut zip_archive) = zip::ZipArchive::new(source.clone()) {
        for i in 0..zip_archive.len() {
            if shall_cancel.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "extraction cancelled",
                ));
            }
            if let Ok(mut file) = zip_archive.by_index(i) {
                if let Some(file_name) = file.enclosed_name() {
                    if let Some(files) = &files_filter {
                        if !files.iter().any(|f| *f == file_name.to_string_lossy()) {
                            continue;
                        }
                    }
                    if file.is_dir() {
                        let target_dir = target_dir.join(file_name);
                        // println!("creating dir: {}", target_dir.display());
                        std::fs::create_dir_all(target_dir)?;
                    } else if file.is_file() {
                        let new_file_name = if let Some(new_file_name) =
                            rename_map.get(file_name.to_string_lossy().as_ref())
                        {
                            PathBuf::from(&new_file_name)
                        } else {
                            file_name
                        };
                        let target_file = target_dir.join(&new_file_name);
                        // todo skip existing files!
                        if let Some(target_dir) = target_file.parent() {
                            std::fs::create_dir_all(target_dir)?;
                            let mut target_file = std::fs::File::create(target_file)?;
                            // use a cancelable copy here
                            //std::io::copy(&mut file, &mut target_file)?;
                            // todo or better a cancelable reader? (check what's faster)
                            cancelable_copy(&mut file, &mut target_file, shall_cancel)?;
                            extracted.push(new_file_name);
                        }
                    } // ignore symlinks
                }
            }
        }
        return Ok(extracted);
    }
    #[cfg(feature = "libarchive")]
    {
        // println!("extract_to_dir: using fallback to libarchive...");
        let archive = if let Some(files) = files_filter {
            ArchiveIteratorBuilder::new(source)
                .filter(move |str, _stat| files.iter().any(|f| f == str))
                .build()
                .map_err(std::io::Error::other)?
        } else {
            // todo use uncompress_archive !
            ArchiveIterator::from_read(source).map_err(std::io::Error::other)?
        };

        let mut file_writer: Option<BufWriter<_>> = None;
        let mut cur_file_name = None;
        let mut bytes_expected = 0;
        for content in archive {
            if shall_cancel.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "extraction cancelled",
                ));
            }
            match content {
                ArchiveContents::StartOfEntry(name, stat) => {
                    // if is dir, create it
                    if stat.st_mode & S_IFDIR == S_IFDIR {
                        let rel_dir = sanitize_destination_path(Path::new(&name))?;
                        let target_dir = target_dir.join(rel_dir);
                        //println!("creating dir: {}", target_dir.display());
                        std::fs::create_dir_all(target_dir)?;
                    } else {
                        let new_name = rename_map.get(&name).unwrap_or(&name).to_string();
                        let file_name = sanitize_destination_path(Path::new(&new_name))?;
                        let target_file = target_dir.join(file_name);
                        if let Some(target_dir) = target_file.parent() {
                            // todo skip existing files!
                            std::fs::create_dir_all(target_dir)?;
                            let target_file = std::fs::File::create(target_file)?;
                            bytes_expected = stat.st_size;
                            file_writer = Some(std::io::BufWriter::new(target_file));
                            cur_file_name = Some(new_name);
                        } else {
                            cur_file_name = None;
                        }
                    }
                }
                ArchiveContents::DataChunk(data) => {
                    if let Some(writer) = &mut file_writer {
                        writer.write_all(&data)?;
                        bytes_expected -= data.len() as i64;
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "Unexpected data chunk (no file writer) for file {:?}",
                                cur_file_name // else(|| "unknown file".into())
                            ),
                        ));
                    }
                }
                ArchiveContents::EndOfEntry => {
                    if let Some(writer) = &mut file_writer {
                        writer.flush()?;
                        let cur_name = cur_file_name.take().unwrap(); // always exists with file_writer
                        if bytes_expected > 0 {
                            // we allow <0 as for some files the size is not known (0) upfront
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    "not enough data {bytes_expected} bytes missing for file {}",
                                    cur_name
                                ),
                            ));
                        }
                        extracted.push(PathBuf::from(cur_name));
                    } // else return err! todo
                    file_writer = None;
                }
                ArchiveContents::Err(e) => {
                    println!("error: {}", e);
                    return Err(std::io::Error::other(e));
                }
            }
        }
        // todo verify bytes_expected here again
        Ok(extracted)
    }
    #[cfg(not(feature = "libarchive"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no libarchive support or corrupt zip file",
        ))
    }
}

// taken from an older version of rust std::io::copy...
fn cancelable_copy<R: std::io::Read + ?Sized, W: std::io::Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    shall_cancel: &Arc<AtomicBool>,
) -> std::io::Result<u64> {
    let mut buf = MaybeUninit::<[u8; 64 * 1024]>::uninit();

    // unsafe {
    // ??? todo? reader.initializer().initialize(buf.get_mut());
    // }

    let mut written = 0;
    loop {
        let len = match reader.read(
            unsafe { buf.assume_init_mut() }, /*  unsafe { buf.get_mut() }*/
        ) {
            Ok(0) => return Ok(written),
            Ok(len) => len,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        writer.write_all(unsafe {
            &buf.assume_init_ref()[..len] /*  &buf.get_ref()[..len]*/
        })?;
        written += len as u64;
        if shall_cancel.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "copy cancelled",
            ));
        }
    }
}

/// check whether a file name is a supported archive and if so extract it to a temp dir
///
/// Supports globs for archives as well like "...zip/**/*.dlt"
/// Checks whether the archive has been extracted to the temp_dirs already and reuses it if so.
/// If not it extracts the archive to a temp dir, returns the list of extracted files and adds the
/// temp dir to the temp_dirs list.
///
/// Multi-volume archives are supported and only the first part should be used (e.g. .zip.001).
///
/// .bz2, .gz (non direntry archives) with single "data" file are extracted into their name without .bz2/.gz extension.
pub fn extract_archives(
    file_name: String,
    temp_dirs: &mut Vec<(String, TempDir)>,
    shall_cancel: &Arc<AtomicBool>,
    log: &slog::Logger,
) -> Vec<String> {
    // check whether its a archive file or whether it's a non existing file with a glob pattern
    let path = std::path::Path::new(&file_name);
    if let Some((archive_path, glob_pattern)) = archive_get_path_and_glob(path) {
        let start_time = Instant::now();
        let (mut archive, can_path) = if is_part_of_multi_volume_archive(&archive_path) {
            let all_parts = search_dir_for_multi_volume_archive(&archive_path);
            info!(
                log,
                "search for other parts for multi volume archive file got: '{:?}'.", all_parts
            );
            let can_path: String = all_parts
                .first()
                .unwrap_or(&archive_path)
                .canonicalize()
                .map_or_else(
                    |_| file_name.clone(),
                    |f| f.to_str().unwrap_or_default().to_owned(),
                );
            let all_files: Vec<_> = all_parts.iter().flat_map(File::open).collect();
            (SeekableChain::new(all_files), can_path)
        } else {
            let can_path: String = archive_path.canonicalize().map_or_else(
                |_| file_name.clone(),
                |f| f.to_str().unwrap_or_default().to_owned(),
            );
            if let Ok(archive_file) = File::open(&archive_path) {
                (SeekableChain::new(vec![archive_file]), can_path)
            } else {
                warn!(
                    log,
                    "failed to open archive file '{}'",
                    archive_path.display()
                );
                return vec![file_name];
            }
        };
        // todo could optimize for glob **/*
        // and/or extract only supported file extensions...

        // special support for .bz2/.gz files with just a single entry "data"
        let archive_name = archive_path
            .file_stem()
            .map(|f| f.to_string_lossy())
            .unwrap_or("data".into());
        let mut rename_map: HashMap<String, String> = HashMap::new();

        match list_archive_contents_cached(&mut archive, &archive_path.to_string_lossy()) {
            Ok(archive_contents) => {
                archive
                    .seek(std::io::SeekFrom::Start(0))
                    .expect("failed to seek");
                let mut matching_files = vec![];
                if archive_contents.len() == 1 && archive_contents[0] == "data" {
                    // special case for .bz2/.gz files with just a single entry "data"
                    if glob_pattern.as_str() == "data" {
                        // no rename
                        matching_files.push("data".to_owned());
                    } else if archive_name == glob_pattern.as_str()
                        || glob_pattern.matches(&archive_name)
                    {
                        let entry = archive_contents[0].to_owned();
                        rename_map.insert(entry.to_owned(), archive_name.to_string());
                        matching_files.push(entry);
                    }
                } else {
                    for entry in archive_contents {
                        if (entry == glob_pattern.as_str() || glob_pattern.matches(&entry))
                            && !entry.ends_with('/')
                        {
                            // we dont need to extract the directories. if there is any file they will be created
                            matching_files.push(entry);
                        }
                    }
                }
                info!(
                    log,
                    "found {} matching files in {}:{:?} took {:?}",
                    matching_files.len(),
                    archive_path.display(),
                    matching_files,
                    start_time.elapsed()
                );
                if !matching_files.is_empty() {
                    // do we have this tempdir yet?
                    let (temp_dir_path, new_temp_dir) =
                        if let Some(temp_dir) = temp_dirs.iter().find(|(p, _d)| p == &can_path) {
                            (temp_dir.1.path().to_owned(), None)
                        } else {
                            let temp_dir = TempDir::new().expect("failed to create temp dir");
                            (temp_dir.path().to_owned(), Some(temp_dir))
                        };
                    //let temp_dir = TempDir::new().expect("failed to create temp dir");
                    info!(
                        log,
                        "extracting archive file '{}' to '{}'",
                        file_name,
                        temp_dir_path.display()
                    );
                    //let temp_dir_path = temp_dir.path().to_owned();
                    match extract_to_dir(
                        &mut archive,
                        &temp_dir_path,
                        Some(matching_files.clone()),
                        &rename_map,
                        shall_cancel,
                    ) {
                        Ok(extracted) => {
                            info!(
                                log,
                                "extracted {}/{} matching files took {:?}",
                                extracted.len(),
                                matching_files.len(),
                                start_time.elapsed()
                            );
                            if let Some(temp_dir) = new_temp_dir {
                                temp_dirs.push((can_path, temp_dir));
                            }
                            extracted
                                .iter()
                                .map(|p| temp_dir_path.join(p).to_string_lossy().to_string())
                                .collect()
                        }
                        Err(e) => {
                            warn!(
                                log,
                                "failed to extract archive file '{}' due to {:?}", file_name, e
                            );
                            vec![file_name]
                        }
                    }
                } else {
                    vec![]
                }
            }
            Err(e) => {
                warn!(
                    log,
                    "failed to list archive contents of '{}' due to {:?}",
                    archive_path.display(),
                    e
                );
                vec![]
            }
        }
    } else {
        // not a supported archive
        vec![file_name]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::utils::seekablechain;
    use slog::{o, Drain, Logger};
    use std::{io::Cursor, time::Instant};
    use tempfile::tempdir;

    #[cfg(feature = "libarchive")]
    use compress_tools::{ArchiveContents, ArchiveIteratorBuilder};

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[test]
    fn test_archive_get_path_and_glob_existing_file() {
        let path = Path::new("tests/lc_ex002.zip"); // an existing file
        let result = archive_get_path_and_glob(path);
        let expected = Some((
            PathBuf::from("tests/lc_ex002.zip"),
            glob::Pattern::new("**/*").unwrap(),
        ));
        assert_eq!(result, expected);
    }

    #[test]
    fn test_archive_get_path_and_glob_existing_directory() {
        let path = Path::new("tests");
        let result = archive_get_path_and_glob(path);
        assert_eq!(result, None);
    }

    #[test]
    fn test_archive_get_path_and_glob_non_existing_file() {
        let path = Path::new("baz.zip");
        let result = archive_get_path_and_glob(path);
        assert_eq!(result, None);
    }

    #[test]
    fn test_archive_get_path_and_glob_nested_file() {
        let path = Path::new("tests/lc_ex002.zip!/nested/file.txt");
        let result = archive_get_path_and_glob(path);
        let expected = Some((
            PathBuf::from("tests/lc_ex002.zip"),
            glob::Pattern::new("nested/file.txt").unwrap(),
        ));
        assert_eq!(result, expected);
    }

    #[test]
    fn test_archive_get_path_and_glob_nested_file_with_glob_chars() {
        let path = Path::new("tests/lc_ex002.zip!/nested/file[01].txt");
        let result = archive_get_path_and_glob(path);
        let expected = Some((
            PathBuf::from("tests/lc_ex002.zip"),
            glob::Pattern::new("nested/file[01].txt").unwrap(),
        ));
        assert_eq!(result, expected);
        let result = result.unwrap();
        assert!(
            result.1.matches("nested/file[01].txt") || result.1.as_str() == "nested/file[01].txt"
        );
    }

    #[test]
    fn test_archive_get_path_and_glob_nested_file_with_invalid_glob_chars() {
        let path = Path::new("tests/lc_ex002.zip!/nested/file[0-1-2.txt");
        let result = archive_get_path_and_glob(path);
        let expected = Some((
            PathBuf::from("tests/lc_ex002.zip"),
            glob::Pattern::new(&glob::Pattern::escape("nested/file[0-1-2.txt")).unwrap(),
        ));
        assert_eq!(result, expected);
        let result = result.unwrap();
        assert!(result.1.matches("nested/file[0-1-2.txt"));
    }

    #[test]
    fn test_archive_get_path_and_glob_nested_file_with_glob() {
        let path = Path::new("tests/lc_ex002.zip/nested/*.txt"); // syntax without "!"
        let result = archive_get_path_and_glob(path);
        let expected = Some((
            PathBuf::from("tests/lc_ex002.zip"),
            glob::Pattern::new("nested/*.txt").unwrap(),
        ));
        assert_eq!(result, expected);
    }

    #[test]
    fn test_archive_contents_metadata_file_exists() {
        let archive_contents = vec!["file1.txt".to_string(), "file2.txt".to_string()];
        let path = "file2.txt";
        let result = archive_contents_metadata(&archive_contents, path).unwrap();
        assert_eq!(result.0, "file");
    }

    #[test]
    fn test_archive_contents_metadata_file_not_found() {
        let archive_contents = vec!["file1.txt".to_string(), "file2.txt".to_string()];
        let path = "file3.txt";
        let result = archive_contents_metadata(&archive_contents, path);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "file or dir not found: file3.txt"
        );
    }

    #[test]
    fn test_archive_contents_metadata_dir_exists() {
        let archive_contents = vec!["dir1/".to_string(), "dir2/".to_string()];
        let path = "dir2/";
        let result = archive_contents_metadata(&archive_contents, path).unwrap();
        assert_eq!(result, ("dir", 0));
    }

    #[test]
    fn test_archive_contents_metadata_dir_not_found() {
        let archive_contents = vec!["dir1/".to_string(), "dir2/".to_string()];
        let path = "dir3/";
        let result = archive_contents_metadata(&archive_contents, path);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "file or dir not found: dir3/"
        );
    }

    #[test]
    fn unzip_list_zip() {
        let start_time = Instant::now();
        let source = std::fs::File::open("tests/lc_ex002.zip").unwrap();
        let files = list_archive_contents(source).unwrap();
        let duration = start_time.elapsed();
        println!(
            "list_archive_contents() took {:?} and returned {} file names",
            duration,
            files.len()
        );
        assert_eq!(files.len(), 2);
    }

    #[cfg(feature = "libarchive")]
    #[test]
    fn unzip_list_7z() {
        let start_time = Instant::now();
        let source = std::fs::File::open("tests/unzip_ex001.7z").unwrap();
        let files = list_archive_contents(source).unwrap();
        let duration = start_time.elapsed();
        println!(
            "list_archive_contents() took {:?} and returned {} file names",
            duration,
            files.len()
        );
        assert_eq!(files.len(), 15);
    }

    #[test]
    fn unzip_list_mult_vol() {
        // part 1, read all into a vec:
        let parts = vec![
            std::fs::File::open("tests/test_volume10k.zip.001").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.002").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.003").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.004").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.005").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.006").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.007").unwrap(),
        ];
        let mut zip_data = Vec::new();
        for mut part in &parts {
            part.read_to_end(&mut zip_data).unwrap();
        }
        // Wrap `zip_data` in a Cursor to provide it with `Read` and `Seek` capabilities
        let cursor = Cursor::new(zip_data);
        let start_time = Instant::now();
        let files = list_archive_contents(cursor).unwrap();
        let duration = start_time.elapsed();
        println!(
            "list_archive_contents() took {:?} and returned {} file names",
            duration,
            files.len()
        );

        // we can chain them as well:
        let seekablechain = seekablechain::SeekableChain::new(parts);

        let start_time = Instant::now();
        let files = list_archive_contents(seekablechain).unwrap();
        let duration = start_time.elapsed();
        println!(
            "list_archive_contents() via seekablechain took {:?} and returned {} file names",
            duration,
            files.len()
        );
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn unzip_list_mult_vol_cached() {
        // part 1, read all into a vec:
        let parts = vec![
            std::fs::File::open("tests/test_volume10k.zip.001").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.002").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.003").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.004").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.005").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.006").unwrap(),
            std::fs::File::open("tests/test_volume10k.zip.007").unwrap(),
        ];
        let mut zip_data = Vec::new();
        for mut part in &parts {
            part.read_to_end(&mut zip_data).unwrap();
        }
        // Wrap `zip_data` in a Cursor to provide it with `Read` and `Seek` capabilities
        let cursor = Cursor::new(zip_data);
        let start_time = Instant::now();
        let files = list_archive_contents_cached(cursor, "vol10k").unwrap();
        let duration = start_time.elapsed();
        println!(
            "list_archive_contents_cached() took {:?} and returned {} file names",
            duration,
            files.len()
        );

        // provide wrong data to show that the cache is in use
        let parts = vec![std::fs::File::open("tests/test_volume10k.zip.003").unwrap()];
        let mut zip_data = Vec::new();
        for mut part in &parts {
            part.read_to_end(&mut zip_data).unwrap();
        }
        // Wrap `zip_data` in a Cursor to provide it with `Read` and `Seek` capabilities
        let cursor = Cursor::new(zip_data);
        let start_time = Instant::now();
        let files_cached = list_archive_contents_cached(cursor, "vol10k").unwrap();
        let duration = start_time.elapsed();
        println!(
            "list_archive_contents_cached() took {:?} and returned {} file names",
            duration,
            files_cached.len()
        );
        assert_eq!(files, files_cached);
    }

    #[test]
    fn test_archive_contents_read_dir() {
        // includes directories only entries
        let files = vec![
            "foo/bar.txt".to_string(),
            "foo/baz.txt".to_string(),
            "foo/".to_string(),
            "foo/bar/".to_string(),
            "foo/bar/baz.txt".to_string(),
            "foo/bar/baz/".to_string(),
            "foo/bar/baz/qux.txt".to_string(),
            "bla".to_string(),
        ];
        let entries_root: Vec<_> = archive_contents_read_dir(&files, "").collect();
        println!("entries_root: {:?}", entries_root);
        assert_eq!(2, entries_root.len());
        assert_eq!(
            entries_root,
            vec![("foo".to_string(), "dir"), ("bla".to_string(), "file")]
        );
        let entries_foo: Vec<_> = archive_contents_read_dir(&files, "foo/").collect();
        println!("entries_foo: {:?}", entries_foo);
        assert_eq!(3, entries_foo.len());
        assert_eq!(
            entries_foo,
            vec![
                ("bar.txt".to_string(), "file"),
                ("baz.txt".to_string(), "file"),
                ("bar".to_string(), "dir")
            ]
        );
        let entries_bar: Vec<_> = archive_contents_read_dir(&files, "foo/bar").collect();
        println!("entries_bar: {:?}", entries_bar);
        assert_eq!(2, entries_bar.len());
        assert_eq!(
            entries_bar,
            vec![("baz.txt".to_string(), "file"), ("baz".to_string(), "dir")]
        );
    }

    #[test]
    fn test_archive_contents_read_dir_non_dirs() {
        // 7z e.g. dont include dir only entries
        let files = vec![
            "foo/bar.txt".to_string(),
            "foo/baz.txt".to_string(),
            "foo/bar/baz.txt".to_string(),
            "foo/bar/baz/".to_string(),
            "foo/bar/baz/qux.txt".to_string(),
            "bla".to_string(),
        ];
        let entries_root: Vec<_> = archive_contents_read_dir(&files, "").collect();
        println!("entries_root: {:?}", entries_root);
        assert_eq!(2, entries_root.len());
        assert_eq!(
            entries_root,
            vec![("foo".to_string(), "dir"), ("bla".to_string(), "file")]
        );
        let entries_foo: Vec<_> = archive_contents_read_dir(&files, "foo/").collect();
        println!("entries_foo: {:?}", entries_foo);
        assert_eq!(3, entries_foo.len());
        assert_eq!(
            entries_foo,
            vec![
                ("bar.txt".to_string(), "file"),
                ("baz.txt".to_string(), "file"),
                ("bar".to_string(), "dir")
            ]
        );
        let entries_bar: Vec<_> = archive_contents_read_dir(&files, "foo/bar").collect();
        println!("entries_bar: {:?}", entries_bar);
        assert_eq!(2, entries_bar.len());
        assert_eq!(
            entries_bar,
            vec![("baz.txt".to_string(), "file"), ("baz".to_string(), "dir")]
        );
    }

    #[test]
    fn test_archive_contents_read_dir_special_dirs() {
        // we dont want abs paths
        let files = vec![
            "/etc/foo/bar.txt".to_string(),
            "./foo/baz.txt".to_string(),
            "../foo/bar/baz.txt".to_string(),
        ];
        let entries_root: Vec<_> = archive_contents_read_dir(&files, "").collect();
        println!("entries_root: {:?}", entries_root);
        assert_eq!(0, entries_root.len()); // todo might add support for ./...

        let entries_foo: Vec<_> = archive_contents_read_dir(&files, "etc/").collect();
        println!("entries_foo: {:?}", entries_foo);
        assert_eq!(0, entries_foo.len());

        let entries_bar: Vec<_> = archive_contents_read_dir(&files, "..").collect();
        println!("entries_bar: {:?}", entries_bar);
        assert_eq!(1, entries_bar.len());
        assert_eq!(entries_bar, vec![("foo".to_string(), "dir")]);
    }

    #[test]
    fn test_archive_contents_read_dir_dirs() {
        // we dont want abs paths
        let files = vec!["dir1/".to_string(), "dir2/".to_string()];
        let entries_root: Vec<_> = archive_contents_read_dir(&files, "").collect();
        println!("entries_root: {:?}", entries_root);
        assert_eq!(2, entries_root.len());
        assert_eq!(
            entries_root,
            vec![("dir1".to_string(), "dir"), ("dir2".to_string(), "dir")]
        );

        let entries_dir2: Vec<_> = archive_contents_read_dir(&files, "dir2/").collect();
        println!("entries_dir2: {:?}", entries_dir2);
        assert_eq!(0, entries_dir2.len());
    }

    #[test]
    fn test_group_by_zip_multi_vol() {
        let parts = vec![
            "tests/test_volume10k.zip",
            "tests/test_volume10k.zip.",
            "tests/test_volume10k.zip.004",
            "tests/test_volume10k.zip.002",
            "tests/test_volume10k.zip.003",
            "tests/test_volume10k.zip.001",
            "tests/test_volume10k.7z.002",
            "tests/test_volume10k.7z.001",
            "tests/test_volume10k.7z.001", // should be deduped!
            "tests/test_volume10k.zip",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();
        let groups = group_by_archive_multi_vol(parts);
        assert_eq!(
            groups.len(),
            if cfg!(feature = "libarchive") { 5 } else { 7 }
        );
        assert_eq!(groups[0], vec!["tests/test_volume10k.zip"]);
        assert_eq!(groups[1], vec!["tests/test_volume10k.zip."]);
        assert_eq!(
            groups[2],
            vec![
                "tests/test_volume10k.zip.001",
                "tests/test_volume10k.zip.002",
                "tests/test_volume10k.zip.003",
                "tests/test_volume10k.zip.004"
            ]
        );
        if cfg!(feature = "libarchive") {
            assert_eq!(
                groups[3],
                vec!["tests/test_volume10k.7z.001", "tests/test_volume10k.7z.002",]
            );
        }
        assert_eq!(groups[groups.len() - 1], vec!["tests/test_volume10k.zip"]); // dupl names ok for non multi vol
    }

    #[test]
    fn unzip_real_multi_vol_ex1() {
        // read dir
        let start_time = Instant::now();
        // get all file names in directory:
        if let Ok(files) =
            std::fs::read_dir("/Volumes/MB_jc3sf/logs/ext_issues/unzip_ex/240701_zips/test")
        {
            let files: Vec<_> = files
                .map(|f| f.unwrap().path().to_string_lossy().to_string())
                .collect();
            let groups = group_by_archive_multi_vol(files);
            let duration = start_time.elapsed();
            println!(
                "group_by_zip_multi_vol() took {:?} and returned {} groups",
                duration,
                groups.len()
            );
            assert_eq!(groups.len(), 1);
            println!("group 0: {:?}", groups[0]);
            assert_eq!(groups[0].len(), 5);
            let vol_files = groups[0]
                .iter()
                .map(|s| std::fs::File::open(s).unwrap())
                .collect();
            let seekablechain = seekablechain::SeekableChain::new(vol_files);
            let start_time = Instant::now();
            let files = list_archive_contents(seekablechain).unwrap();
            let duration = start_time.elapsed();
            println!(
                "list_archive_contents() via seekablechain took {:?} and returned {} file names",
                duration,
                files.len()
            );
            assert_eq!(files.len(), 252); // 201 files, 51 folders
        } else {
            println!("no files found");
        }
    }

    #[cfg(feature = "libarchive")]
    #[test]
    fn unzip_extract_to_dir_7z() {
        let start_time = Instant::now();
        let source = std::fs::File::open("tests/unzip_ex001.7z").unwrap();
        let tmp_dir = tempdir().unwrap();
        let target_dir = tmp_dir.path();
        println!("extracting to tmp_dir {:?}", target_dir);
        let files = list_archive_contents(source).unwrap();
        let source = std::fs::File::open("tests/unzip_ex001.7z").unwrap();
        let shall_cancel = Arc::new(AtomicBool::new(false));
        let extracted = extract_to_dir(
            source,
            target_dir,
            Some(files[2..4].to_owned()),
            &HashMap::new(),
            &shall_cancel,
        )
        .expect("extract_to_dir failed");
        let duration = start_time.elapsed();
        println!(
            "extract_to_dir() took {:?} and extracted {} files",
            duration,
            extracted.len()
        );
        assert_eq!(extracted.len(), 2);
        // verify content:
        let target_dir = target_dir.join("tests");
        let target_files = std::fs::read_dir(target_dir).unwrap();
        let target_files: Vec<_> = target_files.map(|f| f.unwrap().path()).collect();
        assert_eq!(target_files.len(), 2);
        // compare files with files with same name in tests dir:
        for target_file in target_files {
            let target_file_name = target_file.file_name().unwrap().to_str().unwrap();
            let test_file = std::path::Path::new("tests/").join(target_file_name);
            assert!(test_file.exists());
            let target_file = std::fs::read(target_file).unwrap();
            let test_file = std::fs::read(test_file).unwrap();
            assert_eq!(target_file, test_file);
        }
    }

    #[test]
    fn unzip_extract_to_dir_zip_multi_vol() {
        let start_time = Instant::now();
        let parts = search_dir_for_multi_volume_archive(Path::new("tests/test_volume10k.zip.001"));
        assert_eq!(parts.len(), 7);
        let sources = parts.into_iter().flat_map(std::fs::File::open).collect();
        let mut source = seekablechain::SeekableChain::new(sources);

        let tmp_dir = tempdir().unwrap();
        let target_dir = tmp_dir.path();
        let files = list_archive_contents(&mut source).unwrap();
        println!(
            "extracting {} files to tmp_dir {:?}",
            files.len(),
            target_dir
        );
        source
            .seek(std::io::SeekFrom::Start(0))
            .expect("failed to seek");
        let shall_cancel = Arc::new(AtomicBool::new(false));
        let extracted = extract_to_dir(source, target_dir, None, &HashMap::new(), &shall_cancel)
            .expect("extract_to_dir failed");
        let duration = start_time.elapsed();
        println!(
            "extract_to_dir() took {:?} and extracted {} files",
            duration,
            extracted.len()
        );
        assert_eq!(extracted.len(), 1);
    }

    #[cfg(feature = "libarchive")]
    #[test]
    fn unzip_extract_to_reader() {
        let start_time = Instant::now();
        let source = std::fs::File::open("tests/unzip_ex001.7z").unwrap();
        let files = &list_archive_contents(source).unwrap();
        let source = std::fs::File::open("tests/unzip_ex001.7z").unwrap();
        let mut reader = extract_to_reader(source, &files[2]).expect("extract_to_readers failed");
        let duration = start_time.elapsed();
        println!("extract_to_reader() took {:?}", duration,);
        // compare file
        let mut read_file_cont = Vec::new();
        let read_file_res = reader.read_to_end(&mut read_file_cont).unwrap();
        let duration = start_time.elapsed();
        println!("read_to_end() took (incl. extract...) {:?}", duration,);
        let orig_file = std::path::Path::new("./").join(&files[2]);
        let orig_file = std::fs::read(orig_file).unwrap();
        assert_eq!(orig_file.len(), read_file_res);
        assert_eq!(orig_file, read_file_cont);
    }

    #[cfg(feature = "libarchive")]
    #[test]
    fn unzip_unzip() {
        //let source = std::fs::File::open("/Users/mbehr/Downloads/(ide).zip").unwrap();
        // todo this file has slice::from_raw_parts errors!
        let start_time = Instant::now();
        let source = std::fs::File::open("tests/unzip_ex001.7z").unwrap();

        let archive = ArchiveIteratorBuilder::new(source)
            .filter(|str, stat| {
                println!(
                    " filter({},time={} size={}",
                    str, stat.st_mtime, stat.st_size
                );
                str.contains("003") || str.contains("005")
            })
            .build()
            .unwrap();

        let mut cur_file = None;
        let mut cur_size = 0;
        let mut extracted = 0;

        for content in archive
        /*ArchiveIterator::from_read(source).unwrap()*/
        {
            match content {
                ArchiveContents::StartOfEntry(name, stat) => {
                    println!("{name}: size={}", stat.st_size);
                    cur_file = Some(name);
                    cur_size = 0;
                }
                ArchiveContents::DataChunk(data) => {
                    // println!("data: {}", data.len());
                    cur_size += data.len();
                }
                ArchiveContents::EndOfEntry => {
                    extracted += 1;
                    println!("end of entry size={}", cur_size);
                    if let Some(name) = &cur_file {
                        println!("rcvd {}: size={}", name, cur_size);
                    }
                }
                ArchiveContents::Err(e) => {
                    println!("error: {}", e);
                }
            }
        }
        println!(
            "iterate() took {:?} and extracted {} files",
            start_time.elapsed(),
            extracted
        );
    }

    #[test]
    fn extract_archives_1() {
        let mut temp_dirs = vec![];
        let shall_cancel = Arc::new(AtomicBool::new(false));
        let log = new_logger();
        let files = extract_archives(
            "tests/lc_ex002.zip".to_string(),
            &mut temp_dirs,
            &shall_cancel,
            &log,
        );
        println!("extracted files: {:?}", files);
        assert_eq!(files.len(), 1);
        assert_eq!(temp_dirs.len(), 1);
    }

    #[test]
    fn extract_archives_2() {
        let mut temp_dirs = vec![];
        let shall_cancel = Arc::new(AtomicBool::new(false));
        let log = new_logger();
        let files = extract_archives(
            "tests/test_volume10k.zip.001/*.jpg".to_string(),
            &mut temp_dirs,
            &shall_cancel,
            &log,
        );
        println!("extracted files: {:?}", files);
        assert_eq!(files.len(), 1);
        assert_eq!(temp_dirs.len(), 1);
    }

    #[cfg(feature = "libarchive")]
    #[test]
    fn extract_archives_bz2() {
        let mut temp_dirs = vec![];
        let shall_cancel = Arc::new(AtomicBool::new(false));
        let log = new_logger();

        for file_name_glob in [
            "tests/lc_ex005.dlt.bz2",
            "tests/lc_ex005.dlt.bz2!/**/*.dlt",
            "tests/lc_ex005.dlt.bz2!/lc_ex005.dlt",
        ] {
            let files = extract_archives(
                file_name_glob.to_string(),
                &mut temp_dirs,
                &shall_cancel,
                &log,
            );
            println!("extracted files for '{}': {:?}", file_name_glob, files);
            assert_eq!(files.len(), 1);
            assert!(
                files[0].ends_with("/lc_ex005.dlt"),
                "failed for '{}', files[0]={}",
                file_name_glob,
                files[0]
            );
            assert_eq!(temp_dirs.len(), 1, "files={:?}", files); // should stay at 1 as we reuse!
        }
    }
}
