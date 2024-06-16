use lazy_static::lazy_static;

use regex::Regex;
use std::{
    io::{Read, Seek},
    path::{Path, PathBuf},
};

use super::cloneable_seekable_reader::{CloneableSeekableReader, HasLength};

#[cfg(feature = "libarchive")]
use compress_tools::{
    list_archive_files, ArchiveContents, ArchiveIterator, ArchiveIteratorBuilder,
};
#[cfg(feature = "libarchive")]
use libc::S_IFDIR;
#[cfg(feature = "libarchive")]
use std::{
    io::{BufWriter, Write},
    path::Component,
};

// pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// parse an "archive_glob" like foo.zip/**/*.dlt into the archive and the glob part
///
/// The functions does this by checking whether any ancestor the of path does exist.
/// So it's not a parsing of it but needs a real file on disk.
///
/// If the path does and exist and is a supported archive then that file with the
/// global wildcard pattern "**/*" is returned.
pub fn archive_get_path_and_glob(path: &Path) -> Option<(PathBuf, glob::Pattern)> {
    if !path.exists() {
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

pub fn archive_is_supported_filename(file_name: &Path) -> bool {
    let file_ext = file_name
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    let is_supported = file_ext == "zip"
        || (cfg!(feature = "libarchive")
            && (file_ext == "7z"
                || file_ext == "rar"
                || file_ext == "tar"
                || file_ext == "tar.gz"
                || file_ext == "tar.bz2"
                || file_ext == "tar.xz"));
    if !is_supported {
        // check for multi volume zip files:
        if is_part_of_multi_volume_archive(file_name) {
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
        let contents = list_archive_files(source)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
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
/// Returns the number of files extracted
///
/// # Note
/// Any files in the target dir will be overwritten!
pub fn extract_to_dir<RS: Read + Seek + HasLength>(
    source: RS,
    target_dir: &Path,
    files_filter: Option<Vec<String>>,
) -> Result<usize, std::io::Error> {
    // try first with zip lib...
    let source = CloneableSeekableReader::new(source);

    if let Ok(mut zip_archive) = zip::ZipArchive::new(source.clone()) {
        let mut nr_extracted = 0;
        for i in 0..zip_archive.len() {
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
                        let target_file = target_dir.join(file_name);
                        if let Some(target_dir) = target_file.parent() {
                            std::fs::create_dir_all(target_dir)?;
                            let mut target_file = std::fs::File::create(target_file)?;
                            std::io::copy(&mut file, &mut target_file)?;
                            nr_extracted += 1;
                        }
                    } // ignore symlinks
                }
            }
        }
        return Ok(nr_extracted);
    }
    #[cfg(feature = "libarchive")]
    {
        // println!("extract_to_dir: using fallback to libarchive...");
        let archive = if let Some(files) = files_filter {
            ArchiveIteratorBuilder::new(source)
                .filter(move |str, _stat| files.iter().any(|f| f == str))
                .build()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        } else {
            // todo use uncompress_archive !
            ArchiveIterator::from_read(source)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        };

        let mut file_writer: Option<BufWriter<_>> = None;
        let mut cur_file_name = None;
        let mut bytes_expected = 0;
        let mut nr_extracted = 0;
        for content in archive {
            match content {
                ArchiveContents::StartOfEntry(name, stat) => {
                    // if is dir, create it
                    if stat.st_mode & S_IFDIR == S_IFDIR {
                        let rel_dir = sanitize_destination_path(Path::new(&name))?;
                        let target_dir = target_dir.join(rel_dir);
                        //println!("creating dir: {}", target_dir.display());
                        std::fs::create_dir_all(target_dir)?;
                    } else {
                        let file_name = sanitize_destination_path(Path::new(&name))?;
                        let target_file = target_dir.join(file_name);
                        if let Some(target_dir) = target_file.parent() {
                            std::fs::create_dir_all(target_dir)?;
                            let target_file = std::fs::File::create(target_file)?;
                            bytes_expected = stat.st_size;
                            file_writer = Some(std::io::BufWriter::new(target_file));
                            cur_file_name = Some(name);
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
                                "Unexpected data chunk (no file writer) for file {}",
                                cur_file_name.unwrap_or_else(|| "unknown file".into())
                            ),
                        ));
                    }
                }
                ArchiveContents::EndOfEntry => {
                    if let Some(writer) = &mut file_writer {
                        writer.flush()?;
                        nr_extracted += 1;
                        if bytes_expected != 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    "not enough data {nr_extracted} bytes missing for file {}",
                                    cur_file_name.unwrap_or_else(|| "unknown file".into())
                                ),
                            ));
                        }
                    } // else return err! todo
                    file_writer = None;
                }
                ArchiveContents::Err(e) => {
                    println!("error: {}", e);
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                }
            }
        }
        // todo verify bytes_expected here again
        Ok(nr_extracted)
    }
    #[cfg(not(feature = "libarchive"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no libarchive support or corrupt zip file",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::utils::seekablechain;
    use std::{io::Cursor, time::Instant};
    use tempfile::tempdir;

    #[cfg(feature = "libarchive")]
    use compress_tools::{ArchiveContents, ArchiveIteratorBuilder};

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
        let nr_extracted = extract_to_dir(source, target_dir, Some(files[2..4].to_owned()))
            .expect("extract_to_dir failed");
        let duration = start_time.elapsed();
        println!(
            "extract_to_dir() took {:?} and extracted {} files",
            duration, nr_extracted
        );
        assert_eq!(nr_extracted, 2);
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
        let nr_extracted = extract_to_dir(source, target_dir, None).expect("extract_to_dir failed");
        let duration = start_time.elapsed();
        println!(
            "extract_to_dir() took {:?} and extracted {} files",
            duration, nr_extracted
        );
        assert_eq!(nr_extracted, 1);
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
}
