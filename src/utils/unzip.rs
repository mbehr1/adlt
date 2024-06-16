use compress_tools::{
    list_archive_files, ArchiveContents, ArchiveIterator, ArchiveIteratorBuilder,
};
use std::{
    io::{BufWriter, Read, Seek, Write},
    path::{Component, Path},
};

use libc::S_IFDIR;

// pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn list_archive_contents<RS: Read + Seek>(
    source: &mut RS,
) -> Result<Vec<String>, compress_tools::Error> {
    list_archive_files(source)
}

struct UnzippedEntryReader<RS: Read + Seek> {
    archive: ArchiveIterator<RS>,
    file_name: String,
    file_size: usize,
    read_size: usize,
    data: Vec<u8>, // from last read the remaining data
}

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
pub fn extract_to_reader<'a, RS: Read + Seek + 'a>(
    source: &'a mut RS,
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
pub fn extract_to_dir<RS: Read + Seek>(
    source: &mut RS,
    target_dir: &Path,
    files_filter: Option<Vec<String>>,
) -> Result<usize, compress_tools::Error> {
    let archive = if let Some(files) = files_filter {
        ArchiveIteratorBuilder::new(source)
            .filter(move |str, _stat| files.iter().any(|f| f == str))
            .build()?
    } else {
        // todo use uncompress_archive !
        ArchiveIterator::from_read(source)?
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
                    println!("creating dir: {}", target_dir.display());
                    std::fs::create_dir_all(target_dir)?;
                } else {
                    let file_name = sanitize_destination_path(Path::new(&name))?;
                    let target_file = target_dir.join(file_name);
                    let target_dir = target_file.parent().unwrap();
                    std::fs::create_dir_all(target_dir)?;
                    let target_file = std::fs::File::create(target_file)?;
                    bytes_expected = stat.st_size;
                    file_writer = Some(std::io::BufWriter::new(target_file));
                    cur_file_name = Some(name);
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
                    )
                    .into());
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
                        )
                        .into());
                    }
                } // else return err! todo
                file_writer = None;
            }
            ArchiveContents::Err(e) => {
                println!("error: {}", e);
                return Err(e);
            }
        }
    }
    // todo verify bytes_expected here again
    Ok(nr_extracted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use compress_tools::{ArchiveContents, ArchiveIteratorBuilder};
    use std::{io::SeekFrom, time::Instant};
    use tempfile::tempdir;

    #[test]
    fn unzip_list() {
        let start_time = Instant::now();
        let mut source = std::fs::File::open("tests/unzip_ex001.7z").unwrap();
        let files = list_archive_contents(&mut source).unwrap();
        let duration = start_time.elapsed();
        println!(
            "list_archive_contents() took {:?} and returned {} file names",
            duration,
            files.len()
        );
        assert_eq!(files.len(), 15);
    }

    #[test]
    fn unzip_extract_to_dir() {
        let start_time = Instant::now();
        let mut source = std::fs::File::open("tests/unzip_ex001.7z").unwrap();
        let tmp_dir = tempdir().unwrap();
        let target_dir = tmp_dir.path();
        println!("extracting to tmp_dir {:?}", target_dir);
        let files = list_archive_contents(&mut source).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();
        let nr_extracted = extract_to_dir(&mut source, target_dir, Some(files[2..4].to_owned()))
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
    fn unzip_extract_to_reader() {
        let start_time = Instant::now();
        let mut source = std::fs::File::open("tests/unzip_ex001.7z").unwrap();
        let files = &list_archive_contents(&mut source).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();
        let mut reader =
            extract_to_reader(&mut source, &files[2]).expect("extract_to_readers failed");
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
