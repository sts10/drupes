use std::{collections::{BTreeMap, HashMap}, fs::File, io::{BufReader, Read, Seek}, path::{Path, PathBuf}};

use anyhow::bail;
use clap::Parser;
use rayon::prelude::*;
use size::Size;
use walkdir::WalkDir;

/// Finds duplicate files and optionally deletes them.
#[derive(Parser)]
struct Drupes {
    /// Also consider empty files, which will remove all empty files but one.
    #[clap(short, long)]
    empty: bool,

    /// Don't print the first filename in a set of duplicates, so that all the
    /// printed filenames are files to consider removing.
    #[clap(short('f'), long)]
    omit_first: bool,

    /// Instead of listing duplicates, print a summary of what was found.
    #[clap(short('m'), long)]
    summarize: bool,

    /// Engages "paranoid mode" and performs byte-for-byte comparisons of files,
    /// in case you've found the first real-world BLAKE3 hash collision (please
    /// publish it if so)
    #[clap(short, long)]
    paranoid: bool,

    /// Try to delete all duplicates but one, skipping any files that cannot be
    /// deleted for whatever reason.
    #[clap(long)]
    delete: bool,

    /// List of directories to search, recursively, for duplicate files; if
    /// omitted, the current directory is searched.
    roots: Vec<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let mut args = Drupes::parse();

    if args.roots.is_empty() {
        // Search the current directory by default.
        args.roots.push(".".into());
    }

    // Traverse the requested parts of the filesystem, collating files by size.
    // The map is from file size (in bytes) to the list of files found with that
    // size.
    //
    // Any value in the map with more than one path represents a "file size
    // group," which is a potential duplicate group.
    let mut paths: BTreeMap<u64, Vec<PathBuf>> = BTreeMap::new();
    for root in &args.roots {
        for entry in WalkDir::new(root) {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_file() && (meta.len() > 0 || args.empty) {
                paths.entry(meta.len())
                    .or_default()
                    .push(entry.path().to_owned());
            }
        }
    }
    // Drop all file size groups that contain no duplicates (have only one
    // member).
    paths.retain(|_size, paths| paths.len() > 1);

    // Process all paths in file size groups with at least two members. This is
    // constructed as a Rayon pipeline because (1) I find it reasonably clear
    // this way once I got used to it and (2) it's by far the easiest-to-reach
    // "go faster button."
    //
    // 
    let mut hashed_files = paths.par_iter()
        // Flatten the map into a list of paths to hash.
        .flat_map(|(_size, paths)| paths)
        // Hash each path, producing a (path, hash) pair. Note that this can
        // fail to access the filesystem.
        .map(|path| {
            let mut hasher = blake3::Hasher::new();
            hasher.update_reader(File::open(path)?)?;
            Ok::<_, anyhow::Error>((path, hasher.finalize()))
        })
        // Squawk about any reads that failed, and remove them from further
        // consideration.
        .filter_map(|result| {
            match result {
                Ok(data) => Some(data),
                Err(e) => {
                    eprintln!("{e}");
                    None
                }
            }
        })
        // Collect groups of (path, hash) pairs and collate them by hash,
        // producing a stream of maps from hash to vectors of paths. The paths
        // in each vector are hash-groups. Many hash-groups will only contain
        // one path, but any groups containing more than one path have found
        // actual duplicates -- assuming you trust BLAKE3, see below.
        .fold(HashMap::<blake3::Hash, Vec<&Path>>::new, |mut map, (path, hash)| {
            map.entry(hash).or_default().push(path);
            map
        })
        // Collapse the stream of hashmaps into one, merging hash groups as
        // required.
        .reduce(HashMap::new, |mut a, b| {
            for (k, v) in b {
                a.entry(k).or_default().extend(v);
            }
            a
        });

    if args.paranoid {
        // Given our map of collated hash-groups from the previous step, let's
        // check our work.
        //
        // This takes each hash-group containing at least two paths and reads
        // the contents of each file, comparing them to one another. The files
        // are not kept in memory, so this works fine on very large files
        // (keeping files in memory is the operating system's job).
        //
        // Note that if this ever finds anything, it is **almost certainly** a
        // bug in this program. If it isn't a bug in this program, it's probably
        // a file being modified out from under us. BLAKE3 is
        // collision-resistant, and finding two files with the same length, same
        // BLAKE3 hash, and different contents would be a newsworthy event. It's
        // certainly possible, but rather unlikely.
        eprintln!("paranoid mode: verifying file contents");
        hashed_files.par_iter()
            .filter(|(_, files)| files.len() > 1)
            .try_for_each(|(_, files)| {
                // Arbitrarily choose the first file in each group as a
                // "representative."
                let first = &files[0];
                let first_f = File::open(first)?;
                let first_meta = first_f.metadata()?;
                let mut first_f = BufReader::new(first_f);

                // Compare it to every other file in the group, one at a time.
                for other in &files[1..] {
                    // ...starting from the beginning of the first file, please.
                    first_f.rewind()?;

                    let other_f = File::open(other)?;
                    let other_meta = other_f.metadata()?;
                    let mut other_f = BufReader::new(other_f);

                    // This provides some _very basic_ protection against files
                    // being modified while this program is running, but in
                    // general, this program is not written with that situation
                    // in mind.
                    if first_meta.len() != other_meta.len() {
                        bail!("files no longer have same length:\n{}\n{}",
                            first.display(),
                            other.display());
                    }

                    // Read one byte at a time from each file, comparing each
                    // byte. Single byte reads are the easiest thing to
                    // implement, and are reasonably fast because BufReader
                    // converts them into larger reads under the hood. No need
                    // to reimplement the standard library!
                    let mut buf1 = [0u8];
                    let mut buf2 = [0u8];
                    for _ in 0..first_meta.len() {
                        first_f.read_exact(&mut buf1)?;
                        other_f.read_exact(&mut buf2)?;
                        if buf1 != buf2 {
                            bail!("files differ (blake3 collision found?):\n{}\n{}",
                                first.display(),
                                other.display());
                        }
                    }
                }
                Ok(())
            })?;
        eprintln!("files really are duplicates");
    }

    if args.summarize {
        // Work out some statistics, instead of printing filenames.

        // How many unique size classes did we discover in the first pass?
        let unique_size_classes = paths.len();
        // How many files did we find in our recursive scan?
        let total_files_checked = paths.values().map(|v| v.len()).sum::<usize>();

        // How many hash-groups containing duplicates did we discover?
        let set_count = hashed_files.values()
            .filter(|files| files.len() > 1)
            .count();
        // And how many duplicates, beyond the first in each group, did we find?
        let dupe_count = hashed_files.values()
            .filter_map(|files| files.len().checked_sub(1))
            .sum::<usize>();
        // How large are the duplicates on disk?
        let dupe_size = hashed_files.values()
            .filter(|files| files.len() > 1)
            .try_fold(0, |sum, files| {
                std::fs::metadata(files[0])
                    .map(|meta| sum + meta.len() * (files.len() as u64 - 1))
            })?;
        // Convenient unit formatting:
        let dupe_size = Size::from_bytes(dupe_size);

        println!("{dupe_count} duplicate files (in {set_count} sets), \
            occupying {dupe_size}");
        println!("checked {total_files_checked} files in \
            {unique_size_classes} size classes");
    } else {
        // Print filenames of each duplicate-group.
        for files in hashed_files.values_mut() {
            if files.len() > 1 {
                // Our files have arrived in a nondeterministic order due to our
                // use of concurrency. Let's fix that.
                files.sort();

                let mut files = files.iter();
                // Implement the omit-first flag by skipping:
                if args.omit_first {
                    files.next();
                }

                for f in files {
                    println!("{}", f.display());
                }
                if !args.omit_first {
                    println!();
                }
            }
        }
    }

    if args.delete {
        // The scary delete mode!
        for files in hashed_files.values() {
            if files.len() > 1 {
                for f in &files[1..] {
                    println!("deleting: {}", f.display());
                    if let Err(e) = std::fs::remove_file(f) {
                        eprintln!("error deleting {}: {e}", f.display());
                    }
                }
            }
        }

    }

    Ok(())
}
