use std::{collections::{BTreeMap, HashMap}, fs::File, io::{BufReader, Read, Seek}, path::PathBuf};

use anyhow::bail;
use clap::Parser;
use rayon::prelude::*;
use size::Size;
use walkdir::WalkDir;

#[derive(Parser)]
struct Drupes {
    #[clap(short, long)]
    no_empty: bool,

    #[clap(short('f'), long)]
    omit_first: bool,

    #[clap(short('m'), long)]
    summarize: bool,

    #[clap(short, long)]
    paranoid: bool,

    #[clap(long)]
    delete: bool,

    roots: Vec<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Drupes::parse();

    let mut paths: BTreeMap<u64, Vec<PathBuf>> = BTreeMap::new();
    for root in &args.roots {
        for entry in WalkDir::new(root) {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_file() && (meta.len() > 0 || !args.no_empty) {
                paths.entry(meta.len())
                    .or_default()
                    .push(entry.path().to_owned());
            }
        }
    }
    let unique_size_classes = paths.len();
    let total_files_checked = paths.values().map(|v| v.len()).sum::<usize>();

    let mut hashed_files = paths.into_par_iter().flat_map(|(_size, paths)| {
        if paths.len() > 1 {
            paths
        } else {
            vec![]
        }
    }).map(|path| {
        let mut hasher = blake3::Hasher::new();
        hasher.update_reader(File::open(&path)?)?;
        Ok::<_, anyhow::Error>((path, hasher.finalize()))
    }).filter_map(|result| {
        match result {
            Ok(data) => Some(data),
            Err(e) => {
                eprintln!("{e}");
                None
            }
        }
    }).fold(HashMap::<_, Vec<PathBuf>>::new, |mut map, (path, hash)| {
        map.entry(hash).or_default().push(path);
        map
    }).reduce(HashMap::new, |mut a, b| {
        for (k, v) in b {
            a.entry(k).or_default().extend(v);
        }
        a
    });

    if args.paranoid {
        eprintln!("paranoid mode: verifying file contents");
        hashed_files.par_iter().try_for_each(|(_, files)| {
            if files.len() > 1 {
                let first = &files[0];
                let first_f = File::open(first)?;
                let first_meta = first_f.metadata()?;
                let mut first_f = BufReader::new(first_f);

                for other in &files[1..] {
                    first_f.rewind()?;
                    let other_f = File::open(other)?;
                    let other_meta = other_f.metadata()?;
                    let mut other_f = BufReader::new(other_f);

                    if first_meta.len() != other_meta.len() {
                        bail!("files no longer have same length:\n{}\n{}", first.display(), other.display());
                    }

                    let mut buf1 = [0u8];
                    let mut buf2 = [0u8];
                    for _ in 0..first_meta.len() {
                        first_f.read_exact(&mut buf1)?;
                        other_f.read_exact(&mut buf2)?;
                        if buf1 != buf2 {
                            bail!("files differ (blake3 collision found?):\n{}\n{}", first.display(), other.display());
                        }
                    }
                }
            }
            Ok(())
        })?;
        eprintln!("files really are duplicates");
    }

    if args.summarize {
        let set_count = hashed_files.values()
            .filter(|files| files.len() > 1)
            .count();
        let dupe_count = hashed_files.values()
            .filter_map(|files| files.len().checked_sub(1))
            .sum::<usize>();
        let dupe_size = hashed_files.values()
            .filter(|files| files.len() > 1)
            .try_fold(0, |sum, files| {
                std::fs::metadata(&files[0])
                    .map(|meta| sum + meta.len() * (files.len() as u64 - 1))
            })?;
        let dupe_size = Size::from_bytes(dupe_size);
        println!("{dupe_count} duplicate files (in {set_count} sets), \
            occupying {dupe_size}");
        println!("checked {total_files_checked} files in {unique_size_classes} size classes");
    } else {
        for files in hashed_files.values_mut() {
            if files.len() > 1 {
                files.sort();
                let mut files = files.iter();
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
