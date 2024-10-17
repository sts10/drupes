use std::{collections::{BTreeMap, HashMap}, fs::File, path::PathBuf};

use clap::Parser;
use rayon::prelude::*;
use size::Size;
use walkdir::WalkDir;

#[derive(Parser)]
struct Fdupes {
    #[clap(short, long)]
    no_empty: bool,

    #[clap(short('f'), long)]
    omit_first: bool,

    #[clap(short('m'), long)]
    summarize: bool,

    roots: Vec<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Fdupes::parse();

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

    let hashed_files = paths.into_par_iter().flat_map(|(_size, paths)| {
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
        for (_hash, mut files) in hashed_files {
            if files.len() > 1 {
                files.sort();
                let mut files = files.into_iter();
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

    Ok(())
}
