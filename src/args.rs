use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author="mussweg", version, about="Investigate Hacked WordPress Instances.")]
pub struct Args {
    #[clap(short='f', long="format", value_enum)]
    pub format: Option<OutputFormats>,

    #[clap(short='o', long="output")]
    pub destination_fp: Option<String>,

    #[clap(subcommand)]
    pub command: Commands,
}

impl Args {
    pub fn new() -> Self {
        Args::parse()
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {

    #[clap(about = "Compare hacked WordPress instance to the original source code.")]
    WebScan {
        #[clap(value_parser=validate_path)]
        hacked_wordpress_fp: String,
    },

    #[clap(about = "Compare hacked WordPress instance to a backup.")]
    BackupScan {
        #[clap(value_parser=validate_path)]
        hacked_wordpress_fp: String,

        #[clap(value_parser=validate_path)]
        backup_wordpress_fp: String,
    },
}


#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormats {
    CSV,
}

fn validate_path(path: &str) -> Result<(), String> {
    if PathBuf::from(path).exists() {
        Ok(())
    } else {
        Err(format!("Invalid path provided: {}", path))
    }
}
