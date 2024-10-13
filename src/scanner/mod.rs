use crate::args::Commands;
use crate::output::ReportGenerator;

pub trait Scanner {
    fn scan(&self);
}

pub fn run_scanning(command: Commands, rg: Box<dyn ReportGenerator>) {

    let scanner: Box<dyn Scanner>;

    match command {
        Commands::WebScan{hacked_wordpress_fp} => {
            scanner = Box::new(web::WebScanner {
                hacked_wordpress_fp,
                rg
            });
        },
        Commands::BackupScan{hacked_wordpress_fp, backup_wordpress_fp} => {
            scanner = Box::new(backup::BackupScanner {
                hacked_wordpress_fp,
                backup_wordpress_fp,
                rg,
            });
        },
    }

    scanner.scan()
}

pub mod web;
pub mod backup;
pub mod utils;
