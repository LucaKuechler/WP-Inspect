use crate::scanner::Scanner;
use crate::output::ReportGenerator;

pub struct BackupScanner {
    pub hacked_wordpress_fp: String,
    pub backup_wordpress_fp: String,
    pub rg: Box <dyn ReportGenerator>,
}

impl Scanner for BackupScanner {
    fn scan(&self) {
        println!("Scanning using BackupScanner");
    }
}
