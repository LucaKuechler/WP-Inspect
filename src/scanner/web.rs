use crate::scanner::Scanner;
use crate::output::ReportGenerator;
use crate::scanner::utils::get_wordpress_info;


pub struct WebScanner {
    pub hacked_wordpress_fp: String,
    pub rg: Box <dyn ReportGenerator>,
}

impl Scanner for WebScanner {
    fn scan(&self) {

        // Prepare all requirements for the scanning process.
        self.preprocessing();

        println!("Scanning using WebScanner");
    }
}

impl WebScanner {
    fn preprocessing(&self) {
        // Identify the Version and Language Package of the WordPress instance.
        let (version, language) = get_wordpress_info();
    }
}
