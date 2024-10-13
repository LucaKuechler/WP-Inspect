use crate::output::ReportGenerator;

pub struct TTYReportGenerator{}

impl ReportGenerator for TTYReportGenerator {
    fn write(&self) {
        println!("Generating output using TTYReportGenerator.");
    }
}
