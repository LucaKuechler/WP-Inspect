use crate::output::ReportGenerator;

pub struct CSVReportGenerator{
    pub destination_fp: String,
}

impl ReportGenerator for CSVReportGenerator {
    fn write(&self) {
        println!("Generating output using CSVReportGenerator.");
    }
}
