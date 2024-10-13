use crate::args::OutputFormats;

pub trait ReportGenerator {
    fn write(&self);
}

pub fn init_report_generation(format: Option<OutputFormats>, destination_fp: Option<String>) -> Box<dyn ReportGenerator> {

    match format {
        Some(OutputFormats::CSV) => {
            let fp = match destination_fp {
                Some(v) => v,
                None => "./".to_string(),
            };

            return Box::new(csv::CSVReportGenerator{
                destination_fp: fp
            });
        },
        None => {
            return Box::new(tty::TTYReportGenerator{});
        },
    }
}

pub mod csv;
pub mod tty;
