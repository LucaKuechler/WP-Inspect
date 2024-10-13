mod args;
mod scanner;
mod output;


use args::Args;
use scanner::run_scanning;
use output::{ReportGenerator, init_report_generation};

fn main() {

    // Parse the CLI arguments.
    let args = Args::new();

    // Create the ResultGenerator object so that the scanner can write directly to the correct
    // output locations.
    let rg: Box<dyn ReportGenerator> = init_report_generation(args.format, args.destination_fp);

    // Scan the provided WordPress instances for modifications.
    run_scanning(args.command, rg);
}
