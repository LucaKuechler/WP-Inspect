from __future__ import annotations

from pathlib import Path

import click
from click_help_colors import HelpColorsGroup
from pyfiglet import figlet_format
from termcolor import colored

from .wordpress_comperator import LineEnding, WordPressComperator, WordPressComperatorLocal, WordPressComperatorWeb


@click.group(
    cls=HelpColorsGroup,
    help_headers_color="yellow",
    help_options_color="white",
)
def cli() -> None:
    pass


def run_comparison(wpc: WordPressComperator, outpath: Path | None) -> None:
    """
    Identify changes made to WordPress files by comparing it to either the
    original source code from the internet or a backup.
    """
    print((colored(figlet_format("WP - Inspect", font="stop"), color="yellow")) + "\n")  # noqa: T201

    # Validate paths, compare installations, and show results
    wpc.validate_paths()
    wpc.compare()
    wpc.show()

    # Export results if CSV filepath is provided
    if outpath:
        wpc.export(outpath)


@cli.command()
@click.argument("wordpress", type=Path)
@click.option("--csv", type=Path, default=None, help="Specify the output filepath.")
@click.option(
    "--le",
    type=LineEnding,
    default=LineEnding.unix,
    help="Define the line ending used in the hacked wordpress files. [Default: Unix]",
)
def web(wordpress: Path, csv: Path | None, le: LineEnding) -> None:
    """
    Run comparison against the internet source code.
    """
    wpc = WordPressComperatorWeb(wp_filepath_hacked=wordpress, line_ending=le)
    run_comparison(wpc, csv)


@cli.command()
@click.option("--full", is_flag=True, help="If specified the program will include all filetypes.")
@click.option("--csv", type=Path, default=None, help="Specify the output filepath.")
@click.argument("wordpress-backup", type=Path)
@click.argument("wordpress", type=Path)
def local(wordpress: Path, wordpress_backup: Path, csv: Path | None, full: bool) -> None:  # noqa: FBT001
    """
    Run comparison against a local backup.
    """
    wpc = WordPressComperatorLocal(wp_filepath_hacked=wordpress, wp_filepath_backup=wordpress_backup, full=full)
    run_comparison(wpc, csv)
