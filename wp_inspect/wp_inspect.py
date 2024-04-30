import click
from click_help_colors import HelpColorsGroup
from pyfiglet import figlet_format
from termcolor import colored

from .wordpress_comperator import (
    WordPressComperator,
    WordPressComperatorLocal,
    WordPressComperatorWeb,
)


@click.group(
    cls=HelpColorsGroup,
    help_headers_color="yellow",
    help_options_color="white",
)
def cli():
    pass


def run_comparison(wpc: WordPressComperator, outpath: str):
    """
    Identify changes made to WordPress files by comparing it to either the
    original source code from the internet or a backup.
    """
    print((colored(figlet_format("wp_forensics", font="stop"), color="yellow")) + "\n")

    # Validate paths, compare installations, and show results
    wpc.validate_paths()
    wpc.compare()
    wpc.show()

    # Export results if CSV filepath is provided
    if outpath:
        wpc.export(outpath)


@cli.command()
@click.argument("wordpress", type=str)
@click.option("--csv", type=str, default="", help="Specify the output filepath.")
def web(wordpress: str, csv: str):
    """
    Run comparison against the internet source code.
    """
    wpc = WordPressComperatorWeb(wp_filepath_hacked=wordpress)
    run_comparison(wpc, csv)


@cli.command()
@click.option(
    "--full", is_flag=True, help="If specified the program will include all filetypes."
)
@click.option("--csv", type=str, default="", help="Specify the output filepath.")
@click.argument("wordpress-backup", type=str)
@click.argument("wordpress", type=str)
def local(wordpress: str, wordpress_backup: str, csv: str, full: bool):
    """
    Run comparison against a local backup.
    """
    wpc = WordPressComperatorLocal(
        wp_filepath_hacked=wordpress, wp_filepath_backup=wordpress_backup, full=full
    )
    run_comparison(wpc, csv)
