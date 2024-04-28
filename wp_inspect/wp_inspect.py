import click
from click_help_colors import HelpColorsCommand
from pyfiglet import figlet_format
from termcolor import colored

from .wordpress_comperator import WordPressComperatorFactory


@click.command(
    cls=HelpColorsCommand,
    help_headers_color="yellow",
    help_options_color="white",
)
@click.option(
    "--wordpress-backup",
    type=str,
    default="",
    help="Specify the path for wordpress-backup folder.",
)
@click.option("--csv", type=str, default="", help="Specify the output filepath.")
@click.argument("wordpress", type=str)
def main(wordpress: str, wordpress_backup: str, csv: str):
    """
    Identify changes made to WordPress files by comparing it to either the
    original source code from the internet or a backup. 
    """
    print((colored(figlet_format("wp_forensics", font="stop"), color="yellow")) + "\n")

    # Create WordPress comparator instance
    wpc_factory = WordPressComperatorFactory()
    wpc = wpc_factory.create_wpc(wordpress, wordpress_backup)

    # Validate paths, compare installations, and show results
    wpc.validate_paths()
    wpc.compare()
    wpc.show()

    # Export results if CSV filepath is provided
    if not csv == "":
        wpc.export(csv)

if __name__ == '__main__':
    main("", "", "")
