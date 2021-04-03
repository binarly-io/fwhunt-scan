#!/usr/bin/env python3
#
# pylint: disable=invalid-name,missing-module-docstring,missing-function-docstring

# uefi_r2: tools for analyzing UEFI firmware using radare2

import json
import os

import click
from uefi_r2.uefi_analyzer import r2_uefi_analyzer


@click.group()
def cli():
    pass


@click.command()
@click.argument('image_path')
@click.option('-o', '--out', help='Output JSON file.')
def analyze_image(image_path: str, out: str) -> bool:
    """Analyze input UEFI image."""

    if not os.path.isfile(image_path):
        print('{} check image path'.format(
            click.style('ERROR', fg='red', bold=True)))
        return False
    summary = r2_uefi_analyzer.r2_get_summary(image_path, debug=True)
    if out:
        with open(out, 'w') as f:
            json.dump(summary, f, indent=4)
    return True


cli.add_command(analyze_image)

if __name__ == '__main__':
    cli()
