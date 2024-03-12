#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-3.0+

import logging
import os
from typing import List

import click

logging.basicConfig(
    format="%(name)s %(asctime)s %(levelname)s: %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
)
logger = logging.getLogger("fwhunt_scan")

TAG = "fwhunt_scan"


@click.group()
def cli():
    pass


@click.command()
def build():
    """Build docker image."""

    os.system(" ".join(["docker", "build", "-t", TAG, "."]))


@click.command()
@click.argument("module_path")
def analyze(path: str) -> bool:
    """Analyze single EFI file."""

    if not os.path.isfile(path):
        click.echo(
            "{} check module path".format(click.style("ERROR", fg="red", bold=True))
        )
        return False

    fpath = os.path.realpath(path)

    cmdstr = " ".join(
        [
            "docker",
            "run",
            "--rm",
            "-it",
            "-v",
            f"{fpath}:/tmp/module:ro",
            TAG,
            "analyze",
            "/tmp/module",
        ]
    )

    logger.debug(f"Command: {cmdstr}")

    os.system(cmdstr)

    return True


@click.command()
@click.argument("path")
@click.option("-r", "--rule", help="The path to the rule.", multiple=True)
def scan(path: str, rule: List[str]) -> bool:
    """Scan singe EFI file."""

    rules = rule

    if not os.path.isfile(path):
        click.echo(
            "{} check module path".format(click.style("ERROR", fg="red", bold=True))
        )
        return False
    if not all(rule and os.path.isfile(rule) for rule in rules):
        click.echo(
            "{} check rule(s) path".format(click.style("ERROR", fg="red", bold=True))
        )
        return False

    cmd = [
        "docker",
        "run",
        "--rm",
        "-it",
        "-v",
        f"{os.path.realpath(path)}:/tmp/module:ro",
    ]
    rules_cmd = [TAG, "scan", "/tmp/module"]
    for r in rules:
        _, name = os.path.split(r)
        cmd += ["-v", f"{os.path.realpath(r)}:/tmp/{name}:ro"]
        rules_cmd += ["-r", f"/tmp/{name}"]

    cmd += rules_cmd
    cmdstr = " ".join(cmd)

    logger.debug(f"Commamd: {cmdstr}")

    os.system(cmdstr)

    return True


@click.command()
@click.argument("image_path")
@click.option("-r", "--rule", help="The path to the rule.", multiple=True)
@click.option("-d", "--rules_dir", help="The path to the rules directory.")
@click.option(
    "-f",
    "--force",
    help="Enforcing the use of rules without specified volume guids.",
    is_flag=True,
)
def scan_firmware(
    image_path: str, rule: List[str], rules_dir: str, force: bool
) -> bool:
    """Scan UEFI firmware image."""

    rules = rule

    if not os.path.isfile(image_path):
        click.echo(
            "{} check image path".format(click.style("ERROR", fg="red", bold=True))
        )
        return False
    if not (rules_dir or rule):
        click.echo("{} check command".format(click.style("ERROR", fg="red", bold=True)))
        return False
    if rules_dir and not os.path.isdir(rules_dir):
        click.echo(
            "{} check rules directory path".format(
                click.style("ERROR", fg="red", bold=True)
            )
        )
        return False
    if rule and not all(rule and os.path.isfile(rule) for rule in rules):
        click.echo(
            "{} check rule(s) path".format(click.style("ERROR", fg="red", bold=True))
        )
        return False

    cmd = [
        "docker",
        "run",
        "--rm",
        "-it",
        "-v",
        f"{os.path.realpath(image_path)}:/tmp/image:ro",
    ]
    rules_cmd = [TAG, "scan-firmware", "/tmp/image"]

    if force:
        rules_cmd += ["-f"]

    for r in rules:
        _, name = os.path.split(r)
        cmd += ["-v", f"{os.path.realpath(r)}:/tmp/{name}:ro"]
        rules_cmd += ["-r", f"/tmp/{name}"]

    if rules_dir:
        _, name = os.path.split(rules_dir)
        cmd += ["-v", f"{os.path.realpath(rules_dir)}:/tmp/{name}:ro"]
        rules_cmd += ["--rules_dir", f"/tmp/{name}"]

    cmd += rules_cmd
    cmdstr = " ".join(cmd)

    logger.debug(f"Commamd: {cmdstr}")

    os.system(cmdstr)

    return True


cli.add_command(build)
cli.add_command(analyze, "analyze-module")
cli.add_command(analyze, "analyze-bootloader")
cli.add_command(scan)
cli.add_command(scan, "scan-module")
cli.add_command(scan, "scan-bootloader")
cli.add_command(scan_firmware)

if __name__ == "__main__":
    cli()
