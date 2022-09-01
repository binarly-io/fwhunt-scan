#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-3.0+

import os
import pathlib
from typing import List

import click

TAG = "fwhunt_scan"


def scan_module_or_firmware(image_path: str, rule: List[str], command: str):

    if command not in ["scan", "scan-firmware"]:
        return False

    rules = rule

    if not os.path.isfile(image_path):
        print("{} check image path".format(click.style("ERROR", fg="red", bold=True)))
        return False
    if not all(rule and os.path.isfile(rule) for rule in rules):
        print("{} check rule(s) path".format(click.style("ERROR", fg="red", bold=True)))
        return False

    cmd = [
        "docker",
        "run",
        "--rm",
        "-it",
        "-v",
        f"{os.path.realpath(image_path)}:/tmp/image:ro",
    ]
    rules_cmd = [TAG, command, "/tmp/image"]
    for rule in rules:
        _, name = os.path.split(rule)
        cmd += ["-v", f"{os.path.realpath(rule)}:/tmp/{name}:ro"]
        rules_cmd += ["-r", f"/tmp/{name}"]

    cmd += rules_cmd
    cmdstr = " ".join(cmd)

    os.system(cmdstr)

    return True


@click.group()
def cli():
    pass


@click.command()
def build():
    """Build docker image."""

    os.system(" ".join(["docker", "build", "-t", TAG, "."]))


@click.command()
@click.argument("image_path")
def analyze_image(image_path: str) -> bool:
    """Analyze input UEFI image."""

    if not os.path.isfile(image_path):
        print("{} check image path".format(click.style("ERROR", fg="red", bold=True)))
        return False

    fpath = os.path.realpath(image_path)

    cmdstr = " ".join(
        [
            "docker",
            "run",
            "--rm",
            "-it",
            "-v",
            f"{fpath}:/tmp/image:ro",
            TAG,
            "analyze-image",
            "/tmp/image",
        ]
    )

    print(f"Command: {cmdstr}")

    os.system(cmdstr)

    return True


@click.command()
@click.argument("image_path")
@click.option("-r", "--rule", help="The path to the rule.", multiple=True)
def scan(image_path: str, rule: List[str]) -> bool:
    """Scan input UEFI module."""

    return scan_module_or_firmware(image_path, rule, "scan")


@click.command()
@click.argument("image_path")
@click.option("-r", "--rule", help="The path to the rule.", multiple=True)
@click.option("-d", "--rules_dir", help="The path to the rules directory.")
def scan_firmware(image_path: str, rule: List[str], rules_dir: str) -> bool:
    """Scan UEFI firmware image."""

    rules = list(rule)
    error_prefix = click.style("ERROR", fg="red", bold=True)
    if not rules_dir:
        if not all(rules and os.path.isfile(rule) for rule in rules):
            print(f"{error_prefix} check rule(s) path")
            return False
    else:
        rules += list(map(str, pathlib.Path(rules_dir).rglob("*.yml")))

    return scan_module_or_firmware(image_path, rules, "scan-firmware")


cli.add_command(build)
cli.add_command(analyze_image)
cli.add_command(scan)
cli.add_command(scan_firmware)

if __name__ == "__main__":
    cli()
