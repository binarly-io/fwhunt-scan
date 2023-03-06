#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-3.0+

import os
from typing import List

import click

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
def analyze_module(module_path: str) -> bool:
    """Analyze single UEFI module."""

    if not os.path.isfile(module_path):
        print("{} check module path".format(click.style("ERROR", fg="red", bold=True)))
        return False

    fpath = os.path.realpath(module_path)

    cmdstr = " ".join(
        [
            "docker",
            "run",
            "--rm",
            "-it",
            "-v",
            f"{fpath}:/tmp/image:ro",
            TAG,
            "analyze-module",
            "/tmp/image",
        ]
    )

    print(f"Command: {cmdstr}")

    os.system(cmdstr)

    return True


@click.command()
@click.argument("module_path")
@click.option("-r", "--rule", help="The path to the rule.", multiple=True)
def scan(module_path: str, rule: List[str]) -> bool:
    """Scan singe UEFI module."""

    rules = rule

    if not os.path.isfile(module_path):
        print("{} check module path".format(click.style("ERROR", fg="red", bold=True)))
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
        f"{os.path.realpath(module_path)}:/tmp/module:ro",
    ]
    rules_cmd = [TAG, "scan", "/tmp/module"]
    for r in rules:
        _, name = os.path.split(r)
        cmd += ["-v", f"{os.path.realpath(r)}:/tmp/{name}:ro"]
        rules_cmd += ["-r", f"/tmp/{name}"]

    cmd += rules_cmd
    cmdstr = " ".join(cmd)

    print(f"Commamd: {cmdstr}")

    os.system(cmdstr)

    return True


@click.command()
@click.argument("image_path")
@click.option("-r", "--rule", help="The path to the rule.", multiple=True)
@click.option("-d", "--rules_dir", help="The path to the rules directory.")
def scan_firmware(image_path: str, rule: List[str], rules_dir: str) -> bool:
    """Scan UEFI firmware image."""

    rules = rule

    if not os.path.isfile(image_path):
        print("{} check image path".format(click.style("ERROR", fg="red", bold=True)))
        return False
    if not (rules_dir or rule):
        print("{} check command".format(click.style("ERROR", fg="red", bold=True)))
        return False
    if rules_dir and not os.path.isdir(rules_dir):
        print(
            "{} check rules directory path".format(
                click.style("ERROR", fg="red", bold=True)
            )
        )
        return False
    if rule and not all(rule and os.path.isfile(rule) for rule in rules):
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
    rules_cmd = [TAG, "scan-firmware", "/tmp/image"]
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

    print(f"Commamd: {cmdstr}")

    os.system(cmdstr)

    return True


cli.add_command(build)
cli.add_command(analyze_module)
cli.add_command(scan)
cli.add_command(scan_firmware)

if __name__ == "__main__":
    cli()
