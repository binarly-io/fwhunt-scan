import os
import click
from typing import List

TAG = "ghcr.io/binarly-io/fwhunt_scan:latest"


@click.group()
def cli():
    pass


@click.command()
def install():
    """Pull docker image."""

    os.system(" ".join(["docker", "pull", TAG]))


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
    """Scan input UEFI image."""

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
    rules_cmd = [TAG, "scan", "/tmp/image"]
    for rule in rules:
        _, name = os.path.split(rule)
        cmd += ["-v", f"{os.path.realpath(rule)}:/tmp/{name}:ro"]
        rules_cmd += ["-r", f"/tmp/{name}"]

    cmd += rules_cmd
    cmdstr = " ".join(cmd)

    print(f"Command: {cmdstr}")

    os.system(cmdstr)

    return True


cli.add_command(install)
cli.add_command(analyze_image)
cli.add_command(scan)

if __name__ == "__main__":
    cli()
