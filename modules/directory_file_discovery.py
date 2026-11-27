import urllib.request
import urllib.error
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

DIRECTORIES = [
    "admin/",
    "login/",
    "dashboard/",
    "api/",
    "uploads/",
    "assets/",
    "images/",
    "css/",
    "js/",
    "backup/",
    "test/",
    "dev/",
    "staging/",
    "docs/",
    "public/",
]

FILES = [
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
    "README.md",
    "index.php",
    "backup.zip",
    "config.php.bak",
    "error.log",
    "CHANGELOG.txt",
    "manifest.json",
]


def normalize_url(domain):
    domain = domain.strip()

    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain

    parsed = urlparse(domain)

    if not parsed.hostname:
        raise ValueError("Invalid target domain")

    if parsed.username or parsed.password:
        raise ValueError("Credentials in URL are not allowed")

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS are supported")

    return f"{parsed.scheme}://{parsed.netloc}"


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_path(base_url, path):
    target = base_url + "/" + path

    request = urllib.request.Request(
        target,
        headers={
            "User-Agent": "AI-ReconX/1.0"
        },
        method="GET"
    )

    opener = urllib.request.build_opener(NoRedirectHandler())

    try:
        with opener.open(request, timeout=5) as response:
            return {
                "path": "/" + path,
                "status": response.status,
                "size": response.headers.get(
                    "Content-Length", "Unknown"
                ),
                "redirect": "-"
            }

    except urllib.error.HTTPError as error:
        location = error.headers.get("Location", "-")

        return {
            "path": "/" + path,
            "status": error.code,
            "size": error.headers.get(
                "Content-Length", "Unknown"
            ),
            "redirect": location if error.code in (
                301, 302, 303, 307, 308
            ) else "-"
        }

    except Exception:
        return None


def directory_file_discovery(domain):
    console.print(
        Panel(
            "[bold cyan]Directory & File Discovery Module[/bold cyan]\n"
            "[bold yellow]Authorized testing only[/bold yellow]",
            border_style="yellow"
        )
    )

    try:
        base_url = normalize_url(domain)
    except ValueError as error:
        console.print(f"[bold red][!] {error}[/bold red]")
        return

    console.print(
        f"\n[bold cyan][+] Target: {base_url}[/bold cyan]"
    )

    console.print(
        "\n[bold yellow][*] Starting Directory & File Discovery...[/bold yellow]"
    )

    paths = DIRECTORIES + FILES
    results = []

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(check_path, base_url, path): path
            for path in paths
        }

        for future in as_completed(futures):
            result = future.result()

            if result and result["status"] != 404:
                results.append(result)

    table = Table(
        title="[bold cyan]Directory & File Discovery Results[/bold cyan]"
    )

    table.add_column("Path", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Size", justify="right")
    table.add_column("Redirect", style="yellow")

    for item in sorted(results, key=lambda x: x["path"]):
        status = item["status"]

        if status == 200:
            color = "green"
        elif status in (301, 302, 303, 307, 308):
            color = "yellow"
        elif status in (401, 403):
            color = "red"
        else:
            color = "white"

        table.add_row(
            item["path"],
            f"[{color}]{status}[/{color}]",
            str(item["size"]),
            str(item["redirect"])
        )

    console.print(table)

    console.print(
        f"\n[bold green][+] Directory & File Discovery Completed. "
        f"Responses Found: {len(results)}[/bold green]"
    )


if __name__ == "__main__":
    console.print(
        "[bold yellow]Run this module through reconx.py "
        "with an authorized target.[/bold yellow]"
    )
