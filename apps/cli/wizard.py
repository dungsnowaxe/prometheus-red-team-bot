"""First-run interactive setup wizard for choosing AI provider and credentials."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table

from promptheus.config_store import save_config, config_path_display

PROVIDERS: list[dict[str, str | bool]] = [
    {
        "key": "openai",
        "label": "OpenAI",
        "base_url": "",
        "api_key_required": True,
        "default_model": "gpt-4o-mini",
    },
    {
        "key": "groq",
        "label": "Groq (free tier)",
        "base_url": "https://api.groq.com/openai/v1",
        "api_key_required": True,
        "default_model": "llama-3.1-8b-instant",
    },
    {
        "key": "ollama",
        "label": "Ollama (local, no key needed)",
        "base_url": "http://localhost:11434/v1",
        "api_key_required": False,
        "default_model": "llama3.2",
    },
    {
        "key": "glm",
        "label": "GLM / Zhipu AI",
        "base_url": "https://api.z.ai/api/anthropic",
        "api_key_required": True,
        "default_model": "glm-4-flash",
    },
    {
        "key": "custom",
        "label": "Other (OpenAI-compatible API)",
        "base_url": "",
        "api_key_required": True,
        "default_model": "",
    },
]


def _show_provider_menu(console: Console) -> dict[str, str | bool]:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("No.", style="bold cyan", width=4)
    table.add_column("Provider")
    for i, p in enumerate(PROVIDERS, 1):
        table.add_row(str(i), str(p["label"]))
    console.print(table)

    while True:
        choice = Prompt.ask(
            "\n[bold]Select provider[/bold]",
            default="1",
        )
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(PROVIDERS):
                return PROVIDERS[idx]
        except ValueError:
            pass
        console.print(f"[red]Enter a number between 1 and {len(PROVIDERS)}[/red]")


def run_wizard(console: Console | None = None) -> dict[str, str]:
    """Run interactive setup. Returns the saved config dict."""
    if console is None:
        console = Console()

    console.print(
        Panel(
            "[bold]Welcome to PROMPTHEUS setup![/bold]\n"
            "Configure your AI provider for the Judge LLM.",
            title="PROMPTHEUS",
            border_style="cyan",
        )
    )

    provider = _show_provider_menu(console)
    provider_key = str(provider["key"])
    console.print(f"\n  Selected: [bold cyan]{provider['label']}[/bold cyan]\n")

    base_url = str(provider["base_url"])
    if provider_key == "custom":
        base_url = Prompt.ask("[bold]Base URL[/bold] (e.g. https://api.example.com/v1)")
    elif base_url:
        if Confirm.ask(f"  Base URL: [dim]{base_url}[/dim]  — change it?", default=False):
            base_url = Prompt.ask("[bold]Base URL[/bold]", default=base_url)

    api_key = ""
    if provider["api_key_required"]:
        api_key = Prompt.ask("[bold]API key[/bold]", password=True)
        if not api_key.strip():
            console.print("[yellow]No API key entered. Judge will run in Mock mode until configured.[/yellow]")
            api_key = ""

    default_model = str(provider["default_model"])
    if provider_key == "custom":
        model = Prompt.ask("[bold]Model name[/bold]")
    else:
        model = Prompt.ask("[bold]Model name[/bold]", default=default_model)

    config = {
        "provider": provider_key,
        "api_key": api_key.strip(),
        "base_url": base_url.strip(),
        "model": model.strip(),
    }

    path = save_config(config)
    console.print(f"\n[green]Config saved to {path}[/green]\n")
    return config
