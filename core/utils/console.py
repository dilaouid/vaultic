from rich.console import Console

console = Console(force_terminal=True, color_system="truecolor", stderr=True)

def info(msg): console.print(f"ℹ️  {msg}", style="blue")
def success(msg): console.print(f"✅ {msg}", style="green")
def error(msg): console.print(f"❌ {msg}", style="red")
def debug(msg): console.print(f"🔍 {msg}", style="dim")