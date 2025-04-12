from rich.console import Console

console = Console(force_terminal=True, color_system="truecolor")

console.print("🔴 RED", style="red")
console.print("🟢 GREEN", style="green")
console.print("🔵 BLUE", style="blue")
console.print("⚪ DIM", style="dim")
