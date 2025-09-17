#
# |---------------------------------------------------------|
# |                                                         |
# |                 Give Feedback / Get Help                |
# | https://github.com/Pebbling-ai/pebble/issues/new/choose |
# |                                                         |
# |---------------------------------------------------------|
#
#  Thank you users! We ❤️ you! - 🐧

"""Display utilities for the Pebbling server."""

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


def prepare_server_display() -> str:
    """Prepare the colorful ASCII display for the server.

    Returns:
        A string containing a formatted ASCII art display for the server
    """
    try:
        console = Console(record=True)

        # Create Pebbling ASCII art with penguin
        pebbling_art = """
#################################################################
#                                                               #
#                                                               #
#                          ⣀⣠⣤⣤⣤⣤⣤⣤⣀⡀                         #
#                      ⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡀                         #
#                   ⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀                       #
#                  ⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄                        #
#                 ⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀                      #
#                ⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇                      #
#                ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿      #
#                ⢸⡟⠁⠀⠙⢿⣿⣿⣿⡿⠋⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⡇     #
#                ⢹⡀⠀⠀⠀⠈⣿⣿⣿⠁⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⡇                     #
#                ⢨⠁⢠⣾⣶⣦⠀⢸⣿⣿⢠⣾⣿⣶⡀⠀⠀⣿⣿⣿⣿⣿⣿⡇                     #
#                ⢸⠀⢸⣿⣿⣿⠤⠘⠀⠘⠼⣿⣿⣿⡇⠀⢀⣿⣿⣿⣿⣿⣿⣿                     #
#                ⢸⣧⡀⢹⠟⠁⠀⠀⠀⠀⠈⠙⢟⣁⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿                     #
#               ⢀⡟⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠻⣿⣿⣿⣿⣿⣿⡄                     #
#               ⢸⡆⠣⡀⠀⠀⠀⠀⠀⠀⢀⣀⡤⠖⠀⠀⣠⣿⣿⣿⣿⣿⣿⣧                       #
#              ⣼⣿⣦⡘⠢⠤⠤⠤⠤⠤⠒⠉⠁⠀⢀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣇                      #
#             ⣼⣿⣿⠟⠉⠢⣄⣢⠐⣄⠠⣄⢢⣼⠞⠉⠀⠈⠻⢿⣿⣿⣿⣿⣿⣿⣿⣆                     #
#            ⢀⣼⣿⣿⡟⠀⠀⠀⠉⠙⠚⠓⠊⠉⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣆                    #
#           ⢠⣾⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧                   #
#          ⣰⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀                 #
#         ⣴⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀                #
#        ⣰⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷                #
#             ____       _     _     _ _                         #
#             |  _ \ ___ | |__ | |__ | (_)_ __   __ _             #
#             | |_) / _ \| '_ \| '_ \| | | '_ \ / _` |            #
#             |  __/  __/| |_) | |_) | | | | | | (_| |            #
#             |_|   \___||_.__/|_.__/|_|_|_| |_|\__, |            #
#                                   |___/                            #
#####################################################################"""

        version_info = Text("v0.1.0", style="bold bright_yellow")

        # Create colorful display with the pebbling art
        display_content = (
            Text(pebbling_art, style="bold bright_cyan")
            + "\n\n"
            + Text("Pebbling ", style="bold bright_magenta")
            + version_info
            + "\n"
            + Text("🐧 A Protocol Framework for Agent to Agent Communication", style="bold bright_green italic")
        )

        display_panel = Panel.fit(
            display_content,
            title="[bold rainbow]🐧 Pebbling Protocol Framework[/bold rainbow]",
            border_style="bright_blue",
            box=box.DOUBLE,
        )

        console.print(display_panel)
        return console.export_text()
    except ImportError:
        return """
#####################################################################
#  ____       _     _     _ _                                        #
# |  _ \ ___ | |__ | |__ | (_)_ __   __ _                            #
# | |_) / _ \| '_ \| '_ \| | | '_ \ / _` |                           #
# |  __/  __/| |_) | |_) | | | | | | (_| |                           #
# |_|   \___||_.__/|_.__/|_|_|_| |_|\__, |                           #
#                                   |___/                            #
#                                                                    #
#                          ⣀⣠⣤⣤⣤⣤⣤⣤⣀⡀                                #
#                      ⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡀                           #
#                   ⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀                        #
#                  ⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄                       #
#                 ⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀                      #
#                ⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇                      #
#                ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿                      #
#                ⢸⡟⠁⠀⠙⢿⣿⣿⣿⡿⠋⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⡇                     #
#                ⢹⡀⠀⠀⠀⠈⣿⣿⣿⠁⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⡇                     #
#                ⢨⠁⢠⣾⣶⣦⠀⢸⣿⣿⢠⣾⣿⣶⡀⠀⠀⣿⣿⣿⣿⣿⣿⡇                     #
#                ⢸⠀⢸⣿⣿⣿⠤⠘⠀⠘⠼⣿⣿⣿⡇⠀⢀⣿⣿⣿⣿⣿⣿⣿                     #
#                ⢸⣧⡀⢹⠟⠁⠀⠀⠀⠀⠈⠙⢟⣁⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿                     #
#               ⢀⡟⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠻⣿⣿⣿⣿⣿⣿⡄                     #
#               ⢸⡆⠣⡀⠀⠀⠀⠀⠀⠀⢀⣀⡤⠖⠀⠀⣠⣿⣿⣿⣿⣿⣿⣧                     #
#              ⣼⣿⣦⡘⠢⠤⠤⠤⠤⠤⠒⠉⠁⠀⢀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣇                    #
#             ⣼⣿⣿⠟⠉⠢⣄⣢⠐⣄⠠⣄⢢⣼⠞⠉⠀⠈⠻⢿⣿⣿⣿⣿⣿⣿⣿⣆                   #
#            ⢀⣼⣿⣿⡟⠀⠀⠀⠉⠙⠚⠓⠊⠉⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣆                  #
#           ⢠⣾⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧                 #
#          ⣰⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀               #
#         ⣴⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀              #
#        ⣰⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷             #
#####################################################################

🐧 Pebbling Protocol Framework v0.1.0
Pebbling - A Protocol Framework for Agent to Agent Communication"""
