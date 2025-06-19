"""
Example Plugin for SarahToolkit
"""

class ExamplePlugin:
    def __init__(self, config=None):
        self.config = config or {}

    def run(self, *args, **kwargs):
        print("[ExamplePlugin] Plugin executed with args:", args, "and kwargs:", kwargs)
        # Add your plugin logic here
        return "Plugin executed successfully"

def register():
    return ExamplePlugin
