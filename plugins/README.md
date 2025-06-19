# SarahToolkit Plugins

Place your custom plugins in this directory. Each plugin should define a class with a `run` method and a `register()` function that returns the class.

## Example Structure

```
plugins/
  example_plugin.py
  template_plugin.py
  README.md
```

## Example Plugin Usage

- Each plugin should have a `register()` function that returns the plugin class.
- The plugin class should have a `run()` method.

See `example_plugin.py` and `template_plugin.py` for reference.
