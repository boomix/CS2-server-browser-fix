# Contributing

Bug reports, fake-server examples and pull requests are welcome.

- **A fake server slipped through?** Open an issue with the server address, what Steam showed, and (if you can) what A2S_PLAYER returns for it. The Activity log (*Advanced → Activity*) helps.
- **Code changes:** run `pip install -r requirements.txt` and `python src/a2s_filter.py --selftest` before opening a pull request. Add a test case to `selftest()` for any new rule. Keep rules conservative: hiding a real server is worse than showing a fake one.
- The app needs Administrator rights, so test the GUI from an elevated terminal: `python src/a2s_gui.py`.
