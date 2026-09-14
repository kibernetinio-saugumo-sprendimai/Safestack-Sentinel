# Contributing

Use a focused branch and include tests for behavior changes. Before opening a
pull request, run:

```bash
python -m unittest discover -v
python -m compileall -q sentinel tests
```

Explain platform assumptions and any new data collected by a check. Do not
commit credentials, private keys, host reports, generated baselines, virtual
environments, or database files.
