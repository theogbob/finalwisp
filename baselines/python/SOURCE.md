# wisp-server-python baseline
Source: https://github.com/MercuryWorkshop/wisp-server-python (PyPI wisp-python). Upstream checked 2026-11-16 15:45Z (git ls-remote, GitHub API, npm view, PyPI JSON) for 60.78 G02 (bench/showpair.py).
- `python` = **0.11.0** (deeb390, main = PyPI latest, 2026-11-04). Venv baselines/python-0.11.0 from CPython 3.13.6:
  `pip install websockets==17.4 asyncudp==0.11.0 python-socks==3.2.1 psutil==7.2.2 uvloop==0.23.0 ./ref/wisp-server-python-deeb390`
  (the pins of 60.71). Run: `python -m wisp.server --port=PORT --allow-loopback --allow-private --log-level error`.
- `python-0.9.0` = ae940ec (branch dev), the build of results before 2026-11-15.
