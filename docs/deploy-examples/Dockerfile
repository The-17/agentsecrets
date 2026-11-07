# Phase 1: the Go binary is bundled inside the wheel, so there is no GitHub
# fetch at boot and nothing is written to ~/.agentsecrets at startup.
FROM python:3.12-slim

RUN pip install --no-cache-dir agentsecrets-cli==4.0.0

# Phase 2: cloud mode is ONE decision, set once by the platform. No
# `agentsecrets mode cloud` command, no writable ~/.agentsecrets, no config file
# in the image.
ENV AGENTSECRETS_MODE=cloud

# The workload token is injected by the orchestrator (secret/env), never baked
# into the image. Reference it here without a value:
# ENV AGENTSECRETS_TOKEN=

# `agentsecrets env --` resolves secrets via POST /api/workloads/env/, injects
# them into the child, then execs it. The child never sees the token.
# `python -m agentsecrets` is used instead of the `agentsecrets` console script
# so the command resolves regardless of where pip installed the launcher
# (PATH-independent); the console script form works too when it is on PATH.
ENTRYPOINT ["python", "-m", "agentsecrets", "env", "--"]
CMD ["python", "app.py"]
