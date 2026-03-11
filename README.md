# HaltChain
Circuit breaker protocol for autonomous AI economies. Prevents goal drift, velocity attacks, and agent conflicts in real-time.

## Status: Experimental
This is the reference implementation. Not production ready.

## Quick Start
```bash
cargo run -p haltchain-api
```

## Running Tests

Run unit tests for the workspace (policy, validator, API stubs):

```bash
cargo test --workspace
```

You can also build all crates:

```bash
cargo build --workspace
```

## Running the Validator API (local)

Start the HTTP server (listens on port 3000):

```bash
cargo run -p haltchain-api
```

Health probe:

```bash
curl http://localhost:3000/health
```

Validate an action (allowed example):

```bash
curl -s -X POST http://localhost:3000/validate \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"trader_bot_01","api_key":"dev-key","action":{"type":"transfer","amount":500,"currency":"USD","recipient":"acct_abc"}}'
```

Validate an action that violates the hard-coded policy (denied):

```bash
curl -s -X POST http://localhost:3000/validate \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"trader_bot_01","api_key":"dev-key","action":{"type":"transfer","amount":1500,"currency":"USD","recipient":"acct_abc"}}'
```

Rate-limit / circuit-breaker behavior (10 actions per minute): send 11 rapid requests to trip the breaker:

```bash
for i in $(seq 1 11); do
  curl -s -X POST http://localhost:3000/validate \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"rater","api_key":"dev","action":{"type":"generic"}}'
  echo
done
```

Check agent status (circuit-breaker + rate usage):

```bash
curl http://localhost:3000/status/rater
```

## Python SDK (quick start)

Install the SDK (dev path):

```bash
pip install ./sdk/python
```

Example usage:

```python
import haltchain

agent = haltchain.Client(agent_id="trader_bot_01", api_key="dev-key")

@agent.validate
def execute_trade(order):
    # This function runs only if HaltChain returns ALLOW
    print("executing", order)

execute_trade({"type": "transfer", "amount": 100, "currency": "USD", "recipient": "acct_x"})
```
