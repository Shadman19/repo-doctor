def classify(prompt: str) -> dict:
    p = prompt.lower()
    plan = {"intent": "scan", "params": {}}
    if "gpl" in p:
        plan["params"]["block_gpl"] = True
    return plan
