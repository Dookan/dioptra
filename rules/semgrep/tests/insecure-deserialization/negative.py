import json
import yaml


def load(blob, text):
    # ok: python-unsafe-deserialization
    obj = json.loads(blob)
    # ok: python-unsafe-deserialization
    cfg = yaml.safe_load(text)
    return obj, cfg
