import pickle
import yaml


def load(blob, text):
    # ruleid: python-unsafe-deserialization
    obj = pickle.loads(blob)
    # ruleid: python-unsafe-deserialization
    cfg = yaml.load(text)
    # ruleid: python-unsafe-deserialization
    cfg2 = yaml.load(text, Loader=yaml.Loader)
    return obj, cfg, cfg2
