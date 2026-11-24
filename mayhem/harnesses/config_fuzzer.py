#!/usr/bin/env python3
"""acme_srv config parsing: format detection, INI parsing and the YAML loader with its
duplicate-key check (_parse_config_content), then the option loaders that turn the parsed config
into EAB profiles, allowed-domain lists, header-info and cert-chain settings. configparser.Error and
yaml.YAMLError on malformed text are the documented parse failures."""
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import configparser
import logging

import yaml

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    from acme2certifier.acme_srv.helpers import config as cfg

LOG = logging.getLogger("fuzz")
LOG.addHandler(logging.NullHandler())
LOG.setLevel(logging.CRITICAL)
LOG.propagate = False
EXPECTED = (configparser.Error, yaml.YAMLError, ValueError)
LOADERS = (
    cfg.config_check,
    cfg.config_profile_load,
    cfg.config_eab_profile_load,
    cfg.config_headerinfo_load,
    cfg.config_allowed_domainlist_load,
    cfg.config_allowed_iplist_load,
    cfg.config_shortname_denylist_load,
    cfg.config_cert_chain_skip_list_load,
    cfg.config_enroll_config_log_load,
)


def TestOneInput(data: bytes) -> None:
    if not data:
        return -1
    path = "acme_srv.yaml" if data[0] & 1 else "acme_srv.cfg"
    content = data[1:].decode("utf-8", errors="replace")
    try:
        parsed, _ = cfg._parse_config_content(content, path, LOG)  # pylint: disable=protected-access
    except EXPECTED:
        return 0
    for loader in LOADERS:
        loader(LOG, parsed)
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
