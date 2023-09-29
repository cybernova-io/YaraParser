import plyara
import plyara.utils
import yara
import re
import pprint

class YaraRule:

    def __init__(self, name: str, imports: list, tags: list, meta: str, meta_kvp: dict, strings: str, conditions: str, raw_text: str, logic_hash: str):
        self.name : str = name
        self.imports : list = imports
        self.tags : list = tags
        self.meta : str = meta
        self.meta_kvp : dict = meta_kvp
        self.strings : str = strings
        self.conditions : str = conditions
        self.raw_text : str = raw_text
        self.logic_hash : str = logic_hash
        #self.compiles = bool
        #self.compiles_error_msg = str

class Parser:

    parser = plyara.Plyara(meta_as_kv=True, console_logging=False)
    parsed_rules = {}
    finished_rules = list()

    def __init__(self, yara_text, strip_whitespace=False):
        self.parser.clear()
        self.parsed_rules = self.parser.parse_string(yara_text)
        self.strip_whitespace = strip_whitespace

    def parse_rules(self):
        if self.strip_whitespace == False:

            for i in self.parsed_rules:                
                rule = YaraRule(
                    name = i.get("rule_name"),
                    imports = plyara.utils.detect_imports(i),
                    tags = i.get("tags"),
                    meta = i.get("raw_meta"),
                    meta_kvp = i.get("metadata"),
                    strings = i.get("raw_strings"),
                    conditions = i.get("raw_condition"),
                    raw_text = plyara.utils.rebuild_yara_rule(i),
                    logic_hash = plyara.utils.generate_hash(i)
                )
                self.finished_rules.append(rule)

            return self.finished_rules
                
                