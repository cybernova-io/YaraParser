import plyara
import plyara.utils
import yara
import re
import pprint
from typing import Optional


class YaraRule:
    def __init__(
        self,
        name: str,
        imports: list,
        tags: Optional[list],
        meta: str,
        meta_kvp: dict,
        strings: str,
        conditions: str,
        raw_text: str,
        logic_hash: str,
    ):
        self.name: str = name
        self.imports: list = imports
        self.tags: Optional[list] = tags
        self.meta: str = meta
        self.meta_kvp: dict = meta_kvp
        self.strings: str = strings
        self.conditions: str = conditions
        self.raw_text: str = raw_text
        self.logic_hash: str = logic_hash
        self.compiles = bool
        self.compiles_error_msg = str


class YaraParser:
    parser = plyara.Plyara(meta_as_kv=True, console_logging=False)
    parsed_rules = {}
    finished_rules = list()

    def __init__(self, yara_text):
        self.parser.clear()
        self.parsed_rules = self.parser.parse_string(yara_text)
        
    def parse_rules(self):
        for i in self.parsed_rules:
            i["imports"] = plyara.utils.detect_imports(i)
            rule = YaraRule(
                name=i.get("rule_name"),
                imports=i.get("imports"),
                tags=i.get("tags"),
                meta=i.get("raw_meta"),
                meta_kvp=i.get("metadata"),
                strings=i.get("raw_strings"),
                conditions=i.get("raw_condition"),
                raw_text=plyara.utils.rebuild_yara_rule(i),
                logic_hash=plyara.utils.generate_hash(i),
            )
            compile_result = self.get_compile_status(rule.raw_text)
            rule.compiles = compile_result[0]
            rule.compiles_error_msg = compile_result[1]
            self.finished_rules.append(rule)

        return self.finished_rules
    
    def get_compile_status(self, rule):
        """Attempts to compile provided rule. Returns True if rule compiles, returns False and provides error msg if the rule does not compile."""
        try:
            result = yara.compile(source=rule)
            return [True, None]
        except yara.SyntaxError as e:
            return [False, e]
