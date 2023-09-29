import plyara
import plyara.utils
import yara
import re

class SingleParser:

    parser = plyara.Plyara(meta_as_kv=True)

    parsed_rule = {}
    raw_text = ""
    logic_hash = ""
    compiles = ""
    strip_whitespace = False

    def __init__(self, yara_text, strip_whitespace=False):
        self.parser.clear()
        self.parsed_rule = self.parser.parse_string(yara_text)
        self.rule_text = plyara.utils.rebuild_yara_rule(self.parsed_rule[0])
        self.strip_whitespace = strip_whitespace

    def get_rule_dict(self):
        """Returns a dictionary with all relevant data from rule."""
        if self.strip_whitespace == False:
            data = {}
            data["rule_name"] = self.parsed_rule[0]["rule_name"]
            self.parsed_rule[0]['imports'] = plyara.utils.detect_imports(self.parsed_rule[0])
            data["imports"] = self.parsed_rule[0]['imports']
            data['tags'] = self.parsed_rule[0].get('tags')

            try:
                data["rule_meta"] = re.sub(r"\s", "", self.parsed_rule[0]["raw_meta"])
                data["rule_meta_kvp"] = self.parsed_rule[0]["metadata"]
            except:
                data["rule_meta"] = None
                data["rule_meta_kvp"] = None
            try:
                data["rule_strings"] = re.sub(r"\s", "", self.parsed_rule[0]["raw_strings"])
            except:
                data["rule_strings"] = None
            
            data["rule_conditions"] = re.sub(r"\s", "", self.parsed_rule[0]["raw_condition"])
            
            data['raw_text'] = plyara.utils.rebuild_yara_rule(self.parsed_rule[0])
            data["rule_logic_hash"] = plyara.utils.generate_hash(self.parsed_rule[0])
            data["compiles"] = self.get_compile_status(data["raw_text"])

            return data
        if self.strip_whitespace == True:
            data = {}
            data["rule_name"] = self.parsed_rule[0]["rule_name"]
            self.parsed_rule[0]['imports'] = plyara.utils.detect_imports(self.parsed_rule[0])
            data["imports"] = self.parsed_rule[0]['imports']
            data['tags'] = self.parsed_rule[0].get('tags')

            try:
                data["rule_meta"] = re.sub(r"\s", "", self.parsed_rule[0]["raw_meta"])
                data["rule_meta_kvp"] = self.parsed_rule[0]["metadata"]
            except:
                data["rule_meta"] = None
                data["rule_meta_kvp"] = None
            try:
                data["rule_strings"] = re.sub(r"\s", "", self.parsed_rule[0]["raw_strings"])
            except:
                data["rule_strings"] = None
            
            data["rule_conditions"] = re.sub(r"\s", "", self.parsed_rule[0]["raw_condition"])
            
            data['raw_text'] = plyara.utils.rebuild_yara_rule(self.parsed_rule[0])
            data["rule_logic_hash"] = plyara.utils.generate_hash(self.parsed_rule[0])
            data["compiles"] = self.get_compile_status(data["raw_text"])

            return data

    def get_rule_name(self):
        """Return rule name."""
        return self.parsed_rule[0]["rule_name"]

    def get_rule_meta(self):
        """Return rule meta description."""
        return self.parsed_rule[0]["raw_meta"]

    def get_rule_strings(self):
        """Return rule raw strings."""
        return self.parsed_rule[0]["raw_strings"]

    def get_rule_conditions(self):
        """Return rule conditions."""
        return self.parsed_rule[0]["raw_condition"]

    def get_rule_strings_kvp(self):
        """Return rule strings as kvp."""
        return self.parsed_rule[0]["strings"]

    def get_logic_hash(self):
        """Return SHA-256 hash of rule strings and conditions."""
        if self.logic_hash == "":
            self.logic_hash = plyara.utils.generate_hash(self.parsed_rule[0])
            return self.logic_hash
        return self.logic_hash

    def get_compile_status(self, rule_text):
        """Attempts to compile provided rule. Returns True if rule compiles, returns False with the error message if the rule does not compile."""
        if self.compiles == "":
            try:
                result = yara.compile(source=rule_text)
                self.compiles = "True"
                return self.compiles
            except yara.SyntaxError as e:
                self.compiles = "False " + str(e)
                return self.compiles.strip()

    def get_meta_field(self, keyword: str):
        for meta_kvp in self.parsed_rule[0]["metadata"]:
            value = meta_kvp.get(keyword)
            if value is not None:
                return value
        return None
