import plyara
import plyara.utils
import yara
import re

class MultiParser:

    parser = plyara.Plyara(meta_as_kv=True, console_logging=False)
    parsed_rules = {}
    rules_dict = {}
    rule_name_list = list()
    strip_whitespace = False

    def __init__(self, yara_text, strip_whitespace=False):
        self.parser.clear()
        self.parsed_rules = self.parser.parse_string(yara_text)
        self.strip_whitespace = strip_whitespace

    def get_rules_dict(self, rule_name_as_key=False):
        """
        Returns a dictionary of each rule containing relevant attributes of the rules, in order of rules parsed.

        rule_name_as_key: Optional parameter to use rule name as the dictionary key, integer number (order rules are parsed) is default.
        """
        if len(self.rules_dict) != 0:
            return self.rules_dict

        if self.strip_whitespace == False:
            counter = 1
            holder = {}

            for i in self.parsed_rules:
                data = {}
                i['imports'] = plyara.utils.detect_imports(i)
                data["imports"] = i['imports']
                data['tags'] = i.get('tags')
                data["rule_name"] = i["rule_name"]
                data["rule_meta"] = i["raw_meta"]
                data["rule_meta_kvp"] = i["metadata"]
                data["rule_imports"] = i["imports"]
                data["rule_strings"] = i["raw_strings"]
                data["rule_conditions"] = i["raw_condition"]
                data["rule_logic_hash"] = plyara.utils.generate_hash(i)
                data["raw_text"] = plyara.utils.rebuild_yara_rule(i)
                data["compiles"] = self.get_compile_status(data["raw_text"]).strip()

                if rule_name_as_key == True:
                    holder[data["rule_name"]] = data
                else:
                    holder[counter] = data
                    counter += 1
            self.rules_dict = holder
            return self.rules_dict
        if self.strip_whitespace == True:
            counter = 1
            holder = {}

            for i in self.parsed_rules:
                data = {}
                data["rule_name"] = i["rule_name"]
                i['imports'] = plyara.utils.detect_imports(i)
                data["imports"] = i['imports']
                data['tags'] = i.get('tags')

                try:
                    data["rule_meta"] = re.sub(r"\s", "", i["raw_meta"])
                    data["rule_meta_kvp"] = i["metadata"]
                except:
                    data["rule_meta"] = None
                    data["rule_meta_kvp"] = None
                try:
                    data["rule_strings"] = re.sub(r"\s", "", i["raw_strings"])
                except:
                    data["rule_strings"] = None
                
                data["rule_conditions"] = re.sub(r"\s", "", i["raw_condition"])
                
                data['raw_text'] = plyara.utils.rebuild_yara_rule(i)
                data["rule_logic_hash"] = plyara.utils.generate_hash(i)
                data["compiles"] = self.get_compile_status(data["raw_text"]).strip()

                if rule_name_as_key == True:
                    holder[data["rule_name"]] = data
                else:
                    holder[counter] = data
                    counter += 1
            self.rules_dict = holder
            return self.rules_dict

    def get_rule_name_list(self):
        """Get a list of rule names, in order of rules parsed."""

        if len(self.rule_name_list) != 0:
            return self.rule_name_list

        for i in self.parsed_rules:
            self.rule_name_list.append(i["rule_name"])

        return self.rule_name_list

    def get_compile_status(self, rule):
        """Attempts to compile provided rule. Returns True if rule compiles, returns False with the error message if the rule does not compile."""
        try:
            result = yara.compile(source=rule)
            compiles = "True"
            return compiles
        except yara.SyntaxError as e:
            compiles = "False " + str(e)
            return compiles

    def get_meta_fields(
        self,
        rule_meta_kvp: str,
        meta_keyword_list: list = None,
        meta_keyword: str = None,
    ):
        """Takes parsed rule meta field from a Yara rule, and tries to return the value of a specified meta field if it exists.
        meta_keyword_list: Optional list parameter that can be used to obtain multiple keyword values at once.
        meta_keyword: Optional str parameter that can be used to obtain one keyword value at a time.
        """
        if meta_keyword_list is not None:
            keyword_value_list = list()
            for keyword in meta_keyword_list:
                for meta_kvp in rule_meta_kvp:
                    value = meta_kvp.get(keyword)
                    if value is not None:
                        keyword_value_list.append({keyword: value})
            return keyword_value_list

        elif meta_keyword is not None:
            for meta_kvp in rule_meta_kvp:
                value = meta_kvp.get(meta_keyword)
                if value is not None:
                    return value
            return None
