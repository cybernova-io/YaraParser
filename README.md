# Intro

Package I am working on to be used in parsing Yara rules into their individual components. 
Package may also contain utilities or extra features I develop for working with Yara rules over time.

# Usage
```python
pip install YaraParser
```

```python
from YaraParser import YaraParser

test = """
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Big_Numbers0
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 20:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}
"""

parser = YaraParser(test)

rules = parser.parse_rules()

print(rules[0].__dict__)
```

```
{'name': 'Big_Numbers0', 'imports': [], 'tags': None, 'meta': 'meta:\n\t\tauthor = "_pusher_"\n\t\tdescription = "Looks for big numbers 20:sized"\n\t\tdate = "2016-07"\n\t', 'meta_kvp': [{'author': '_pusher_'}, {'description': 'Looks for big numbers 20:sized'}, {'date': '2016-07'}], 'strings': 'strings:\n\t\t$c0 = /[0-9a-fA-F]{20}/ fullword ascii\n\t', 'conditions': 'condition:\n\t\t$c0\n', 'raw_text': 'rule Big_Numbers0\n{\n\tmeta:\n\t\tauthor = "_pusher_"\n\t\tdescription = "Looks for big numbers 20:sized"\n\t\tdate = "2016-07"\n\n\tstrings:\n\t\t$c0 = /[0-9a-fA-F]{20}/ fullword ascii\n\n\tcondition:\n\t\t$c0\n}\n', 'logic_hash': 'cc15c2fe1e9d195ce446c522991f04a9dee858e9752b385473d82c85b5826051', 'compiles': True, 'compiles_error_msg': None}
```

## Quick breakdown
YaraParser class returns a list of YaraRule objects corresponding to the Yara rule input string.
These objects contain the following attributes:
- Name
- Imports
- Tags
- Meta
- Meta_kvp
- Strings
- Conditions
- Raw Text
- Logic Hash (Hash of strings and conditions, can be used to prevent duplicate rules)
- Compiles
- Compile Error Msg


