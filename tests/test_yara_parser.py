import pytest
from YaraParser import YaraParser
from YaraParser.YaraParser import YaraRule
import re

# https://github.com/Yara-Rules/rules/blob/master/webshells/WShell_ChinaChopper.yar
# /*
#    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
# */

rule_text = """
rule webshell_ChinaChopper_aspx
{
  meta:
    author      = "Ryan Boyle randomrhythm@rhythmengineering.com"
    date        = "2020/10/28"
    description = "Detect China Chopper ASPX webshell"
    reference1  = "https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html"
    filetype    = "aspx"
  strings:
	$ChinaChopperASPX = {25 40 20 50 61 67 65 20 4C 61 6E 67 75 61 67 65 3D ?? 4A 73 63 72 69 70 74 ?? 25 3E 3C 25 65 76 61 6C 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-100] 75 6E 73 61 66 65}
  condition:
	$ChinaChopperASPX
}
"""


test_rule = """
rule webshell_ChinaChopper_aspx
{
  meta:
    author      = "Ryan Boyle randomrhythm@rhythmengineering.com"
    date        = "2020/10/28"
    description = "Detect China Chopper ASPX webshell"
    reference1  = "https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html"
    filetype    = "aspx"
  strings:
	$ChinaChopperASPX = {25 40 20 50 61 67 65 20 4C 61 6E 67 75 61 67 65 3D ?? 4A 73 63 72 69 70 74 ?? 25 3E 3C 25 65 76 61 6C 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-100] 75 6E 73 61 66 65}
  condition:
	$ChinaChopperASPX
}

import "hash" 

rule CrossRAT: RAT
{
    meta:
        description = "Detects CrossRAT known hash"
        author = "Simon Sigre (simon.sigre@gmail.com)"
        date = "26/01/2018"
        ref = "https://simonsigre.com"
        ref= "https://objective-see.com/blog/blog_0x28.html"
    strings:
        $magic = { 50 4b 03 04 ( 14 | 0a ) 00 }
        $string_1 = "META-INF/"
        $string_2 = ".class" nocase

    condition:
        filesize < 400KB and
        $magic at 0 and 1 of ($string_*) and
        hash.md5(0, filesize) == "85b794e080d83a91e904b97769e1e770"
}
"""


@pytest.fixture()
def parsed_rule():
    parser = YaraParser(test_rule)
    rules = parser.parse_rules()
    rule = rules[0]

    return rule

@pytest.fixture()
def second_rule():
    parser = YaraParser(test_rule)
    rules = parser.parse_rules()
    rule = rules[1]

    return rule

def test_rule_name(parsed_rule):
    assert parsed_rule.name == "webshell_ChinaChopper_aspx"


def test_rule_imports(parsed_rule):
    assert parsed_rule.imports == []


def test_rule_tags(parsed_rule):
    assert parsed_rule.tags == None


def test_rule_meta(parsed_rule):

    meta = """meta:
    author      = "Ryan Boyle randomrhythm@rhythmengineering.com"
    date        = "2020/10/28"
    description = "Detect China Chopper ASPX webshell"
    reference1  = "https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html"
    filetype    = "aspx"
    """
    assert parsed_rule.meta.strip() == meta.strip()

def test_rule_meta_kvp(parsed_rule):
    meta_kvp = [{'author': 'Ryan Boyle randomrhythm@rhythmengineering.com'}, {'date': '2020/10/28'}, {'description': 'Detect China Chopper ASPX webshell'}, {'reference1': 'https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html'}, {'filetype': 'aspx'}]
    assert parsed_rule.meta_kvp == meta_kvp

def test_rule_strings(parsed_rule):
    strings = """strings:
	$ChinaChopperASPX = {25 40 20 50 61 67 65 20 4C 61 6E 67 75 61 67 65 3D ?? 4A 73 63 72 69 70 74 ?? 25 3E 3C 25 65 76 61 6C 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-100] 75 6E 73 61 66 65}"""
    assert parsed_rule.strings.strip() == strings.strip()

def test_rule_conditions(parsed_rule):
    condition = """condition:
	$ChinaChopperASPX"""
    assert parsed_rule.conditions.strip() == condition.strip()

def test_rule_raw_text(parsed_rule):
    
    assert re.sub("\\s", "", parsed_rule.raw_text) == re.sub("\\s", "", rule_text)

def test_compilation(parsed_rule):
    assert parsed_rule.compiles == True
    
def test_rule_two_tags(second_rule):
    assert second_rule.tags == ["RAT"]

def test_rule_two_imports(second_rule):
    assert second_rule.imports == ["hash"]