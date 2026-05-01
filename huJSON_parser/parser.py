"""
huJSON Parser for Headscale ACL files.
Strips // line comments and /* block comments */  then deserialises into 'HeadscalePolicy' dataclass
Warns user if required src and dst formats are not present in ACL and removes such src/dst in rules. (Mostly include infrastructure rules)
Assumption: Parser getting valid huJSON file as input
"""

import json
import re
import ipaddress
from models.policy import ACLRule, HeadscalePolicy
from acl_generator.generator import ACLGenerator
from synthetic_data.generator import generate_synthetic_db
from static_policy_checker.policy_checker import StaticPolicyChecker

class huJSON_Parser:
    def __init__(self, file_path: str):
        self.file_path = file_path
    
    def _strip_comments(self, text:str) -> str:
        result_text = []
        idx = 0
        in_string = False

        while(idx < len(text)):
            ch = text[idx]

            # Parsing within string
            if in_string:
                if ch == '"':
                    in_string = False       # mark as end of string
                    result_text.append(ch)
                    idx += 1
                else:
                    result_text.append(ch)
                    idx += 1
            else:   # Handling comments
                if ch == '"':
                    in_string = True
                    result_text.append(ch)
                    idx += 1
                elif text[idx:idx+2] == "//":   # line comments: skip to end of the line
                    while(idx < len(text) and text[idx] != '\n'):
                        idx += 1
                elif text[idx:idx+2] == "/*":   # block comments: skip entire block till the string "*/"
                    idx += 2    #skip /*
                    while(idx < len(text) and text[idx:idx+2] != "*/"):
                        idx += 1
                    idx += 2    #skip */
                else:
                    result_text.append(ch)
                    idx += 1

        return ''.join(result_text)
    
    def _remove_trailing_commas(self, text:str) -> str:
        return re.sub(r',\s*([}\]])', r'\1', text)
    
    def _parse_hujson_text(self, text:str) -> str:
        stripped_comments_text = self._strip_comments(text)
        # print(stripped_comments_text)
        # print("---------------------------")
        clean_text = self._remove_trailing_commas(stripped_comments_text)
        # print(clean_text)
        return clean_text
    
    def _is_valid_src(self, entry: str) -> bool:
        # Valid src: 'username@' format only.
        if entry.endswith("@") and entry != "@":
            return True
        return False
    
    def _is_valid_dst(self, entry: str) -> bool:
        # Valid dst: 'cidr:port', 'cidr:*', bare 'cidr' format only
        try:
            addr = entry.rsplit(":", 1)[0] if ":" in entry else entry
            ipaddress.ip_network(addr, strict=False)
            return True
        except ValueError:
            return False
    
    def _json_to_HeadScalePolicy(self, json_dict: dict) -> HeadscalePolicy:
        tag_owners = json_dict.get("tagOwners", {})
        auto_approvers = json_dict.get("autoApprovers", {})
        hosts = json_dict.get("hosts")
        acls = []

        for i, rule_dict in enumerate(json_dict.get("acls", [])):
            raw_src = rule_dict.get("src", [])
            raw_dst = rule_dict.get("dst", [])

            valid_src = [src for src in raw_src if self._is_valid_src(src)]
            valid_dst = [dst for dst in raw_dst if self._is_valid_dst(dst)]

            invalid_src = [src for src in raw_src if not self._is_valid_src(src)]
            invalid_dst = [dst for dst in raw_dst if not self._is_valid_dst(dst)]

            if len(invalid_src) > 0:
                print(f"[PARSER WARNING] Rule {i}: unexpected src format skipped: {invalid_src}")
            if len(invalid_dst) > 0:
                print(f"[PARSER WARNING] Rule {i}: unexpected src format skipped: {invalid_dst}")
            
            if not valid_src or not valid_dst:
                print(f"[PARSER WARNING] Rule {i}: skipped entirely - no valid src or dst")
                continue

            acls.append(ACLRule(action=rule_dict.get("action", "accept"), 
                                src=valid_src, 
                                dst=valid_dst, 
                                proto=rule_dict.get("proto")))
        
        return HeadscalePolicy(tag_owners=tag_owners, acls=acls, auto_approvers=auto_approvers, hosts=hosts)
    
    def parse(self) -> HeadscalePolicy:
        with open(self.file_path, "r") as f:
            file_text = f.read()
        
        cleaned_file_text = self._parse_hujson_text(file_text)
        json_dict = json.loads(cleaned_file_text)
        headscalePolicy = self._json_to_HeadScalePolicy(json_dict)
        return headscalePolicy
    
if __name__ == "__main__":
    # acl_filepath = "sample_acl2.txt"
    # parser = huJSON_Parser(acl_filepath)
    # policy = parser.parse()
    # print()
    # # print(policy.to_dict())
    # print(policy.to_hujson())

    db = generate_synthetic_db(num_students=7, num_instructors=2)
    # generator = ACLGenerator(db)
    # policy = generator.generate_and_write("sample_acl_generate.txt")
    # print(policy.to_hujson)

    # Added some random comments to sample acl to verify the parser
    acl_filepath = "sample_acl_generate.txt"
    parser = huJSON_Parser(acl_filepath)
    acl_policy = parser.parse()
    # print(acl_policy.to_dict())
    print(acl_policy.to_hujson())

    static_checker = StaticPolicyChecker(db)
    static_checker_result = static_checker.check(acl_policy)
    static_checker_result.report()