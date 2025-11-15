#!/usr/bin/env python3

import tarfile
import gzip
import xml.etree.ElementTree as ET
import csv
import sys
import os
from pathlib import Path

def extract_tar_gz(tar_path, extract_path="./pan_config"):
    """Extract gzipped tar ball to a directory"""
    try:
        with tarfile.open(tar_path, 'r:gz') as tar:
            tar.extractall(path=extract_path)
        print(f"[+] Extracted to {extract_path}")
        return extract_path
    except Exception as e:
        print(f"[-] Error extracting tar: {e}")
        sys.exit(1)

def is_valid_xml_file(filepath):
    """Check if file is a valid XML file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content or not content.startswith('<'):
                return False
        return True
    except:
        return False

def find_xml_files(root_path):
    """Find all valid XML files in extracted directory"""
    xml_files = []
    for root, dirs, files in os.walk(root_path):
        for file in files:
            if file.endswith('.xml'):
                filepath = os.path.join(root, file)
                if is_valid_xml_file(filepath):
                    xml_files.append(filepath)
                else:
                    print(f"[*] Skipping invalid XML file: {filepath}")
    return xml_files

def parse_firewall_rules(xml_files):
    """Extract firewall rules from PAN OS XML config files"""
    rules = []
    
    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Look for security rules in multiple possible locations
            # Standard location: config/devices/entry/vsys/entry/rulebase/security/rules/entry
            for rules_elem in root.findall('.//rulebase/security/rules'):
                for rule_entry in rules_elem.findall('entry'):
                    rule = parse_rule_entry(rule_entry)
                    if rule:
                        rules.append(rule)
            
            # Pre-rules
            for rules_elem in root.findall('.//rulebase/pre-rulebase/security/rules'):
                for rule_entry in rules_elem.findall('entry'):
                    rule = parse_rule_entry(rule_entry)
                    if rule:
                        rules.append(rule)
            
            # Post-rules
            for rules_elem in root.findall('.//rulebase/post-rulebase/security/rules'):
                for rule_entry in rules_elem.findall('entry'):
                    rule = parse_rule_entry(rule_entry)
                    if rule:
                        rules.append(rule)
            
            # sp/vsys1 structure (SP device style)
            for rules_elem in root.findall('.//sp/vsys/entry/rulebase/security/rules'):
                for rule_entry in rules_elem.findall('entry'):
                    rule = parse_rule_entry(rule_entry)
                    if rule:
                        rules.append(rule)
            
            # Also try generic vsys path
            for rules_elem in root.findall('.//vsys/entry/rulebase/security/rules'):
                for rule_entry in rules_elem.findall('entry'):
                    rule = parse_rule_entry(rule_entry)
                    if rule:
                        rules.append(rule)
            
            # Panorama pre-rulebase and post-rulebase (SP config style)
            for rules_elem in root.findall('.//panorama/pre-rulebase/security/rules'):
                for rule_entry in rules_elem.findall('entry'):
                    rule = parse_rule_entry(rule_entry)
                    if rule:
                        rules.append(rule)
            
            for rules_elem in root.findall('.//panorama/post-rulebase/security/rules'):
                for rule_entry in rules_elem.findall('entry'):
                    rule = parse_rule_entry(rule_entry)
                    if rule:
                        rules.append(rule)
                        
        except ET.ParseError as e:
            print(f"[!] Could not parse {xml_file}: {e}")
        except Exception as e:
            print(f"[!] Error processing {xml_file}: {e}")
    
    return rules

def parse_rule_entry(rule_elem):
    """Parse individual security rule entry"""
    rule_data = {}
    
    # Get rule name
    rule_data['Name'] = rule_elem.get('name', 'N/A')
    
    # Extract common rule fields
    rule_data['Description'] = get_element_text(rule_elem, 'description', 'N/A')
    rule_data['Action'] = get_element_text(rule_elem, 'action', 'N/A')
    rule_data['Disabled'] = get_element_text(rule_elem, 'disabled', 'no')
    rule_data['Log at Session Start'] = get_element_text(rule_elem, 'log-start', 'N/A')
    rule_data['Log at Session End'] = get_element_text(rule_elem, 'log-end', 'N/A')
    
    # Source/Destination
    rule_data['From Zone'] = parse_list_field(rule_elem, 'from/member')
    rule_data['To Zone'] = parse_list_field(rule_elem, 'to/member')
    rule_data['Source Address'] = parse_list_field(rule_elem, 'source/member')
    rule_data['Destination Address'] = parse_list_field(rule_elem, 'destination/member')
    rule_data['Source User'] = parse_list_field(rule_elem, 'source-user/member')
    
    # Services
    rule_data['Service'] = parse_list_field(rule_elem, 'service/member')
    
    # Application
    rule_data['Application'] = parse_list_field(rule_elem, 'application/member')
    
    # Category
    rule_data['Category'] = parse_list_field(rule_elem, 'category/member')
    
    return rule_data

def get_element_text(elem, path, default='N/A'):
    """Safely get text from nested element"""
    try:
        sub_elem = elem.find(path)
        if sub_elem is not None and sub_elem.text:
            return sub_elem.text
    except:
        pass
    return default

def parse_list_field(elem, path):
    """Parse repeating list fields (like members)"""
    try:
        items = []
        for member in elem.findall(path):
            if member.text:
                items.append(member.text)
        return '; '.join(items) if items else 'N/A'
    except:
        return 'N/A'

def export_to_csv(rules, output_file='firewall_rules.csv'):
    """Export rules to CSV file"""
    if not rules:
        print("[-] No rules found to export")
        return
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Name', 'Description', 'Action', 'Disabled',
                'From Zone', 'To Zone', 'Source Address', 'Destination Address',
                'Source User', 'Service', 'Application', 'Category',
                'Log at Session Start', 'Log at Session End'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rules)
        
        print(f"[+] Exported {len(rules)} rules to {output_file}")
    except Exception as e:
        print(f"[-] Error writing CSV: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 pan_config_parser.py <backup.tar.gz> [output.csv] [--verbose]")
        sys.exit(1)
    
    tar_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'firewall_rules.csv'
    verbose = '--verbose' in sys.argv
    
    if not os.path.exists(tar_path):
        print(f"[-] File not found: {tar_path}")
        sys.exit(1)
    
    print(f"[*] Processing {tar_path}")
    
    # Extract tar.gz
    extract_path = extract_tar_gz(tar_path)
    
    # Find XML files
    print("[*] Finding XML configuration files...")
    xml_files = find_xml_files(extract_path)
    print(f"[+] Found {len(xml_files)} XML files")
    if verbose:
        for f in xml_files:
            print(f"    - {f}")
    
    # Parse rules
    print("[*] Parsing firewall rules...")
    rules = parse_firewall_rules(xml_files)
    print(f"[+] Found {len(rules)} firewall rules")
    
    if len(rules) == 0 and verbose:
        print("[*] No rules found. Checking sp-config.xml structure...")
        for xml_file in xml_files:
            if 'sp-config' in xml_file:
                print(f"\n[*] Analyzing {xml_file}:")
                try:
                    tree = ET.parse(xml_file)
                    root = tree.getroot()
                    print(f"    Root tag: {root.tag}")
                    # Print first few levels of structure
                    for child in root:
                        print(f"    - {child.tag}")
                        for subchild in child:
                            print(f"      - {subchild.tag}")
                except Exception as e:
                    print(f"    Error: {e}")
    
    # Export to CSV
    export_to_csv(rules, output_file)
    
    print("[+] Done!")

if __name__ == "__main__":
    main()
