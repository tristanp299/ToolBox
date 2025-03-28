#!/usr/bin/env python3
#Author: Tristan Pereira
#Date: 2025-03-28
#Purpose: Parse JSON files and organize the data by various fields.
#Usage: python3 json_parser.py <json_file> [--path <dot_notation_path>] [--pretty] [--compact] [--organize-by <field>] [--organize-all] [--include-lists-dicts] [--output-dir <output_directory>] [--inspect] [--grep]

import json
import argparse
from typing import Any, Dict, List
from pathlib import Path
from datetime import datetime
from collections import Counter

class TrafficClassifier:
    def __init__(self):
        self.model = None  # Could load a pre-trained model
        self.feature_extractors = {
            'packet_size': lambda p: len(p),
            'port_category': lambda p: self.categorize_port(p),
            'protocol_features': lambda p: self.get_protocol_features(p)
        }
    
    def classify_traffic(self, packet):
        features = self.extract_features(packet)
        return self.model.predict([features]) if self.model else None

def load_json(file_path: str) -> Any:
    """
    Load and parse a JSON file.
    If the JSON is a dict with a "result" key, returns the list in "result".
    Otherwise, returns the parsed JSON.
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            if isinstance(data, dict) and 'result' in data:
                print(f"Successfully loaded JSON file with {len(data['result'])} items in result list")
                return data['result']
            elif isinstance(data, list):
                print(f"Successfully loaded JSON file with {len(data)} items")
            else:
                print("Successfully loaded JSON file with 1 object")
            return data
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        exit(1)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        exit(1)

def parse_sys_tags(tags_str: str) -> List[str]:
    """
    Parse the sys_tags string into a list of tags.
    Handles various possible formats.
    """
    if not tags_str:
        return []
    
    # Debug line
    print(f"Debug - Raw sys_tags content: '{tags_str}'")
    
    # Remove any surrounding brackets or quotes
    tags_str = tags_str.strip('[]"')
    
    # Split by common delimiters
    tags = []
    for tag in tags_str.split(','):
        tag = tag.strip()
        if tag:
            tags.append(tag)
    # Debug line
    print(f"Debug - Parsed tags: {tags}")
    return tags

def inspect_json_structure(data: Any, indent: str = "") -> None:
    """
    Recursively inspect and print the structure of JSON data.
    Helps users understand what fields are available.
    """
    if isinstance(data, dict):
        print(f"{indent}Object with fields:")
        for key, value in data.items():
            print(f"{indent}  - {key}: {type(value).__name__}")
            inspect_json_structure(value, indent + "    ")
    elif isinstance(data, list):
        print(f"{indent}List with {len(data)} items")
        if data:
            print(f"{indent}First item structure:")
            inspect_json_structure(data[0], indent + "  ")
    else:
        print(f"{indent}Value of type: {type(data).__name__}")

def find_tag_fields(data: Any) -> List[str]:
    """
    Try to find fields that might contain tags.
    Looks for fields containing lists of strings or sys_tags.
    """
    tag_fields = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key == 'sys_tags' or (isinstance(value, list) and all(isinstance(item, str) for item in value)):
                tag_fields.append(key)
            elif isinstance(value, dict):
                tag_fields.extend(find_tag_fields(value))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                tag_fields.extend(find_tag_fields(item))
    return list(set(tag_fields))  # Remove duplicates

def get_value_by_path(data: Any, path: str) -> Any:
    """
    Get a value from nested JSON using dot notation.
    Example: "users.0.name" will get the name of the first user.
    """
    try:
        for key in path.split('.'):
            if key.isdigit():
                key = int(key)
            data = data[key]
        return data
    except (KeyError, IndexError, TypeError):
        return None

def pretty_print(data: Any, indent: int = 2) -> None:
    """
    Print JSON data in a pretty format.
    """
    if indent:
        print(json.dumps(data, indent=indent))
    else:
        print(json.dumps(data))

def filter_by_tags(data: Any, tags: List[str], tag_field: str = "sys_tags") -> List[Any]:
    """
    Filter JSON data based on tags.
    Returns items that have any of the specified tags.
    """
    items = data if isinstance(data, list) else [data]
    
    filtered = []
    for item in items:
        if tag_field == "sys_tags":
            item_tags = parse_sys_tags(item.get(tag_field, ""))
        else:
            item_tags = item.get(tag_field, [])
        
        if any(tag in item_tags for tag in tags):
            filtered.append(item)
    
    print(f"Found {len(filtered)} items matching tags: {tags}")
    return filtered

def get_field_value(item: Dict[str, Any], field: str) -> Any:
    """
    Get a field value from an item, handling nested fields.
    """
    if '.' in field:
        parts = field.split('.')
        value = item
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part, '')
            else:
                return ''
        return value
    return item.get(field, '')

def organize_by_field(data: Any, field: str) -> Dict[str, List[Any]]:
    """
    Organize data by any field.
    Returns a dictionary where keys are field values and values are lists of items.
    """
    organized = {}
    items = data if isinstance(data, list) else [data]
    
    print(f"Processing {len(items)} items for organization by field: {field}")
    for item in items:
        value = get_field_value(item, field)
        if not value:
            print(f"Warning: Item {item.get('sys_id', 'unknown')} has no value for field '{field}'")
            continue
            
        if value not in organized:
            organized[value] = []
        organized[value].append(item)
            
    print(f"Found {len(organized)} unique values for field '{field}'")
    for val_key, items_for_value in organized.items():
        print(f"  Value '{val_key}': {len(items_for_value)} items")
    return organized

def save_organized_data(data: Dict[str, List[Any]], output_dir: str) -> None:
    """
    Save organized data to separate files by value.
    Creates a timestamped directory for the output.
    """
    if not data:
        print("No data to save - no values found in the input data")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = Path(output_dir) / f"organized_{timestamp}"
    output_path.mkdir(parents=True, exist_ok=True)
    print(f"Creating output directory: {output_path}")

    for value, items_for_value in data.items():
        safe_value = "".join(c for c in str(value) if c.isalnum() or c in (' ', '-', '_')).strip()
        file_path = output_path / f"{safe_value}.json"
        
        with open(file_path, 'w') as f:
            json.dump(items_for_value, f, indent=2)
        print(f"Saved {len(items_for_value)} items with value '{value}' to {file_path}")

def organize_all_fields(data: Any, include_lists_dicts: bool = False) -> Dict[str, Dict[str, List[Any]]]:
    """
    Organize data by all fields, creating separate lists for each unique value.
    Returns a nested dict: { fieldName: { fieldValue: [items...] } }
    
    If include_lists_dicts=False, fields whose values are lists or dicts are skipped.
    """
    organized = {}
    items = data if isinstance(data, list) else [data]
    
    if not items:
        return organized

    first_item = items[0]
    fields = []

    def gather_keys(obj: Any, prefix: str = ""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    gather_keys(v, full_key)
                else:
                    fields.append(full_key)
        else:
            pass

    gather_keys(first_item)

    print(f"Processing {len(items)} items for {len(fields)} fields")

    for field in fields:
        field_organized = {}
        for item in items:
            value = get_field_value(item, field)
            if value is None or value == '':
                continue

            if not include_lists_dicts and (isinstance(value, dict) or isinstance(value, list)):
                continue

            if isinstance(value, (dict, list)):
                value = json.dumps(value, sort_keys=True)

            field_organized.setdefault(value, []).append(item)

        if field_organized:
            organized[field] = field_organized
            print(f"\nField '{field}':")
            print(f"  Found {len(field_organized)} unique values")
            for val, items_group in field_organized.items():
                print(f"    Value '{val}': {len(items_group)} items")

    return organized

def flatten_json(y: Any, prefix: str = '') -> Dict[str, Any]:
    """
    Flatten a nested JSON object into a dictionary with dot-notated key paths.
    Lists are indexed with square brackets.
    """
    out = {}
    if isinstance(y, dict):
        for k, v in y.items():
            new_key = f"{prefix}.{k}" if prefix else k
            out.update(flatten_json(v, new_key))
    elif isinstance(y, list):
        for i, item in enumerate(y):
            new_key = f"{prefix}[{i}]"
            out.update(flatten_json(item, new_key))
    else:
        out[prefix] = y
    return out

def is_empty_value(v: Any) -> bool:
    """
    Return True if v is considered empty.
    Empty means: None, an empty string (after stripping), an empty list, or an empty dict.
    """
    if v is None:
        return True
    if isinstance(v, str) and v.strip() == "":
        return True
    if isinstance(v, (list, dict)) and len(v) == 0:
        return True
    return False

def main():
    parser = argparse.ArgumentParser(description='A flexible JSON parser with CLI support')
    parser.add_argument('file', help='Path to the JSON file')
    parser.add_argument('--path', help='Dot notation path to extract specific value (e.g., "users.0.name")')
    parser.add_argument('--pretty', action='store_true', help='Pretty print the output')
    parser.add_argument('--compact', action='store_true', help='Print without whitespace')
    parser.add_argument('--organize-by', help='Field to organize by (e.g., "u_htm_primary_role" or "user.value")')
    parser.add_argument('--organize-all', action='store_true', help='Organize by all fields')
    parser.add_argument('--include-lists-dicts', action='store_true',
                        help='Include list/dict fields in --organize-all (may produce large blobs)')
    parser.add_argument('--output-dir', default='organized_data', help='Directory to save organized data')
    parser.add_argument('--inspect', action='store_true', help='Inspect JSON structure')
    parser.add_argument('--grep', action='store_true', 
                        help='Flatten JSON and save grep-like organized output into files')
    
    args = parser.parse_args()

    # Load the JSON file
    data = load_json(args.file)

    # Inspect mode: prints the JSON structure
    if args.inspect:
        print("\nJSON Structure:")
        inspect_json_structure(data)
        return

    # Extract a specific value using a dot notation path
    if args.path:
        result = get_value_by_path(data, args.path)
        if result is None:
            print(f"No value found at path: {args.path}")
            exit(1)
        print(result)
    # Grep-like mode: flatten the JSON, organize the output by key, and save into files
    elif args.grep:
        organized = {}
        if isinstance(data, list):
            # Merge flattened outputs from each item
            for item in data:
                flat = flatten_json(item)
                for key, value in flat.items():
                    organized.setdefault(key, []).append(value)
        else:
            organized = {k: [v] for k, v in flatten_json(data).items()}
        
        # Create a timestamped directory for the grep-like output
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_output_path = Path(args.output_dir) / f"grep_output_{timestamp}"
        base_output_path.mkdir(parents=True, exist_ok=True)
        
        # Save each key and its list of values into a separate text file for readability.
        # Only non-empty values are included and duplicate values are summarized with counts.
        for key, values in organized.items():
            filtered_values = [v for v in values if not is_empty_value(v)]
            if not filtered_values:
                continue  # Skip keys with only empty values
            safe_key = "".join(c for c in key if c.isalnum() or c in (' ', '-', '_')).strip()
            if not safe_key:
                safe_key = "unknown"
            file_path = base_output_path / f"{safe_key}.txt"
            with open(file_path, 'w') as f:
                f.write(f"Key: {key}\n")
                f.write("Values:\n")
                counter = Counter(filtered_values)
                for value, count in counter.items():
                    if count > 1:
                        f.write(f"  {value} (x{count})\n")
                    else:
                        f.write(f"  {value}\n")
            print(f"Saved grep-like output for key '{key}' to {file_path}")
    # Organize by all fields
    elif args.organize_all:
        organized_data = organize_all_fields(data, include_lists_dicts=args.include_lists_dicts)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_output_path = Path(args.output_dir) / f"organized_{timestamp}"
        base_output_path.mkdir(parents=True, exist_ok=True)
        print(f"Creating base output directory for all fields: {base_output_path}")
        for field, value_dict in organized_data.items():
            safe_field = "".join(c for c in str(field) if c.isalnum() or c in (' ', '-', '_')).strip()
            field_path = base_output_path / safe_field
            field_path.mkdir(exist_ok=True)
            for val, items_list in value_dict.items():
                safe_val = "".join(c for c in str(val) if c.isalnum() or c in (' ', '-', '_')).strip()
                file_path = field_path / f"{safe_val}.json"
                with open(file_path, 'w') as f:
                    json.dump(items_list, f, indent=2)
                print(f"Saved {len(items_list)} items with {field}='{val}' to {file_path}")
    # Organize by a specified field
    elif args.organize_by:
        organized_data = organize_by_field(data, args.organize_by)
        save_organized_data(organized_data, args.output_dir)
    # Default output: either compact or pretty-printed JSON
    else:
        if args.compact:
            print(json.dumps(data, separators=(',', ':')))
        else:
            pretty_print(data, indent=2 if args.pretty else None)

if __name__ == '__main__':
    main()
