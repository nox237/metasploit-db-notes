import os
import argparse
from datetime import datetime
import xml.etree.ElementTree as ET

templates = """# {{title}}

## MetaData

{{metadata}}

## Exploit Attempts

{{exploit_attempts}}

## Services

{{services}}

## Vulns

{{vulns}}

***

## Manual Notes

- 
"""

host_keys = [
    "address", "mac", "comm", "name", "os-name", "os-flavor", "os-sp",
    "os-lang", "arch", "info", "comments", "scope", "virtual-host",
    "detected-arch", "os-family",

    # Count
    # "note-count", "vuln-count", "service-count",
    # "host-detail-count", "exploit-attempt-count", "cred-count",
]
host_list_keys = {
    # "host_details": [],
    "exploit_attempts": ["module", "exploited", "fail-reason", "fail-detail", 'loot-id', 'port', 'proto'],
    "services": ["port", "proto", "state", "name", "info", "id"],
    "notes": ["critical", "ntype", "seen", "service-id", "vuln-id"],
    "vulns": ["name", "info", "origin-id", "origin-type", "notes", "id"]
}

def check_data(element):
    try:
        data = int(element.text)
    except Exception:
        data = element.text
    return data

def parse_xml_to_dict(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()    
    notes = []

    for host in root.findall('.//hosts/host'):
        temp_data = {}

        for host_key in host_keys:
            element = host.find(host_key)
            temp_data[host_key] = check_data(element)
        
        for key, val in host_list_keys.items():
            elements = host.findall(f'./{key}/{key[:-1]}')

            temp_data[key] = []
            for element in elements:
                temp_data2 = {}
                for val2 in val:
                    temp_data2[val2] = check_data(element.find(f'./{val2}'))
                temp_data[key].append(temp_data2)
        notes.append(temp_data)
    return notes

def generate_notes(data, output_path):
    if not os.path.exists(output_path):
        os.mkdir(output_path)

    markdown_content = templates
    # Generate basic docs template
    with open(os.path.join(output_path, data['address']+"-notes.md"), "w") as f:
        markdown_content = markdown_content.replace("{{title}}", data['address'])

        metadatas = []
        metadatas.append("| Key | Value |")
        metadatas.append("|-----|-------|")
        for key in host_keys:
            value = f"**{data[key]}**" if data[key] != None else "None"
            metadatas.append(f"| {key} | {value} |")
        markdown_content = markdown_content.replace("{{metadata}}", "\n".join(metadatas))
        # markdown_content = markdown_content.replace("{{sections}}", "\n\n".join(sections))

        exploit_attempts = []
        for dt in data['exploit_attempts']:
            exploit_attempts.append(f"- **{dt['module']}** ({dt['exploited']}, {dt['port']}/{dt['proto']}) ")
        if exploit_attempts:
            markdown_content = markdown_content.replace("{{exploit_attempts}}", "\n".join(exploit_attempts))
        else:
            markdown_content = markdown_content.replace("{{exploit_attempts}}", "No exploit attempts")

        services = []
        for dt in data['services']:
            services.append(f"- **{dt['port']}/{dt['proto']}** - {dt['state']}: {dt['name']}")
        if services:
            markdown_content = markdown_content.replace("{{services}}", "\n".join(services))
        else:
            markdown_content = markdown_content.replace("{{services}}", "No services")

        vulns = []
        for dt in data['vulns']:
            vulns.append(f"- *{dt['name']}*: {dt['info']}")
        if vulns:
            markdown_content = markdown_content.replace("{{vulns}}", "\n".join(vulns))
        else:
            markdown_content = markdown_content.replace("{{vulns}}", "No vulns")

        f.write(markdown_content)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert Metasploit notes from XML to JSON')
    parser.add_argument('input_file', help='Path to the input XML file')
    parser.add_argument('--output', '-o', default=os.path.join(os.getcwd(), "output") ,help='Path to output the notes')
    args = parser.parse_args()
    input_file = args.input_file

    notes_data = parse_xml_to_dict(input_file)
    for data in notes_data:
        generate_notes(data, args.output)