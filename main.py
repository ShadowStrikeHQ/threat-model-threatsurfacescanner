#!/usr/bin/env python3

import argparse
import logging
import socket
import subprocess
import sys
import json
import os

try:
    import graphviz
    import markdown2
except ImportError as e:
    print(f"Error: Missing dependencies. Please install: {e.name}")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description='Threat Modeling Automation Tool')
    parser.add_argument('target', help='Target system (IP address, hostname, or domain)')
    parser.add_argument('-p', '--ports', default='21,22,80,443,3389', help='Comma-separated list of ports to scan (default: 21,22,80,443,3389)')
    parser.add_argument('-o', '--output', default='threat_model.json', help='Output file for threat model (default: threat_model.json)')
    parser.add_argument('--format', choices=['json', 'markdown', 'pdf', 'graphviz'], default='json', help='Output format (default: json)')
    parser.add_argument('--model-name', default='default_model', help='Name of the threat model (default: default_model)')
    return parser


def validate_target(target):
    """
    Validates the target input to ensure it's a valid IP address, hostname, or domain.
    Returns:
        bool: True if the target is valid, False otherwise.
    """
    try:
        socket.inet_aton(target)  # Check if it's a valid IP address
        return True
    except socket.error:
        try:
            socket.gethostbyname(target) #Check if it's a valid hostname or domain
            return True
        except socket.gaierror:
            logging.error(f"Invalid target: {target}.  Must be a valid IP address, hostname, or domain.")
            return False


def scan_ports(target, ports):
    """
    Scans the specified ports on the target system using nmap.

    Args:
        target (str): The target system's IP address, hostname, or domain.
        ports (str): A comma-separated list of ports to scan.

    Returns:
        dict: A dictionary containing the scan results.
    """
    try:
        ports_list = [int(p) for p in ports.split(',')]  # Convert ports string to a list of integers
        if not all(0 < port < 65536 for port in ports_list):
            raise ValueError("Invalid port number(s). Ports must be between 1 and 65535.")

        nmap_command = ['nmap', '-sV', '-p', ports, target]
        process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stderr:
            logging.error(f"nmap scan failed: {stderr.decode()}")
            return {}

        #Parse the nmap output (basic parsing, can be improved with proper nmap parsing libraries)
        results = {}
        for line in stdout.decode().splitlines():
            if "open" in line and "tcp" in line:
                port = line.split("/")[0]
                service = line.split(" ")[-1]
                results[port] = service

        return results

    except ValueError as e:
        logging.error(f"Error: Invalid input.  {e}")
        return {}
    except FileNotFoundError:
        logging.error("Error: nmap not found. Please ensure nmap is installed and in your PATH.")
        return {}
    except Exception as e:
        logging.error(f"An unexpected error occurred during port scanning: {e}")
        return {}

def identify_vulnerabilities(scan_results):
    """
    Identifies potential vulnerabilities based on the scan results (open ports and services).

    Args:
        scan_results (dict): A dictionary containing the scan results.

    Returns:
        list: A list of potential vulnerabilities.
    """
    vulnerabilities = []
    for port, service in scan_results.items():
        if port == "21" and "ftp" in service.lower():
            vulnerabilities.append(f"Port 21 (FTP): Possible anonymous login or weak credentials. Service: {service}")
        elif port == "22" and "ssh" in service.lower():
            vulnerabilities.append(f"Port 22 (SSH): Brute-force attacks, outdated SSH version. Service: {service}")
        elif port == "80" and "http" in service.lower():
            vulnerabilities.append(f"Port 80 (HTTP): Unencrypted traffic, potential web application vulnerabilities. Service: {service}")
        elif port == "443" and "https" in service.lower():
            vulnerabilities.append(f"Port 443 (HTTPS): Vulnerable SSL/TLS configurations, web application vulnerabilities. Service: {service}")
        elif port == "3389" and "msrdp" in service.lower():
             vulnerabilities.append(f"Port 3389 (RDP): Brute-force attacks, outdated RDP version. Service: {service}")
        else:
            vulnerabilities.append(f"Port {port}: Potential vulnerability associated with service: {service}")
    return vulnerabilities


def generate_threat_model(target, vulnerabilities, model_name):
    """
    Generates a basic threat model in JSON format.

    Args:
        target (str): The target system.
        vulnerabilities (list): A list of vulnerabilities.
        model_name (str): The name of the threat model.

    Returns:
        dict: A dictionary representing the threat model.
    """
    threat_model = {
        "model_name": model_name,
        "target": target,
        "vulnerabilities": vulnerabilities
    }
    return threat_model


def export_threat_model(threat_model, output_file, output_format="json"):
    """
    Exports the threat model to the specified format.

    Args:
        threat_model (dict): The threat model.
        output_file (str): The output file path.
        output_format (str): The output format (json, markdown, pdf, graphviz).
    """
    try:
        if output_format == "json":
            with open(output_file, "w") as f:
                json.dump(threat_model, f, indent=4)
            logging.info(f"Threat model exported to {output_file} in JSON format.")

        elif output_format == "markdown":
            markdown_content = f"# Threat Model: {threat_model['model_name']}\n\n"
            markdown_content += f"## Target: {threat_model['target']}\n\n"
            markdown_content += "## Vulnerabilities:\n\n"
            for vulnerability in threat_model['vulnerabilities']:
                markdown_content += f"- {vulnerability}\n"

            with open(output_file, "w") as f:
                f.write(markdown_content)
            logging.info(f"Threat model exported to {output_file} in Markdown format.")

        elif output_format == "pdf":
            markdown_content = f"# Threat Model: {threat_model['model_name']}\n\n"
            markdown_content += f"## Target: {threat_model['target']}\n\n"
            markdown_content += "## Vulnerabilities:\n\n"
            for vulnerability in threat_model['vulnerabilities']:
                markdown_content += f"- {vulnerability}\n"

            try:
                 html_content = markdown2.markdown(markdown_content)
                 with open("temp.html", "w") as f:
                    f.write(html_content)

                 subprocess.run(["wkhtmltopdf", "temp.html", output_file], check=True)
                 os.remove("temp.html") #Clean up
                 logging.info(f"Threat model exported to {output_file} in PDF format.")
            except FileNotFoundError:
                logging.error("wkhtmltopdf not found. Please ensure wkhtmltopdf is installed and in your PATH. PDF export failed.")
            except Exception as e:
                logging.error(f"Error converting to PDF: {e}")

        elif output_format == "graphviz":
            try:
                dot = graphviz.Digraph(comment=f'Threat Model: {threat_model["model_name"]}')
                dot.node('A', threat_model['target'])

                for i, vulnerability in enumerate(threat_model['vulnerabilities']):
                    dot.node(str(i+1), vulnerability)
                    dot.edge('A', str(i+1))

                dot.render(output_file, view=False, format="pdf")  # Output as PDF
                logging.info(f"Threat model graph exported to {output_file}.pdf in Graphviz format.")

            except graphviz.backend.ExecutableNotFound:
                logging.error("Graphviz not found. Please ensure Graphviz is installed and in your PATH.")
            except Exception as e:
                logging.error(f"Error generating Graphviz graph: {e}")
        else:
            logging.error(f"Unsupported output format: {output_format}")

    except IOError as e:
        logging.error(f"Error writing to file: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during export: {e}")


def main():
    """
    Main function to orchestrate the threat modeling process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not validate_target(args.target):
        sys.exit(1)

    logging.info(f"Starting threat modeling for target: {args.target}")
    scan_results = scan_ports(args.target, args.ports)

    if not scan_results:
        logging.warning("No open ports found or scan failed. Exiting.")
        sys.exit(1)

    vulnerabilities = identify_vulnerabilities(scan_results)

    if not vulnerabilities:
        logging.info("No vulnerabilities identified.")
    else:
        logging.info("Identified potential vulnerabilities:")
        for vulnerability in vulnerabilities:
            logging.info(f"- {vulnerability}")

    threat_model = generate_threat_model(args.target, vulnerabilities, args.model_name)
    export_threat_model(threat_model, args.output, args.format)
    logging.info("Threat modeling completed.")


if __name__ == "__main__":
    main()