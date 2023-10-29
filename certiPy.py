#!/usr/bin/python3
"""
certiPy.py: An OpenSSL Tool for generating private keys and signing requests from a JSON file.

Author:     [Author Name]
Company:    [Company Name]

Usage: certiPy.py [-h] -i  [-ol] [-n] [-c] [-d] [-y] [-opk] [-ipk] [-t] [-b] [-osr] [-conf] [-dig]

    options:
    -h, --help           show this help message and exit

    input:
    -i , --input         input file [JSON]

    logging:
    -ol , --output-log   output path logs [default=/logs]

    input filter:
    -n , --network       network name to generate private key and signing request for
    -c , --cluster       cluster name to generate private key and signing request for

    terminal output:
    -d, --debug          set to get debug output [default=False]
    -y, --skip-checking  set to skip SSL parameter checking [default=False]

    private key generation:
    -opk , --output-pk   output path private keys [default=/keys]
    -ipk , --input-pk    prepared private key [default=None]
    -t , --type          file type [default=pem]
    -b , --bits          key size in bits (2048/4096/8192) [default=4096]

    signing request generation:
    -osr , --output-sr   output path signing requests [default=/reqs]
    -conf , --config     prepared config file for generating signing request [default=None]
    -dig , --digest      hash function for generating the signing request (sha256/sha384/sha512) [default=sha256]


Example:
    certiPy.py -i data.json

The input file should be in JSON format and contain the following fields:
   [
        {
            "Network": "<network_name>",
            "Cluster":
            [
                {
                    "dns_alias_tech_cluster": "<cluster_tech_name>",
                    "ip": "<cluster_ip>",
                    "dns_alias_human_cluster": "<cluster_human_name>",
                    "machines":
                    [
                        {
                            "machine": "<machine_name>",
                            "dns_alias_tech_machine": "<machine_tech_name>",
                            "ipv4_address": "<machine_ip>",
                            "dns_alias_human_machine": "<machine_human_name>"
                        },
                        {
                            "machine": "<machine_name>",
                            "dns_alias_tech_machine": "<machine_tech_name>",
                            "ipv4_address": "<machine_ip>",
                            "dns_alias_human_machine": "<machine_human_name>"
                        },
                    ]
                },
                {
                    .
                    .
                    .
                }
            ]
        },
        {
            .
            .
            .
        }
    ]
"""
import argparse
import logging
import os
import stat
import subprocess
import json
import datetime
import re


# Main ------------------------------------------------------------------------------------------------------------------------------------------------- #
def main(args: argparse.Namespace):
    """
    The main function of the SSL tool.

    This function takes as input the argparse.Namespace object containing the parsed arguments and performs the main operations of the tool.
    It creates the necessary directories, loads the JSON data, generates private keys and signing requests, and logs the results.

    Args:
        args (argparse.Namespace): The parsed arguments.

    Logs:
        logging.info: Information about the generated private keys and signing requests.
    """

    handle_directories(args.output_pk, args.output_sr)
    source = load_json_data(args.input)

    count_pk = count_sr = 0

    for cluster in get_clusters(source, args.network, args.cluster):
        try:
            private_key, count_pk = generate_private_keys(cluster.get("cluster"), args.type, args.output_pk, args.input_pk, args.bits, args.debug, count_pk)
            signing_request, count_sr = generate_signing_requests(cluster, private_key, args.output_sr, args.config, args.digest, args.skip_checking, args.debug, count_sr)
        except Exception as e:
            logging.exception(f"Failed to process cluster {cluster}: {e}")
            continue

        print("-" * os.get_terminal_size().columns)

    logging.info(f"{count_pk} private keys generated.")
    logging.info(f"{count_sr} signing requests generated.")
# ------------------------------------------------------------------------------------------------------------------------------------------------------ #

# Argument Parser -------------------------------------------------------------------------------------------------------------------------------------- #
def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments using argparse module.

    Returns:
        args (argparse.Namespace): Namespace object returned by argparse.ArgumentParser.parse_args() method, containing the values of the parsed arguments.
    """
    parser = argparse.ArgumentParser(description="A simple SSL tool to automatically generate private keys and signing request from a JSON file.", prog="certiPy.py")

    # input
    required_args = parser.add_argument_group("input")
    required_args.add_argument("-i", "--input", type=str, required=True, metavar="", help="input file [JSON]")

    # logging
    logging_group = parser.add_argument_group("logging")
    logging_group.add_argument("-ol", "--output-log", type=str, required=False, default="logs", metavar="", help="output path logs [default=/logs]")

    # filter input
    input_filter_group = parser.add_argument_group("input filter")
    input_filter_group.add_argument("-n", "--network", type=str,required=False, default=None, metavar="", help="network name to generate private key and signing request for")
    input_filter_group.add_argument("-c", "--cluster", type=str,required=False, default=None, metavar="", help="cluster name to generate private key and signing request for")

    # output config
    terminal_output_group = parser.add_argument_group("terminal output")
    terminal_output_group.add_argument("-d", "--debug", required=False, default=False, action="store_true", dest="debug", help="set to get debug output [default=False]")
    terminal_output_group.add_argument("-y", "--skip-checking", required=False, default=False, action="store_true", dest="skip_checking", help="set to skip SSL parameter checking [default=False]")

    # private keys
    private_key_generation_group = parser.add_argument_group("private key generation")
    private_key_generation_group.add_argument("-opk", "--output-pk", type=str, required=False, default="keys", metavar="", help="output path private keys [default=/keys]")
    private_key_generation_group.add_argument("-ipk", "--input-pk", type=str, required=False, default=None, metavar="", help="prepared private key [default=None]")
    private_key_generation_group.add_argument("-t", "--type", type=str, required=False, default="pem", metavar="", help="file type [default=pem]")
    private_key_generation_group.add_argument("-b", "--bits", type=int, required=False, default=4096, choices=[2048, 4096, 8192], metavar="", help="key size in bits (2048/4096/8192) [default=4096]")

    # signing requests
    signing_request_generation_group = parser.add_argument_group("signing request generation")
    signing_request_generation_group.add_argument("-osr", "--output-sr", type=str, required=False, default="reqs", metavar="", help="output path signing requests [default=/reqs]")
    signing_request_generation_group.add_argument("-conf", "--config", type=str, required=False, default=None, metavar="", help="prepared config file for generating signing request [default=None]")
    signing_request_generation_group.add_argument("-dig", "--digest", type=str, required=False, default="sha256", choices=["sha256", "sha384", "sha512"], metavar="", help="hash function for generating the signing request (sha256/sha384/sha512) [default=sha256]")

    args = parser.parse_args()
    check_arguments(parser, args)

    return args


def check_arguments(parser: argparse.ArgumentParser, args: argparse.Namespace):
    """
    Check the validity of the provided arguments.

    Arguments:
        parser (argparse.ArgumentParser): The ArgumentParser instance used to parse the command-line arguments.
        args (argparse.Namespace): The Namespace object containing the parsed command-line arguments.

    Raises:
        argparse.ArgumentTypeError: If the input file is not a .json file.
        argparse.ArgumentTypeError: If input files can not be found.
        argparse.ArgumentTypeError: If input files do not have reading permission.
    """
    # check input file format
    _, file_extension = os.path.splitext(args.input)
    if file_extension != ".json":
        parser.error(f"Input file must be a .json file, got {file_extension}")

    # make absolute paths
    cwd = os.getcwd()
    for attr in ["input", "output_log", "output_pk", "output_sr", "input_pk", "config"]:
        file = getattr(args, attr)
        if file and not os.path.isabs(file):
            setattr(args, attr, f"{cwd}/{file}")

    # check if input files exists
    for file in [args.input, args.input_pk, args.config]:
        if file and not os.path.isfile(file):
            parser.error(f"File not found: {file}")

    # check input files read permission
    for file in [args.input, args.input_pk, args.config]:
        if file and not os.access(file, os.R_OK):
            parser.error(f"Missing permission to read file: {file}")

    # remove leading dot from key file extension/type
    args.type = args.type.strip().lstrip(".")
# ------------------------------------------------------------------------------------------------------------------------------------------------------ #

# Logging ---------------------------------------------------------------------------------------------------------------------------------------------- #
def setup_logging(log_dir: str):
    """
    Setup logging configuration.

    Arguments:
        log_dir (str): The directory where the log files will be stored.

    Logs:
        Main log file will be saved at `log_dir/main.log` and it will include the timestamp, logging level, message, filename and line number.
    """
    os.makedirs(log_dir, exist_ok=True)

    FORMAT = "%(asctime)s [%(levelname)s] %(message)s (%(filename)s:%(lineno)d)"
    logging.basicConfig(level=logging.DEBUG, format=FORMAT, handlers=[logging.FileHandler(f"{log_dir}/main.log"), logging.StreamHandler()])
# ------------------------------------------------------------------------------------------------------------------------------------------------------ #

# JSON Data Handling ----------------------------------------------------------------------------------------------------------------------------------- #
def load_json_data(source: str) -> list:
    """
    Load data from a JSON file.

    Arguments:
        source (str): The path of the file from which the data is to be loaded.

    Returns:
        data (dict): The data loaded from the file.

    Raises:
        FileNotFoundError: If the file is not found.
        json.JSONDecodeError: If there was an error decoding the JSON data.

    Logs:
        logging.info: Information about the data that was loaded.
        logging.error: Information about any errors encountered while loading the data.
    """
    try:
        with open(source, "r") as file:
            data = json.load(file)
        logging.info(f"Data loaded from file: {source}")
        data = validate_data(data)
        return data
    except FileNotFoundError:
        logging.error(f"File not found: {source}")
        exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error loading data from file {source}: {e}")
        exit(1)


def validate_data(source: list) -> list:
    """
    Validate source data.

    Arguments:
        source (list): List of JSON objects

    Returns:
        data (list): List with all JSON objects which have network names.

    Logs:
        logging.warning: Number of JSON objects that have no network or cluster name and therefore are not included.
    """
    data = []
    network_skipped = cluster_skipped = 0

    for item in source:
        if item.get("network"):
            for cluster in item.get("cluster"):
                if cluster.get("dns_alias_human_cluster") or cluster.get("dns_alias_tech_cluster"):
                    data.append(item)
                else:
                    cluster_skipped += 1
        else:
            network_skipped += 1

    if network_skipped > 0:
        logging.warning(f"{network_skipped} network item(s) ingored due to missing network name!")
    if cluster_skipped > 0:
        logging.warning(f"{cluster_skipped} cluster item(s) ignored due to missing cluster name!")

    return data


def get_clusters(source: dict, network: str, cluster: str) -> list:
    """
    Get Cluster Infos based on network and cluster name.

    Arguments:
        source (dict): Dictionary containing the network and cluster information.
        network (str): Network name to filter for.
        cluster (str): Cluster name to filter for.

    Returns:
        clusters (list): List of dictionaries containing the network and cluster information.
    """
    network_matches = [network_item for network_item in source if network_item.get("network") == network or network is None]
    clusters = [{"network": network_item.get("network"), "cluster": cluster_item}
                for network_item in network_matches
				if network_item.get("cluster")
                for cluster_item in network_item.get("cluster")
                if cluster_item.get("dns_alias_human_cluster") == cluster or cluster_item.get("dns_alias_tech_cluster") == cluster or cluster is None]
    return clusters
# ------------------------------------------------------------------------------------------------------------------------------------------------------ #

# Private Key Generation ------------------------------------------------------------------------------------------------------------------------------- #
def generate_private_keys(cluster: dict, type: str, output_pk: str, input_pk: str, bits: str, debug: bool, count: int):
    """
    Generate private RSA keys for a given cluster.

    Arguments:
        cluster (dict): A dictionary containing information about a cluster.
        type (str): The type of RSA key file to be generated.
        output_pk (str): The output directory path where the RSA key file will be generated.
        input_pk (str): Path of an already generated private key. If provided the steps of the generation are skipped.
        bits (str): The number of bits to use when generating the key.
        debug (bool): A flag indicating whether to display the debug output of the RSA key information.
        count (int): Running count of generated private keys.

    Returns:
        file_path (str): The full path of the generated RSA key file.
        count (int): Running count of generated private keys
    """
    cluster_name = cluster.get("dns_alias_human_cluster") if cluster.get("dns_alias_human_cluster") else cluster.get("dns_alias_tech_cluster")
    cluster_name = re.sub("\s+", "_", cluster_name.strip())

    filename = f"id_key_{cluster_name}_ssl.{type}"
    file_path = os.path.join(output_pk, filename)

    if input_pk:
        logging.info(f"Using provided private key: {input_pk}")
        return input_pk, count
    if os.path.isfile(file_path):
        logging.info(f"Using exisitng private key: {filename}")
        return file_path, count
    else:
        create_rsa_key(filename, file_path, str(bits), debug)
        change_permission_to_read_only(file_path)
        count += 1
        return file_path, count


def create_rsa_key(filename: str, file_path: str, bits: str, debug: bool):
    """
    Create an RSA private key using OpenSSL.

    Arguments:
        filename (str): The name of the RSA key file to be generated.
        file_path (str): The full path of the RSA key file to be generated.
        bits (str): The number of bits to use when generating the key.
        debug (bool): A flag indicating whether to display the debug output of the RSA key information.

    Raises:
        subprocess.CalledProcessError: If there is an error generating the RSA key using OpenSSL.

    Logs:
        logging.info: Information about the generated private key.
        logging.error: Information about any errors encountered while generating the RSA key using OpenSSL.
    """
    try:
        subprocess.run(["openssl", "genrsa", "-out", file_path, bits], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
        if debug: subprocess.run(["openssl", "rsa", "-text", "-noout", "-in", file_path], stdout=subprocess.DEVNULL, check=True)
        logging.info(f"Private key generated: {filename}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error generating RSA key: {e}")
        exit(1)
# ------------------------------------------------------------------------------------------------------------------------------------------------------ #

# Signing Request Generation --------------------------------------------------------------------------------------------------------------------------- #
def generate_signing_requests(cluster: dict, private_key: str, output_sr: str, config: str, digest: str, skip_checking: bool, debug: bool, count: int):
    """
    Generate signing requests for the cluster.

    Arguments:
        cluster (dict): The cluster information.
        private_key (str): The path to the private key file.
        output_sr (str): The output directory for the signing requests.
        config (str): Path of an already generated config file.
        digest (str): The message digest algorithm to use when generating the signing request.
        skip_checking (bool): A flag indicating whether the SSL parameters have to be manually validated or not.
        debug (bool): A flag indicating whether to display the debug output of the signing request information.
        count (int): Running count of generated Signing Requests.

    Returns:
        file_path_sr (str): The path to the generated signing request.
        count (int): Running count of generated Signing Requests.

    Logs:
        logging.error: If the SSL parameters where NOT validated.
        logging.info: If the SSL parameters where validated.
    """
    cluster_name = cluster.get("cluster").get("dns_alias_human_cluster") if cluster.get("cluster").get("dns_alias_human_cluster") else cluster.get("cluster").get("dns_alias_tech_cluster")
    cluster_name = re.sub("\s+", "_", cluster_name.strip())

    date = re.sub("\.\d+", "", str(datetime.datetime.now())).replace("-", "").replace(" ", "_").replace(":", "")

    filename_sr = f"{date}_id_req_{cluster_name}_ssl.csr"
    file_path_sr = os.path.join(output_sr, filename_sr)

    filename_config = f"{date}_csr_config_{cluster_name}.conf"
    file_path_config = os.path.join(output_sr, "config", filename_config)

    csr_info = get_csr_info(cluster.get("network"), cluster.get("cluster"))

    # generate or update config file
    if not config:
        generate_config_file(csr_info, file_path_config)
    else:
        update_config_file(csr_info, config, file_path_config)

    if debug or not skip_checking:
        show_signing_request_infos(cluster.get("network"), cluster.get("cluster"), private_key, file_path_sr, file_path_config)

        if not skip_checking and input("Validate SSL Parameters (Y/N) > ").lower() != "y":
            logging.warning("SSL Parameters NOT validated!")
            return None, count

    logging.info("SSL Parameters validated!")

    create_signing_request(filename_sr, private_key, file_path_sr, file_path_config, digest, debug)
    change_permission_to_read_only(file_path_sr)
    change_permission_to_read_only(file_path_config)

    count += 1
    return file_path_sr, count


def generate_config_file(csr_info: dict, config_file_path: str):
    """
    Generate a config file template. The method then calls update_config_file() with its given parameters.

    Argumemnts:
        csr_info (dict): Information required for Certificate Signing Request.
        config_file_path (str): Config file path.
    """
    config_file_template = """[req]
prompt = no
distinguished_name = req_distinguished_name
req_extensions = req_ext

[req_distinguished_name]
CN={commonName}
C={country}
O={organization}
emailAddress={emailAddress}
{organizationalUnits}

[req_ext]
subjectAltName = @alt_names

[alt_names]
{altNames}
"""
    try:
        with open(config_file_path, "w") as f:
            f.write(config_file_template)
    except PermissionError as e:
        logging.error(f"Permission for writing denied: {config_file_path}")
        exit(1)
    logging.info(f"Successfully created config file: {config_file_path}")

    update_config_file(csr_info, config_file_path, config_file_path)


def update_config_file(csr_info: dict, input_config_path: str, output_config_path: str):
    """
    Update a config file based on the given Certificate Signing Request information.

    Arguments:
        csr_info (dict): Information required for Certificate Signing Request.
            This dictionary should have the following keys:
                "commonName" (str): The common name of the certificate.
                "country" (str): The country of the certificate.
                "organization" (str): The organization name of the certificate.
                "emailAddress" (str): The email address of the certificate.
                "organizationalUnits" (list): A list of organizational unit strings.
                "alt_names" (dict): A dictionary of alternative names for the certificate, where the key is the name type (e.g. "DNS") and the value is a list of alternative names. 
        input_config_path (str): Path of the config file template.
        output_config_path (str): Path where the config file will be saved.

    Raises:
        KeyError: When the config file template is missing an key.
        PermissionError: When the config file is missing the write permission.

    Logs:
        logging.error: Missing key in config file.
        logging.error: Missing write permission.
        logging.info: Information about the updated config file.
    """
    with open(input_config_path, "r") as f:
        config_file_template = f.read()

    try:
        config_file_content = config_file_template.format(
            commonName=csr_info["commonName"],
            country=csr_info["country"],
            organization=csr_info["organization"],
            emailAddress=csr_info["emailAddress"],
            organizationalUnits=get_organizationalUnits(csr_info["organizationalUnits"]),
            altNames=get_altNames(csr_info["altNames"])
        )
    except KeyError as e:
        logging.error(f"The key {e} is missing in the config file")
        exit(1)

    try:
        with open(output_config_path, "w") as f:
            f.write(config_file_content)
    except PermissionError as e:
        logging.error(f"Permission for writing denied: {output_config_path}")
        exit(1)

    logging.info(f"Successfully updated config file: {output_config_path}")


def get_altNames(altNames: dict) -> str:
    """
    Get altNames in config file format.

    Arguments:
        altNames (dict): Dictorary of the altNames.

    Returns:
        altNames (list): altNames in config file format.
    """
    return "\n".join(f"{alt_name_type}.{index}={alt_name}" for alt_name_type, alt_names in altNames.items() for index, alt_name in enumerate(alt_names, start=1))


def get_organizationalUnits(organizationalUnits: list) -> str:
    """
    Get organizationalUnits in config file format.

    Arguments:
        organizationalUnits (dict): Dictorary of the organizationalUnits.

    Returns:
        organizationalUnits (list): organizationalUnits in config file format.
    """
    return "\n".join(f"{index}.OU={unit}" for index, unit in enumerate(organizationalUnits, start=1))


def get_csr_info(network: str, cluster: dict) -> dict:
    """
    Get Certificate Signing Request information.

    Arguments:
        network (str): Network name for the commonName.
        cluster (dict): Clsuter information.

    Returns:
        csr_info (dict): Certificate Signing Request information.
    """
    csr_info = {
        "commonName": f"{cluster.get('dns_alias_human_cluster')}.intern",
        "country": "<country_code>",
        "organization": "<company>",
        "emailAddress": "<email>",
        "organizationalUnits": [
            "<company>",
            "SSL Server",
            "SSL"
        ],
        "altNames": {
            "DNS": get_dns_list(network, cluster),
            "IP": get_ip_list(cluster)
        }
    }
    return csr_info


def get_dns_list(network: str, cluster: dict) -> list:
    """
    Get all DNS information of the network and cluster.

    Arguments:
        network (str): Network name.
        cluster (dict): Clsuter information.

    Returns:
        dns_list (list): List of all DNS of the network and cluster.
    """
    dns_list = [f"{network}.intern"] if network else []
    dns_list.extend([f"{cluster.get('dns_alias_human_cluster')}.intern"]
                    if cluster.get('dns_alias_human_cluster') else [])
    dns_list.extend([f"{machine.get('dns_alias_human_machine')}.intern"
                    for machine in cluster.get("machines")
                    if machine.get("dns_alias_human_machine")]
                    if cluster.get("machines") else [])
    return dns_list


def get_ip_list(cluster: dict) -> list:
    """
    Get all IP information of the network and cluster.

    Arguments:
        network (str): Network name.
        cluster (dict): Clsuter information.

    Returns:
        ip_list (list): List of all IP of the network and cluster.
    """
    ip_list = [cluster.get("ip")] if cluster.get("ip") else []
    ip_list.extend([machine.get("ipv4_address")
                   for machine in cluster.get("machines")
                   if machine.get("ipv4_address")]
                   if cluster.get("machines") else [])
    return ip_list


def create_signing_request(filename: str, private_key: str, signing_request: str, config: str, digest: str, debug: bool):
    """
    Create a signing request using OpenSSL.

    Arguments:
        filename (str): The name of the file to generate the signing request.
        private_key (str): Private Key path.
        signing_request (str): Signing Request path.
        config (str): Config file path.
        digest (str): The message digest algorithm to use when generating the signing request.
        debug (bool): A flag indicating whether to display the debug output of the signing request information.

    Raises:
        subprocess.CalledProcessError: If there is an error generating the signing request using OpenSSL.

    Logs:
        logging.info: Information about the generated signing request.
        logging.exception: Information about any errors encountered while generating the signing request using OpenSSL.
    """
    try:
        with subprocess.Popen(["openssl", "req", "-new", "-key", private_key, "-out", signing_request, f"-{digest}", "-config", config], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout_output, _ = proc.communicate()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, proc.args, stdout_output)

        if debug: subprocess.run(["openssl", "req", "-text", "-noout", "-verify", "-in", signing_request, "-config", config], check=True)
        logging.info(f"Signing Request generated: {filename}")
    except subprocess.CalledProcessError as e:
        error = re.sub(r"(\r\n|\r|\n)", "", str(e.stdout.decode()))
        logging.error(f"Error generating Signing Request: {error}")
        exit(1)


def show_signing_request_infos(network: str, cluster: dict, private_key: str, signing_request: str, config: str):
    """
    Print textual representation of the SSL parameters

    Arguments:
        network (str): Network name.
        cluster (dict): Cluster information.
        private_key (str): Private Key path.
        signing_request (str): Signing Request path.
        config (str): Config file path.
    """
    with open(config, "r") as file:
        csr_info = file.read()

    print("-" * os.get_terminal_size().columns)
    print(f"Network: {network}")
    print(f"Cluster:")
    print(json.dumps(cluster, indent=4))
    print(f"\nPrivate Key: {private_key}")
    print(f"Signing Request: {signing_request}")
    print(f"Config: {config}\n")
    print(csr_info)
    print("-" * os.get_terminal_size().columns)
# ------------------------------------------------------------------------------------------------------------------------------------------------------ #

# Utilities -------------------------------------------------------------------------------------------------------------------------------------------- #
def handle_directories(output_pk: str, output_sr: str):
    """
    Create the necessary directories for the SSL tool

    Arguments:
        output_pk (str): The path of the private key directory
        output_sr (str): The path of the signing request directory
    """
    create_directory(output_pk)
    create_directory(output_sr)
    create_directory(f"{output_sr}/config")


def create_directory(dir_path: str) -> str:
    """
    Create a directory at the specified path.

    Arguments:
        dir_path (str): The path of the directory to be created.

    Returns:
        dir_path (str): The path of the directory that was created.

    Raises:
        OSError: If there was an error while creating the directory.

    Logs:
        logging.info: Information about the created directory.
        logging.error: Information about any errors encountered while creating the directory.
    """
    try:
        os.makedirs(dir_path, exist_ok=True)
        logging.info(f"Created directory: {dir_path}")
        return dir_path
    except OSError as e:
        logging.error(f"Error while creating directory: {e}")
        exit(1)


def change_permission_to_read_only(path: str):
    """
    Change the file permission to read-only.

    Arguments:
        path (str): The path of the file whose permission is to be changed.

    Logs:
        logging.info: Information about the file whose permission was changed to read-only.
    """
    try:
        os.chmod(path, stat.S_IRUSR)
        logging.info(f"File permission changed to read-only: {path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error while changing file permission: {e}")
        exit(1)
# ------------------------------------------------------------------------------------------------------------------------------------------------------ #


if __name__ == "__main__":
    # parse input arguments
    args = parse_arguments()

    # setup logging
    setup_logging(args.output_log)

    # log input arguments
    if args.debug:
        input_args = " ".join(["[{}={}]".format(arg, getattr(args, arg)) for arg in vars(args)])
        logging.debug(f"Script executed with: {input_args}")

    # run main method
    main(args)
