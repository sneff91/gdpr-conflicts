import configparser
import logging
import os
import smtplib
from datetime import datetime
from json import dumps
from pathlib import Path
from time import time

import truststore
from niquests import post
from niquests.auth import HTTPBasicAuth
from xmltodict import parse

from compare import compare


def retrieve_and_parse_config(app_path) -> tuple[dict, list[dict]]:
    """Load application configuration and CUCM cluster definitions.

    Reads config.ini from the script directory, initializes logging,
    normalizes global settings, and constructs CUCM cluster configs.

    Returns:
        A tuple containing:
        - global_settings: dict of application-level settings
        - cucm_clusters: list of per-cluster configuration dictionaries
    """

    config_file = app_path / 'config.ini'
    config = configparser.ConfigParser(interpolation=None)
    config.read(config_file)

    # Global config.ini settings
    global_settings = {
        'output_destination': config.get('settings', 'OUTPUT_DESTINATION', fallback='logging'),
        'pattern_types': config.get('settings', 'PATTERN_TYPES', fallback='both'),
        'include_elapsed_time': config.getboolean('settings', 'INCLUDE_ELAPSED_TIME', fallback=True),
        'severity_level': os.path.expandvars(config.get('settings', 'SEVERITY_LEVEL', fallback='warning')),
        'max_results': config.getint('settings', 'MAX_RESULTS', fallback=200_000),
        'max_samples': config.getint('settings', 'MAX_SAMPLES', fallback=20),
        'cert_path': config.get('settings', 'CERT_PATH', fallback=None),
        'use_pretty_print': config.getboolean('settings', 'USE_PRETTY_PRINT', fallback=False),
        'smtp_server': os.path.expandvars(config.get('smtp', 'SMTP_SERVER', fallback=None)),
        'smtp_port': config.getint('smtp', 'SMTP_PORT', fallback=25),
        'smtp_from': os.path.expandvars(config.get('smtp', 'SMTP_FROM', fallback=None)),
        'smtp_to': os.path.expandvars(config.get('smtp', 'SMTP_TO', fallback=None)),
        'log_retention': config.getint('logging', 'LOG_RETENTION', fallback=30),
        'log_file_dir': os.path.expandvars(config.get('logging', 'LOG_FILE_DIR', fallback='')),
    }

    # Map specified pattern type from config.ini to CUCM nomenclature
    pattern_type_mapping = {
        'enterprise': ['Enterprise Number'],
        'e164': ['+E.164 Number'],
        'both': ['Enterprise Number', '+E.164 Number']
    }
    global_settings['pattern_types']: list[str] = pattern_type_mapping.get(global_settings['pattern_types'])

    # Populate CUCM cluster config from config.ini sections
    cucm_clusters = []
    for section in config.sections():
        if section.lower().startswith('cucm_'):
            cluster_config = {
                'label': os.path.expandvars(config.get(section, 'LABEL', fallback=None)),
                'fqdn': os.path.expandvars(config.get(section, 'FQDN', fallback=None)),
                'axl_user': os.path.expandvars(config.get(section, 'AXL_USER', fallback=None)),
                'axl_pass': os.path.expandvars(config.get(section, 'AXL_PASS', fallback=None)),
                'verify_cert': config.getboolean(section, 'VERIFY_CERT', fallback=True),
                'http_secure': config.getboolean(section, 'HTTP_SECURE', fallback=True),
            }
            ignore_patterns = config.get(section, 'IGNORE_PATTERNS', fallback=None)
            if ignore_patterns:
                cluster_config['ignore_patterns'] = [pattern.strip() for pattern in ignore_patterns.split(",")]
            cucm_clusters.append(cluster_config)

    return global_settings, cucm_clusters


def setup_logging(app_path, logging_settings) -> None:
    """Initialize application logging and enforce log retention.

    Creates the logging directory if needed, configures the logging
    subsystem, and removes log files older than the configured
    retention period.
    """

    # If logging directory is not specified in config.ini, set it to a default 'logging' directory within the script's directory
    if not logging_settings.get('log_file_dir'):
        logging_settings['log_file_dir'] = app_path / 'logging'
    LOGGING_DIR = logging_settings.get('log_file_dir')
    todays_date = datetime.today().strftime('%Y-%m-%d')
    LOGPATH = os.path.join(LOGGING_DIR, f'gdpr-conflicts-{todays_date}.log')

    # Create specified logging directory if it does not exist
    Path(LOGPATH).parent.mkdir(parents=True, exist_ok=True)

    # Set log retention period based on config.ini setting
    LOG_RETENTION = logging_settings.get('log_retention')

    logging.basicConfig(
        filename=LOGPATH,
        filemode='a',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )

    # Delete logs older than the log retention period specified in config.ini
    logging.info(f"Cleaning up logs older than {LOG_RETENTION} days")
    for log in os.listdir(LOGGING_DIR):
        if not log.startswith('gdpr-conflicts') and log.endswith('.log'):
            continue
        # Get full filepath for log and calculate age of the log by comparing the current time to the last modified time of the log
        file_path = os.path.join(LOGGING_DIR, log)
        file_age = time() - os.path.getmtime(file_path)
        # Multiple log retention period by 86400 seconds in a day and delete if it exceeds the log retention period
        if file_age >= LOG_RETENTION * 86400:
            os.remove(file_path)
    
    return


def retrieve_advertised_patterns(cucm_clusters: list[dict], cert_path: str | None, pattern_types: list[str]) -> dict[str, list[str]]:
    """Retrieve GDPR Advertised Patterns from CUCM clusters via AXL API.

    Queries each configured CUCM cluster using the AXL API, parses the
    SOAP response, filters patterns based on pattern type and ignore
    rules, and returns patterns grouped by cluster label.

    Raises:
        FileNotFoundError: If a configured certificate path does not exist.
    """

    # Define the SOAP body for the AXL API request to retrieve advertised patterns from CUCM clusters
    SOAP_BODY = '''
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://www.cisco.com/AXL/API/14.0">
    <soapenv:Header/>
    <soapenv:Body>
        <ns:listAdvertisedPatterns>
        <searchCriteria>
            <!--Optional:-->
            <description>%</description>
            <!--Optional:-->
            <pattern>%</pattern>
        </searchCriteria>
        <returnedTags uuid="?">
            <!--Optional:-->
            <description>?</description>
            <!--Optional:-->
            <pattern>?</pattern>
            <!--Optional:-->
            <patternType>?</patternType>
        </returnedTags>
        </ns:listAdvertisedPatterns>
    </soapenv:Body>
    </soapenv:Envelope>
    '''

    # Define the SOAP headers for the AXL API request
    SOAP_HEADERS = {
        'Content-Type': 'application/xml',
        'Accept': 'application/xml',
    }

    cluster_patterns = {}

    for cluster in cucm_clusters:
        # Set protocol and port depending on secure/non-secure HTTP preference
        if cluster.get('http_secure'):
            protocol = 'https'
            port = 8443
        else:
            protocol = 'http'
            port = 80

        # If VERIFY_CERT is false for the cluster, do not verify certs
        if not cluster.get('verify_cert'):
            verify = False
        else:
            # Use the cert path explicitly set in config.ini per the global setting CERT_PATH
            if cert_path:
                if not os.path.exists(cert_path):
                    raise FileNotFoundError(f"CERT_PATH does not exist: {cert_path}")
                verify = cert_path
            # Use the system CA trust store by default if CERT_PATH is not explicitly specified
            else:
                truststore.inject_into_ssl()
                verify = True
        
        # Make AXL API request to retrieve advertised patterns from the cluster and store the response for processing
        response = post(
            url=f"{protocol}://{cluster.get('fqdn')}:{port}/axl/",
            data=SOAP_BODY,
            headers=SOAP_HEADERS,
            auth=HTTPBasicAuth(cluster.get('axl_user'), cluster.get('axl_pass')),
            verify=verify,
            timeout=15
            )
        
        # Return error and skip to next cluster if there is an issue with the request (e.g. connection issue, auth issue, etc.)
        if response.status_code != 200:
            logging.error(f"Error occurred while fetching advertised patterns from CUCM cluster {cluster.get('label')}: {response.status_code}")
            continue

        # Convert the XML response to a JSON format for easier parsing
        jsonified_response = parse(response.text)

        # XML output format for CUCM 15 and above
        if jsonified_response.get('soap:Envelope'):
            pattern_data = parse(response.text)['soap:Envelope']['soap:Body']['ns2:listAdvertisedPatternsResponse']['return']['advertisedPatterns']
        # XML output format for CUCM 14 and under
        elif jsonified_response.get('soapenv:Envelope'):
            pattern_data = parse(response.text)['soapenv:Envelope']['soapenv:Body']['ns:listAdvertisedPatternsResponse']['return']['advertisedPatterns']
        else:
            logging.error(f"Unexpected format received from CUCM cluster {cluster.get('label')}: {response.text}. Skipping...")
            continue

        # Parse patterns from jsonified_response
        patterns = []
        for pattern_block in pattern_data:
            # Do not add pattern to patterns list if there is an ignore_patterns list from the config ini and this pattern is to be ignored
            if (
                cluster.get('ignore_patterns')
                and pattern_block.get('pattern') not in cluster.get('ignore_patterns')
                and pattern_block.get('patternType') in pattern_types
            ):
                patterns.append(pattern_block.get('pattern'))
            # Otherwise add retrieved pattern to the patterns list for processing
            elif (
                not cluster.get('ignore_patterns')
                and pattern_block.get('patternType') in pattern_types
            ):
                patterns.append(pattern_block.get('pattern'))
        cluster_patterns[cluster.get('label')] = patterns

    return cluster_patterns


def send_email_notification(smtp_server, smtp_port, smtp_from, smtp_to, smtp_body) -> None:
    """Send an email notification containing conflict results.

    Logs success or SMTP errors but does not raise exceptions.
    """

    try:
        # Construct the email message
        subject = "CUCM Advertised Pattern Conflicts Detected"
        message = f"From: {smtp_from}\nTo: {smtp_to}\nSubject: {subject}\n\n{smtp_body}"
        # Connect to the SMTP server and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.sendmail(smtp_from, smtp_to, message)
        logging.info(f"Email notification successfully sent to {smtp_to}")
    except smtplib.SMTPException as e:
        logging.error(f"An SMTP error occurred: {e}")
    
    return


def main() -> None:
    # Identify the directory location of main.py to determine the location of config.ini and default logging
    app_path = Path(__file__).resolve().parent

    # Retrieve config settings and CUCM cluster information from config.ini and assign to variables for ease of use
    global_settings, cucm_clusters = retrieve_and_parse_config(app_path=app_path)
    cert_path: str | None = global_settings.get('cert_path')
    pattern_types: list[str] = global_settings.get('pattern_types')
    time_it: bool = global_settings.get('include_elapsed_time')
    max_results: int = global_settings.get('max_results')
    max_samples: int = global_settings.get('max_samples')
    use_pretty_print: bool = global_settings.get('use_pretty_print')
    severity_level: str = global_settings.get('severity_level')
    output_destination: str = global_settings.get('output_destination')

    # Set up logging based on config.ini settings and clean up old logs per the log retention setting
    setup_logging(app_path, global_settings)

    if time_it:
        logging.info("Measuring CUCM AXL API processing time...")
        time_start = time()

    # Retrieve advertised patterns from each CUCM cluster via AXL API and store in a dictionary for processing
    cluster_patterns: dict[str, list[str]] = retrieve_advertised_patterns(
        cucm_clusters=cucm_clusters,
        cert_path=cert_path,
        pattern_types=pattern_types
        )

    if time_it:
        time_stop = time()
        logging.info(f"CUCM AXL API processing time: {time_stop - time_start:.3f} seconds")
        logging.info("Measuring advertised pattern conflict processing time...")
        time_start = time()

    # Exit script early if no advertised patterns were retrieved from any of the CUCM clusters
    if not cluster_patterns:
        logging.info("No advertised patterns retrieved from any CUCM cluster. Exiting script")
        return

    # Compare advertised patterns identify intracluster overlaps and intercluster conflicts
    intracluster_overlap, intercluster_conflicts = compare(
        cluster_patterns=cluster_patterns,
        max_results=max_results,
        max_samples=max_samples
        )

    if time_it:
        time_stop = time()
        logging.info(f"Advertised pattern conflict processing time: {time_stop - time_start:.3f} seconds")

    # Reformat the JSON output "pretty print" style if the config.ini setting USE_PRETTY_PRINT is set to true
    if use_pretty_print:
        intracluster_overlap: str = dumps(intracluster_overlap, indent=4, ensure_ascii=False, sort_keys=False, separators=(",", ": "))
        intercluster_conflicts: str = dumps(intercluster_conflicts, indent=4, ensure_ascii=False, sort_keys=False, separators=(",", ": "))

    email_body: str = ""

    # Include informational intra-cluster pattern overlaps in the output if the config.ini setting SEVERITY_LEVEL is set to 'informational'
    if severity_level == 'informational':
        email_body += f"INTRA-CLUSTER PATTERN OVERLAP:\n{intracluster_overlap}\n\n"
        logging.info(f"INTRA-CLUSTER PATTERN OVERLAP:\n{intracluster_overlap}")

    # Log results to file if the config.ini setting OUTPUT_DESTINATION is set to 'logging' or 'both'
    if output_destination in ['logging', 'both']:
        logging.warning(f"INTER-CLUSTER CONFLICTS:\n{intercluster_conflicts}")

    # Send results in email notification if the config.ini setting OUTPUT_DESTINATION is set to 'email' or 'both'
    if output_destination in ['email', 'both']:
        email_body += f"INTER-CLUSTER CONFLICTS:\n{intercluster_conflicts}"
        send_email_notification(
            smtp_server=global_settings.get('smtp_server'),
            smtp_port=global_settings.get('smtp_port'),
            smtp_from=global_settings.get('smtp_from'),
            smtp_to=global_settings.get('smtp_to'),
            smtp_body=email_body
        )
    
    logging.info("Script has finished executing")
    exit(0)

if __name__ == '__main__':
    main()
