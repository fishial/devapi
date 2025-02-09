#!/usr/bin/env python3
#
# Demo of the Fishial Deveopers API written in Python
#
import os
import sys
import argparse
import json
import requests
import hashlib
import base64
import mimetypes
import urllib3
import logging

# Disable warnings about insecure HTTPS requests (mimics curl’s --insecure)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging with a default level of WARNING.
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.WARNING,
)


def err(message):
    print(message)
    print("In order to learn more, run: recognize_fish --help")
    sys.exit(1)


def get_file_metadata(picture_path):
    """
    Compute file metadata: base name, MIME type, byte size, and MD5 checksum
    (base64 encoded, matching the openssl behavior in the Bash script).
    """
    name = os.path.basename(picture_path)
    mime, _ = mimetypes.guess_type(picture_path)
    if mime is None:
        mime = "application/octet-stream"
    size = os.path.getsize(picture_path)
    hasher = hashlib.md5()
    with open(picture_path, "rb") as f:
        # Read file in chunks to handle large files
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    checksum = base64.b64encode(hasher.digest()).decode("utf-8")
    return name, mime, size, checksum


def main():
    parser = argparse.ArgumentParser(
        description="Fishial Recognition command line tool.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\
Examples:

    recognize_fish --help
    recognize_fish -h

        Prints this message.

    recognize_fish --identify fishpic.jpg
    recognize_fish -i fishpic.jpg

        Prints metadata of fishpic.jpg.

    recognize_fish --key-id=abc123 --key-secret=abcd1234 fishpic.jpg
    recognize_fish -k abc123 -s abcd1234 fishpic.jpg

        Requests recognition of fishes pictured on fishpic.jpg.
        Client key "abc123" with secret "abcd1234" will be used.
""",
    )
    parser.add_argument("picture", nargs="?", help="Picture file to process")
    parser.add_argument(
        "-i",
        "--identify",
        action="store_true",
        help="Identifies picture metadata and exits without performing fish recognition.",
    )
    parser.add_argument("-k", "--key-id", help="Client key ID.")
    parser.add_argument("-s", "--key-secret", help="Client key secret.")
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug logging output."
    )

    args = parser.parse_args()

    # Update logging level based on the --debug flag.
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.picture is None or not os.path.isfile(args.picture):
        err("No picture file has been specified.")

    # IDENTIFY METADATA
    print("Identifying picture metadata...\n")
    name, mime, size, checksum = get_file_metadata(args.picture)
    print(f"  file name: {name}")
    print(f"  MIME type: {mime}")
    print(f"  byte size: {size}")
    print(f"   checksum: {checksum}\n")

    # If only identification is requested, exit here.
    if args.identify:
        sys.exit(0)

    # Ensure that both key id and key secret are provided for recognition.
    if not args.key_id or not args.key_secret:
        err("Both --key-id and --key-secret must be provided for fish recognition.")

    #############################
    # OBTAIN AUTH TOKEN
    #############################
    print("Obtaining auth token...")
    auth_url = "https://api-users.fishial.ai/v1/auth/token"
    auth_payload = {"client_id": args.key_id, "client_secret": args.key_secret}

    logging.debug("Auth token request URL: %s", auth_url)
    logging.debug("Auth token request payload: %s", json.dumps(auth_payload))

    try:
        r = requests.post(
            auth_url,
            json=auth_payload,
            headers={"Content-Type": "application/json"},
            verify=False,
        )
        r.raise_for_status()
    except Exception as e:
        err(f"Error obtaining auth token: {e}")

    logging.debug("Auth token response: %s", r.text)
    try:
        auth_data = r.json()
    except Exception as e:
        err(f"Failed to parse auth token JSON: {e}")

    if args.debug:
        print("\nAuth token response JSON:")
        print(json.dumps(auth_data, indent=2))

    auth_token = auth_data.get("access_token")
    if not auth_token:
        err("Failed to obtain access token.")
    auth_header = {"Authorization": f"Bearer {auth_token}"}
    print(f"\nAccess token: {auth_token}")

    #############################
    # OBTAIN UPLOAD URL
    #############################
    print("\nObtaining upload url...")
    upload_url_api = "https://api.fishial.ai/v1/recognition/upload"
    upload_payload = {
        "blob": {
            "filename": name,
            "content_type": mime,
            "byte_size": size,
            "checksum": checksum,
        }
    }
    headers = auth_header.copy()
    headers.update(
        {"Content-Type": "application/json", "Accept": "application/json"}
    )

    logging.debug("Upload URL request to: %s", upload_url_api)
    logging.debug("Upload URL request payload: %s", json.dumps(upload_payload))

    try:
        r = requests.post(
            upload_url_api, json=upload_payload, headers=headers, verify=False
        )
        r.raise_for_status()
    except Exception as e:
        err(f"Error obtaining upload URL: {e}")

    logging.debug("Upload URL response: %s", r.text)
    try:
        upload_data = r.json()
    except Exception as e:
        err(f"Failed to parse upload URL JSON: {e}")

    if args.debug:
        print("\nUpload URL response JSON:")
        print(json.dumps(upload_data, indent=2))

    signed_id = upload_data.get("signed-id")
    direct_upload = upload_data.get("direct-upload", {})
    direct_upload_url = direct_upload.get("url")
    direct_upload_headers = direct_upload.get("headers", {})
    content_disposition = direct_upload_headers.get("Content-Disposition")
    if not (signed_id and direct_upload_url and content_disposition):
        err("Missing upload information in response.")

    #############################
    # UPLOAD FILE
    #############################
    print("\nUploading picture to the cloud...")
    put_headers = {
        "Content-Disposition": content_disposition,
        "Content-Md5": checksum,
        "Content-Type": "",  # intentionally empty header, per original script
    }
    logging.debug("File upload URL: %s", direct_upload_url)
    logging.debug("File upload headers: %s", json.dumps(put_headers))

    try:
        with open(args.picture, "rb") as f:
            r = requests.put(
                direct_upload_url, data=f, headers=put_headers, verify=False
            )
            r.raise_for_status()
    except Exception as e:
        err(f"Error uploading file: {e}")

    try:
        upload_response_data = r.json()
        if args.debug:
            print("\nFile upload response JSON:")
            print(json.dumps(upload_response_data, indent=2))
    except Exception:
        if args.debug:
            print("\nFile upload response text:")
            print(r.text)
    logging.debug("File upload response: %s", r.text)

    #############################
    # RUN RECOGNITION
    #############################
    print("\nRequesting fish recognition...")
    recognition_url = f"https://api.fishial.ai/v1/recognition/image?q={signed_id}"
    logging.debug("Fish recognition URL: %s", recognition_url)

    try:
        r = requests.get(recognition_url, headers=auth_header, verify=False)
        r.raise_for_status()
    except Exception as e:
        err(f"Error during fish recognition: {e}")

    logging.debug("Fish recognition response: %s", r.text)
    try:
        recognition_data = r.json()
    except Exception as e:
        err(f"Failed to parse fish recognition JSON: {e}")

    if args.debug:
        print("\nFish recognition response JSON:")
        print(json.dumps(recognition_data, indent=2))

    results = recognition_data.get("results", [])
    fish_count = len(results)
    print(f"\nFishial Recognition found {fish_count} fish(es) on the picture.")

    if fish_count == 0:
        sys.exit(0)

    #############################
    # PRINT RESULTS
    #############################
    for idx, fish in enumerate(results, start=1):
        print(f"\nFish {idx} is:")
        species_list = fish.get("species", [])
        for species in species_list:
            species_name = species.get("name", "Unknown")
            accuracy = species.get("accuracy", "N/A")
            print(f"  - {species_name} [accuracy {accuracy}]")


if __name__ == "__main__":
    main()
