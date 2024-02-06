import base64
from dnslib import DNSRecord

def decode_abuf(abuf):
    # Decode the Base64-encoded string
    dns_response = base64.b64decode(abuf)

    # Parse the DNS message
    dns_record = DNSRecord.parse(dns_response)

    return dns_record

def get_answer(abuf):
    # Decode and parse the abuf
    decoded_dns_record = decode_abuf(abuf)

    # Initialize an empty string for the answer address
    answer_address = ""

    # Check if the answer section is present in the DNS record
    if decoded_dns_record.rr:
        # Extract the address from the answer section
        answer_address = decoded_dns_record.rr[0].rdata

    return str(answer_address)

if __name__ == "__main__":
    import sys

    # Check if an abuf string is provided as an argument
    if len(sys.argv) > 1:
        abuf_string = sys.argv[1]
    else:
        print("No abuf string provided. Please provide an abuf string as an argument.")
        sys.exit(1)

    # Get the answer address from the abuf string
    answer_address = get_answer(abuf_string)

    # Print the answer address
    print(answer_address)

