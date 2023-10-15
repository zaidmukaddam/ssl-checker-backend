from flask import Flask, jsonify, request, abort
from flask_cors import CORS
from OpenSSL import SSL
import ssl
from OpenSSL import crypto
import socket

app = Flask(__name__)
CORS(app)

def get_certificate_chain(host):
    context = SSL.Context(SSL.SSLv23_METHOD)    
    context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)  # Exclude older protocols for security
    connection = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    connection.connect((host, 443))
    connection.do_handshake()
    chain = connection.get_peer_cert_chain()

    chain_data = []
    for cert in chain:
        cert_data = {
            "commonName": cert.get_subject().CN,
            "organization": cert.get_subject().O,
            "location": f"{cert.get_subject().C}, {cert.get_subject().ST}, {cert.get_subject().L}",
            "validFrom": cert.get_notBefore().decode("utf-8"),
            "validTo": cert.get_notAfter().decode("utf-8"),
            "serialNumber": str(cert.get_serial_number()),
            "signatureAlgorithm": cert.get_signature_algorithm().decode("utf-8"),
            "issuer": cert.get_issuer().CN
        }
        chain_data.append(cert_data)

    return chain_data

def get_certificate(hostname):
    """Fetch SSL certificate details."""
    pem_cert = ssl.get_server_certificate((hostname, 443))
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
    return x509

@app.route('/ssl-info', methods=['GET'])
def get_ssl_info():
    hostname = request.args.get('hostname')

    if not hostname:
        abort(400, description="Hostname is required.")

    ip_address = socket.gethostbyname(hostname)

    chain = get_certificate_chain(hostname)

    try:
        x509 = get_certificate(hostname)
        subject = x509.get_subject()
        issuer = x509.get_issuer()
        
        return jsonify({
            "chain": chain,
            "commonName": subject.CN,
            "organization": subject.O,
            "location": f"{subject.L}, {subject.ST}, {subject.C}",
            "validFrom": x509.get_notBefore().decode("utf-8"),
            "validTo": x509.get_notAfter().decode("utf-8"),
            "serialNumber": str(x509.get_serial_number()),
            "signatureAlgorithm": x509.get_signature_algorithm().decode("utf-8"),
            "issuer": issuer.CN,
            "ipAddress": ip_address 
        })

    except Exception as e:
        return jsonify({"error": "Failed to fetch SSL certificate.", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(port=3000)
