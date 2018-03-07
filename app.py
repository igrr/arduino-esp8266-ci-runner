from flask import Flask, request, abort
from datetime import datetime
from hashlib import sha1
import hmac
import binascii
import re
from os import environ

app = Flask(__name__)

def check_signature(data, signature_received):
    data = request.data
    key = environ['GITHUB_WEBHOOK_KEY']
    print('Using key={}'.format(key))
    key_bytes = bytes(key, 'UTF-8')
    hashed = hmac.new(key_bytes, data, sha1)
    signature_expected = str(binascii.hexlify(hashed.digest()), 'UTF-8')
    if signature_received != signature_expected:
        print('Signature expected={} received={}'.format(signature_expected, signature_received))
        return False
    return True

def start_ci(repo_url, commit_id):
    print('Starting CI for repo {} commit {}'.format(repo_url, commit_id))

def process_push_event(event):
    if not event['created']:
        return
    if event['ref'] != 'refs/heads/master':
        return
    repo_url = event['repository']['clone_url']
    commit_id = event['after']
    start_ci(repo_url, commit_id)

@app.route('/hook', methods = ['POST'])
def hook():
    signature_header = request.headers['x-hub-signature']
    signature = re.search(r'sha1=([0-9A-Fa-f]+)', signature_header).group(1)
    if not check_signature(request.data, signature):
        print('Signature mismatch, ignoring request')
        abort(401)
    
    event = request.headers['x-github-event']
    if event == 'push':
        process_push_event(request.get_json())
    else:
        print('Unsupported event, ignoring request')
        abort(400)

    return 'Ok\n'




if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)

