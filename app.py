from flask import Flask, request, abort
from datetime import datetime
from hashlib import sha1
import hmac
import binascii
import re
from os import environ
import requests

app = Flask(__name__)


ALLOWED_ROLES = ['OWNER', 'MEMBER', 'COLLABORATOR']

TEST_COMMAND = '#hwtest'

def check_signature(data, signature_received):
    data = request.data
    key = environ['GITHUB_WEBHOOK_KEY']
    key_bytes = bytes(key, 'UTF-8')
    hashed = hmac.new(key_bytes, data, sha1)
    signature_expected = str(binascii.hexlify(hashed.digest()), 'UTF-8')
    if signature_received != signature_expected:
        print('Signature expected={} received={}'.format(signature_expected, signature_received))
        return False
    return True


def start_ci(repo_url, commit_id, status_url):
    print('Starting CI for repo {} commit {}'.format(repo_url, commit_id))
    ci_webhook_url = environ['CI_WEBHOOK_URL']
    ci_webhook_token = environ['CI_WEBHOOK_TOKEN']
    ci_ref = environ['CI_REF']
    arguments = {
        'token': ci_webhook_token,
        'ref': ci_ref,
        'variables[CI_REPO_URL]': repo_url,
        'variables[CI_COMMIT_ID]': commit_id,
        'variables[CI_STATUS_URL]': status_url,
    }
    print('Sending request to {}'.format(ci_webhook_url))
    r = requests.post(ci_webhook_url, params=arguments)
    if r.status_code != 201:
        print('Request failed with status code', r.status_code)
    print('Received response: "{}"'.format(str(r.content, 'UTF-8')))


def process_push_event(event):
    if event['ref'] != 'refs/heads/master':
        print('Ignoring push to branch other than master')
        return
    repo_url = event['repository']['clone_url']
    commit_id = event['after']
    status_url_template = event['repository']['statuses_url']
    status_url = status_url_template.replace('{sha}', commit_id)
    start_ci(repo_url, commit_id, status_url)


def process_comment_event(event):
    if 'pull_request' not in event['issue']:
        print('ignoring comment if not a PR')
        return
    if event['issue']['state'] != 'open':
        print('ignoring comment on a closed PR')
        return
    if event['action'] != 'created':
        print('ignoring deletions/modifications of comments')
        return
    author_association = event['comment']['author_association']
    if author_association not in ALLOWED_ROLES:
        print('only owners and collaborators can start CI')
        return
    if TEST_COMMAND not in event['comment']['body']:
        print('no test command found')
        return
    print('Got test command for PR #{} from {}'.format(
        event['issue']['number'], event['comment']['user']['login']))

    # Get JSON descibing the PR
    pr_api_url = event['issue']['pull_request']['url']
    print('PR URL: {}'.format(pr_api_url))
    pr = requests.get(pr_api_url).json()

    # Start CI
    source_repo = pr['head']['repo']['clone_url']
    source_commit = pr['head']['sha']
    status_url = pr['statuses_url']
    start_ci(source_repo, source_commit, status_url)


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
    elif event == 'issue_comment':
        process_comment_event(request.get_json())
    elif event == 'ping':
        pass
    else:
        print('Unsupported event, ignoring request')
        abort(400)
    return 'Ok\n'


if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)

