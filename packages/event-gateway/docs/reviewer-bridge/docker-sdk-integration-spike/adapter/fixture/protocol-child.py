"""Provider-free, fixed-fixture NDJSON control-plane child."""
import json
import re
import sys
import time
import uuid

LIMIT = 256 * 1024
LINE = 64 * 1024
MODEL = 'claude-sonnet-4-6'


def require(condition):
    if not condition:
        raise ValueError('protocol refused')


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=object_pairs,
                      parse_constant=lambda _: require(False))


class Child:
    def __init__(self, mode, session):
        """Initialize a success, early-terminal, eof, or abort fixture with a validated UUID session."""
        self.mode, self.session = mode, session
        self.input_bytes = self.output_bytes = self.counter = 0
        self.initialized = self.started = False
        self.pending = None
        self.digest = None
        self.pages = 0

    def emit(self, value):
        raw = (json.dumps(value, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8')
        self.output_bytes += len(raw)
        require(len(raw) <= LINE and self.output_bytes <= LIMIT)
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()

    def mcp(self, message, stage):
        self.counter += 1
        request_id = f'offline-{self.counter}'
        self.pending = (request_id, stage)
        self.emit({'type': 'control_request', 'request_id': request_id, 'request': {
            'subtype': 'mcp_message', 'server_name': 'frozen', 'message': message}})

    def read_page(self):
        self.mcp({'jsonrpc': '2.0', 'id': 2 + self.pages, 'method': 'tools/call',
                  'params': {'name': 'read_next', 'arguments': {}}}, 'page')

    def terminal(self):
        require(self.digest is not None)
        self.emit({'type': 'result', 'subtype': 'success', 'is_error': False,
                   'terminal_reason': 'completed', 'permission_denials': [],
                   'session_id': self.session, 'uuid': str(uuid.UUID(int=1)),
                   'modelUsage': {MODEL: {}}, 'result': json.dumps({
                       'schema': 'knitli-review-report:v1', 'snapshotSha256': self.digest,
                       'findings': [], 'limitations': ['Synthetic in-memory process; not a provider review']})})

    def receive(self, frame):
        require(isinstance(frame, dict))
        kind = frame.get('type')
        if kind == 'control_request':
            request = frame.get('request')
            require(not self.initialized and isinstance(request, dict)
                    and request.get('subtype') == 'initialize'
                    and request.get('sdkMcpServers') == ['frozen']
                    and isinstance(frame.get('request_id'), str))
            self.initialized = True
            self.emit({'type': 'control_response', 'response': {'subtype': 'success',
                       'request_id': frame['request_id'], 'response': {}}})
        elif kind == 'user':
            require(self.initialized and not self.started)
            self.started = True
            message = frame.get('message')
            require(isinstance(message, dict))
            content = message.get('content')
            if isinstance(content, list):
                require(len(content) == 1 and content[0].get('type') == 'text')
                content = content[0].get('text')
            require(isinstance(content, str))
            match = re.fullmatch(r'Review frozen snapshot ([a-f0-9]{64})\. Read all 3 pages, then return the report\.', content)
            if match:
                self.digest = match[1]
            self.emit({'type': 'system', 'subtype': 'init', 'session_id': self.session,
                       'model': MODEL, 'tools': ['mcp__frozen__read_next']})
            if self.mode == 'eof':
                return False
            if self.mode != 'abort':
                self.mcp({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                    'protocolVersion': '2024-11-05', 'capabilities': {},
                    'clientInfo': {'name': 'offline-fake-process', 'version': '1'}}}, 'initialize')
        elif kind == 'control_response':
            response = frame.get('response')
            require(self.pending is not None and isinstance(response, dict)
                    and response.get('subtype') == 'success'
                    and response.get('request_id') == self.pending[0])
            stage = self.pending[1]
            self.pending = None
            body = response.get('response')
            require(isinstance(body, dict) and 'mcp_response' in body)
            result = body['mcp_response']
            if stage == 'initialize':
                require(isinstance(result, dict) and isinstance(result.get('result'), dict) and not result.get('error'))
                self.mcp({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, 'notified')
            elif stage == 'notified':
                if self.mode == 'early-terminal':
                    self.terminal()
                else:
                    self.read_page()
            else:
                require(isinstance(result, dict) and not result.get('error'))
                result = result.get('result')
                require(isinstance(result, dict) and not result.get('isError'))
                content = result.get('content')
                require(isinstance(content, list) and len(content) == 1 and isinstance(content[0], dict)
                        and content[0].get('type') == 'text' and isinstance(content[0].get('text'), str))
                page = parse(content[0]['text'])
                require(isinstance(page, dict) and isinstance(page.get('snapshotSha256'), str)
                        and re.fullmatch('[a-f0-9]{64}', page['snapshotSha256']))
                if self.digest is None:
                    self.digest = page['snapshotSha256']
                require(page['snapshotSha256'] == self.digest
                        and page.get('unit') == ['manifest', 'diff', 'file:0:after'][self.pages]
                        and isinstance(page.get('remaining'), int) and not isinstance(page['remaining'], bool)
                        and page['remaining'] == 2 - self.pages)
                self.pages += 1
                if self.pages == 3:
                    self.terminal()
                else:
                    self.read_page()
        else:
            require(False)
        return True

    def run(self):
        while True:
            raw = sys.stdin.buffer.readline(LINE + 1)
            if not raw:
                if self.mode == 'abort' and self.started:
                    while True:
                        time.sleep(60)
                return
            self.input_bytes += len(raw)
            require(len(raw) <= LINE and self.input_bytes <= LIMIT and raw.endswith(b'\n'))
            require(raw.strip())
            if not self.receive(parse(raw.decode('utf-8'))):
                return


def main():
    try:
        require(len(sys.argv) == 3 and sys.argv[1] in ('success', 'early-terminal', 'eof', 'abort'))
        require(re.fullmatch(r'[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}', sys.argv[2]))
        uuid.UUID(sys.argv[2])
        Child(sys.argv[1], sys.argv[2]).run()
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError, BrokenPipeError):
        sys.stderr.write('synthetic protocol refused\n')
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
