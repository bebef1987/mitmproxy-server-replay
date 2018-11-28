# mitmproxy-server-replay


## Usage:
### 	alternate-server-replay-2.0.2.py
Original/current alternate-server-replay
```bash
pip3 install mitmproxy==2.0.2 
mitmdump -k -s "alternate-server-replay-2.0.2.py recodring.mp"
```

### 	alternate-server-replay-4.0.4-best-match.py
4.0.4 alternate-server-replay with best match algorithm (original updated to work with mitmproxy 4.0.4)
```bash
pip3 install mitmproxy==4.0.4
mitmdump --scripts alternate-server-replay-4.0.4-best-match.py --set server_replay="recording.mp"
```

### 	alternate-server-replay-4.0.4-no-best-match.py
4.0.4 alternate-server-replay default server-replay algorithm with return 404 if request not found
```bash
pip3 install mitmproxy==4.0.4
mitmdump --scripts alternate-server-replay-4.0.4-no-best-match.py --set server_replay="recording.mp"
```