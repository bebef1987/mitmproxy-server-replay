import hashlib
import http
import urllib
import typing

import sys
from collections import defaultdict

from mitmproxy import ctx, http
from mitmproxy import flow
from mitmproxy import exceptions
from mitmproxy import io
from mitmproxy import command
import mitmproxy.types

class ServerPlaybackB:
    def __init__(self):

        ctx.master.addons.remove(ctx.master.addons.get("serverplayback"))

        self.flowmap = {}
        self.configured = False
        ctx.options.server_replay_kill_extra = True

        # ctx.options.server_replay_refresh = True

        # self.load_file(ctx.options.server_replay[0])


    def load(self, loader):
        loader.add_option(
            "server_replay_kill_extra", bool, True,
            "Kill extra requests during replay."
        )
        loader.add_option(
            "server_replay_nopop", bool, False,
            """
            Don't remove flows from server replay state after use. This makes it
            possible to replay same response multiple times.
            """
        )
        loader.add_option(
            "server_replay_refresh", bool, False,
            """
            Refresh server replay responses by adjusting date, expires and
            last-modified headers, as well as adjusting cookie expiration.
            """
        )
        loader.add_option(
            "server_replay_use_headers", typing.Sequence[str], [],
            "Request headers to be considered during replay."
        )
        loader.add_option(
            "server_replay", typing.Sequence[str], [],
            "Replay server responses from a saved file."
        )
        loader.add_option(
            "server_replay_ignore_content", bool, False,
            "Ignore request's content while searching for a saved flow to replay."
        )
        loader.add_option(
            "server_replay_ignore_params", typing.Sequence[str], [],
            """
            Request's parameters to be ignored while searching for a saved flow
            to replay.
            """
        )
        loader.add_option(
            "server_replay_ignore_payload_params", typing.Sequence[str], [],
            """
            Request's payload parameters (application/x-www-form-urlencoded or
            multipart/form-data) to be ignored while searching for a saved flow
            to replay.
            """
        )
        loader.add_option(
            "server_replay_ignore_host", bool, False,
            """
            Ignore request's destination host while searching for a saved flow
            to replay.
            """
        )

    @command.command("replay.server")
    def load_flows(self, flows: typing.Sequence[flow.Flow]) -> None:
        """
            Replay server responses from flows.
        """
        self.flowmap = {}
        for i in flows:
            if i.response:  # type: ignore
                l = self.flowmap.setdefault(self._hash(i.request), [])
                l.append(i)
        ctx.master.addons.trigger("update", [])

    @command.command("replay.server.file")
    def load_file(self, path: mitmproxy.types.Path) -> None:
        print("Replaying from files: {}".format(path))
        try:
            flows = io.read_flows_from_paths([path])
        except exceptions.FlowReadException as e:
            raise exceptions.CommandError(str(e))
        self.load_flows(flows)

    @command.command("replay.server.stop")
    def clear(self) -> None:
        """
            Stop server replay.
        """
        self.flowmap = {}
        ctx.master.addons.trigger("update", [])

    @command.command("replay.server.count")
    def count(self) -> int:
        return sum([len(i) for i in self.flowmap.values()])

    def _hash(self, flow):
        """
            Calculates a loose hash of the flow request.
        """
        r = flow.request

        _, _, path, _, query, _ = urllib.parse.urlparse(r.url)
        queriesArray = urllib.parse.parse_qsl(query, keep_blank_values=True)

        key: typing.List[typing.Any] = [str(r.port), str(r.scheme), str(r.method), str(path)]
        if not ctx.options.server_replay_ignore_content:
            if ctx.options.server_replay_ignore_payload_params and r.multipart_form:
                key.extend(
                    (k, v)
                    for k, v in r.multipart_form.items(multi=True)
                    if k.decode(errors="replace") not in ctx.options.server_replay_ignore_payload_params
                )
            elif ctx.options.server_replay_ignore_payload_params and r.urlencoded_form:
                key.extend(
                    (k, v)
                    for k, v in r.urlencoded_form.items(multi=True)
                    if k not in ctx.options.server_replay_ignore_payload_params
                )
            else:
                key.append(str(r.raw_content))

        if not ctx.options.server_replay_ignore_host:
            key.append(r.host)

        filtered = []
        ignore_params = ctx.options.server_replay_ignore_params or []
        for p in queriesArray:
            if p[0] not in ignore_params:
                filtered.append(p)
        for p in filtered:
            key.append(p[0])
            key.append(p[1])

        if ctx.options.server_replay_use_headers:
            headers = []
            for i in ctx.options.server_replay_use_headers:
                v = r.headers.get(i)
                headers.append((i, v))
            key.append(headers)
        return hashlib.sha256(
            repr(key).encode("utf8", "surrogateescape")
        ).digest()

    def next_flow(self, request):
        """
            Returns the next flow object, or None if no matching flow was
            found.
        """
        hsh = self._hash(request)
        flows = self.flowmap.get(hsh, None)
        if flows is None:
            return None

        # if it's an exact match, great!
        if len(flows) == 1:
            candidate = flows[0]
            if (candidate.request.url == request.url and
               candidate.request.raw_content == request.raw_content):
                # ctx.log.info("For request {} found exact replay match".format(request.url))
                return candidate

        # find the best match between the request and the available flow candidates
        match = -1
        flow = None
        ctx.log.info("Candiate flows for request: {}".format(request.url))
        for candidate_flow in flows:
            candidate_match = self._match(candidate_flow.request, request)
            ctx.log.info("\n  score={} url={}".format(candidate_match, candidate_flow.request.url))
            if candidate_match > match:
                match = candidate_match
                flow = candidate_flow
        ctx.log.info("For request \n{} best match \n{} with score=={}".format(request.url,
                     flow.request.url, match))
        return flow

    def configure(self, updated):
        if not self.configured and ctx.options.server_replay:
            self.configured = True
            try:
                flows = io.read_flows_from_paths(ctx.options.server_replay)
            except exceptions.FlowReadException as e:
                raise exceptions.OptionsError(str(e))
            self.load_flows(flows)

    def request(self, f):
        if self.flowmap:
            rflow = self.next_flow(f.request)
            if rflow:
                response = rflow.response.copy()
                response.is_replay = True
                if ctx.options.server_replay_refresh:
                    response.refresh()
                f.response = response
            elif ctx.options.server_replay_kill_extra:
                ctx.log.warn(
                    "server_playback: killed non-replay request {}".format(
                        f.request.url
                    )
                )
                f.response = http.HTTPResponse.make(404, b'', {'content-type': 'text/plain'})

    def _match(self, request_a, request_b):
        """
            Calculate a match score between two requests.
            Match algorithm:
              * identical query keys: 3 points
              * matching query param present: 1 point
              * matching query param value: 3 points
              * identical form keys: 3 points
              * matching form param present: 1 point
              * matching form param value: 3 points
              * matching body (no multipart or encoded form): 4 points
        """
        match = 0

        path_a, queries_a, form_a, content_a = self._parse(request_a)
        path_b, queries_b, form_b, content_b = self._parse(request_b)

        keys_a = set(queries_a.keys())
        keys_b = set(queries_b.keys())
        if keys_a == keys_b:
            match += 3

        for key in keys_a:
            values_a = set(queries_a[key])
            values_b = set(queries_b[key])
            if len(values_a) == len(values_b):
                match += 1
            if values_a == values_b:
                match += 3

        if form_a and form_b:
            keys_a = set(form_a.keys())
            keys_b = set(form_b.keys())
            if keys_a == keys_b:
                match += 3

            for key in keys_a:
                values_a = set(form_a.get_all(key))
                values_b = set(form_b.get_all(key))
                if len(values_a) == len(values_b):
                    match += 1
                if values_a == values_b:
                    match += 3

        elif content_a and (content_a == content_b):
            match += 4

        return match

    def _parse(self, r):
        """
            Return (path, queries, formdata, content) for a request.
        """
        _, _, path, _, query, _ = urllib.parse.urlparse(r.url)
        queriesArray = urllib.parse.parse_qsl(query, keep_blank_values=True)
        queries = defaultdict(list)
        for k, v in queriesArray:
            queries[k].append(v)

        content = None
        formdata = None
        if r.raw_content != b'':
            if r.multipart_form:
                formdata = r.multipart_form
            elif r.urlencoded_form:
                formdata = r.urlencoded_form
            else:
                content = r.content
        return (path, queries, formdata, content)

    def _hash(self, r):
        """
            Calculates a loose hash of the flow request.
        """
        path, queries, _, _ = self._parse(r)

        key = [str(r.port), str(r.scheme), str(r.method), str(path)]  # type: List[Any]
        if not ctx.options.server_replay_ignore_host:
            key.append(r.host)

        if len(queries):
            key.append("?")

        return hashlib.sha256(
            repr(key).encode("utf8", "surrogateescape")
        ).digest()


addons = [ServerPlaybackB()]