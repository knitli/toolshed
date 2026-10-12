import copy
import io
import json
import unittest
from unittest.mock import Mock, patch

import test_native_ci_provenance as fixtures

V = fixtures.V


def page(nodes, *, has_next=False, cursor=None):
    return {"data": {"repository": {"databaseId": V.REPOSITORY_ID,
            "pullRequests": {"nodes": nodes,
                             "pageInfo": {"hasNextPage": has_next, "endCursor": cursor}}}}}


class NativeProvenanceSweepTests(unittest.TestCase):
    def test_ancestry_requests_only_exact_targets_and_status(self):
        for status, build in (("BEHIND", fixtures.BUILD), ("IDENTICAL", fixtures.MAIN)):
            api = Mock()
            comparison = {"status": status, "baseTarget": {"oid": fixtures.MAIN},
                          "headTarget": {"oid": build}}
            api.request.return_value = {"data": {"repository": {"databaseId": V.REPOSITORY_ID,
                                                                 "ref": {"compare": comparison}}}}
            V.require_ancestry(api, build, fixtures.MAIN)
            api.request.assert_called_once_with("graphql", {"query": V.ANCESTRY_QUERY,
                                                            "variables": {"build": build}})
            for field in ("message", "files", "commits", "body"):
                self.assertNotIn(field, V.ANCESTRY_QUERY)

    def test_ancestry_rejects_changed_main_wrong_direction_and_partial_errors(self):
        good = {"status": "BEHIND", "baseTarget": {"oid": fixtures.MAIN},
                "headTarget": {"oid": fixtures.BUILD}}
        comparisons = [None, {**good, "status": "AHEAD"}, {**good, "status": "DIVERGED"},
                       {**good, "status": "unknown"}, {**good, "baseTarget": {"oid": fixtures.HEAD}},
                       {**good, "headTarget": {"oid": fixtures.HEAD}},
                       {**good, "baseTarget": None}, {**good, "headTarget": {}}]
        for comparison in comparisons:
            api = Mock()
            api.request.return_value = {"data": {"repository": {"databaseId": V.REPOSITORY_ID,
                                                                 "ref": {"compare": comparison}}}}
            with self.subTest(comparison=comparison), self.assertRaises(ValueError):
                V.require_ancestry(api, fixtures.BUILD, fixtures.MAIN)
        api = Mock()
        api.request.return_value = {"data": {"repository": {"databaseId": V.REPOSITORY_ID,
                                                             "ref": {"compare": good}}},
                                    "errors": [{"message": "partial response"}]}
        with self.assertRaises(ValueError):
            V.require_ancestry(api, fixtures.BUILD, fixtures.MAIN)

    def test_projected_sweep_survives_bodies_that_overflow_rest_bound(self):
        pulls = [{"number": index, "head": {"sha": fixtures.HEAD}, "body": "x" * 65536}
                 for index in range(1, 51)]
        projected = page([{"number": pull["number"], "headRefOid": pull["head"]["sha"]}
                          for pull in pulls])
        opener = Mock()

        def response(request, timeout):
            self.assertEqual(timeout, 30)
            if request.full_url == "https://api.github.com/graphql":
                payload = json.loads(request.data)
                self.assertNotIn("body", payload["query"])
                self.assertEqual(payload["variables"], {"cursor": None})
                return io.BytesIO(json.dumps(projected).encode())
            self.assertEqual(request.full_url, V.API + "pulls?state=open&per_page=50&page=1")
            return io.BytesIO(json.dumps(pulls).encode())

        opener.open.side_effect = response
        with patch.object(V.urllib.request, "build_opener", return_value=opener):
            api = V.GitHub(self.id())
        with self.assertRaises(ValueError):
            api.request("pulls?state=open&per_page=50&page=1")
        result = list(V.open_pulls(api))
        self.assertEqual(result, [{"number": pull["number"], "head": pull["head"]} for pull in pulls])
        self.assertLess(len(json.dumps(projected)), V.LIMIT)
        self.assertEqual(opener.open.call_count, 2)

    def test_projected_pagination_preserves_current_head_identifiers(self):
        api = Mock()
        api.request.side_effect = [page([{"number": 1, "headRefOid": fixtures.HEAD}],
                                        has_next=True, cursor="next"),
                                   page([{"number": 2, "headRefOid": fixtures.MAIN}])]
        self.assertEqual(list(V.open_pulls(api)),
                         [{"number": 1, "head": {"sha": fixtures.HEAD}},
                          {"number": 2, "head": {"sha": fixtures.MAIN}}])
        self.assertEqual([call.args[1]["variables"] for call in api.request.call_args_list],
                         [{"cursor": None}, {"cursor": "next"}])

    def test_invalid_projection_never_supplies_a_candidate(self):
        good = page([{"number": 1, "headRefOid": fixtures.HEAD}])
        wrong_repository = copy.deepcopy(good)
        wrong_repository["data"]["repository"]["databaseId"] = 1
        vectors = [wrong_repository, {**good, "errors": [{"message": "partial response"}]},
                   page([{"number": True, "headRefOid": fixtures.HEAD}]),
                   page([{"number": 1, "headRefOid": "main"}]),
                   page([], has_next=1)]
        for value in vectors:
            api = Mock()
            api.request.return_value = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                list(V.open_pulls(api))

    def test_missing_or_repeated_cursor_stops_sweep(self):
        for cursor in (None, ""):
            api = Mock()
            api.request.return_value = page([], has_next=True, cursor=cursor)
            with self.subTest(cursor=cursor), self.assertRaises(ValueError):
                list(V.open_pulls(api))
        api = Mock()
        api.request.return_value = page([], has_next=True, cursor="same")
        with self.assertRaises(ValueError):
            list(V.open_pulls(api))
        self.assertEqual(api.request.call_count, 2)


if __name__ == "__main__":
    unittest.main()
