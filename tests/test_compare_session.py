"""Round-trip tests for two-capture (before/after) session persistence.

lpw_session has no Streamlit dependency, so we can exercise the composite-key
save/load/list/delete path directly. Uses a temp HOME so it never touches the
real ~/.lpw/sessions.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))


def _fresh_session_module(home):
    os.environ['HOME'] = home
    # import fresh so _sessions_dir() picks up the temp HOME
    for m in list(sys.modules):
        if m == 'lpw_session':
            del sys.modules[m]
    import lpw_session
    return lpw_session


def main():
    failures = []

    def check(cond, msg):
        print(('PASS' if cond else 'FAIL') + ': ' + msg)
        if not cond:
            failures.append(msg)

    with tempfile.TemporaryDirectory() as home:
        s = _fresh_session_module(home)

        # 1. single-capture key is unchanged from the historical scheme
        import hashlib
        expected = hashlib.md5("cap.pcap:0".encode()).hexdigest()[:12]
        got = os.path.basename(s._session_path("cap.pcap", 0))
        check(got == f"{expected}.json", "single-capture key matches legacy MD5(fname:idx)")

        # 2. comparison key differs from either single-capture key
        single_a = s._session_path("a.pcap", 0)
        single_b = s._session_path("b.pcap", 1)
        compare = s._session_path("a.pcap", 0, "b.pcap", 1)
        check(compare not in (single_a, single_b), "composite key distinct from single keys")

        # 3. single-capture save/load round trip (no compare fields)
        s.save_session("a.pcap", "Packets 1-10 of 10", 0, "AAA-text",
                       "model-x", "127.0.0.1", 11434,
                       [{"role": "user", "content": "hi"}])
        single = s.load_session("a.pcap", 0)
        check(single is not None and single['chunk_text'] == "AAA-text", "single session loads")
        check(not single.get('compare_mode'), "single session has no compare_mode")

        # 4. comparison save/load round trip
        s.save_session("a.pcap", "A 1-10 of 10", 0, "AAA-text",
                       "model-x", "127.0.0.1", 11434,
                       [{"role": "user", "content": "compare them"}],
                       compare_mode=True, pcap_fname_b="b.pcap",
                       chunk_label_b="B 1-5 of 5", chunk_idx_b=0,
                       chunk_text_b="BBB-text")
        comp = s.load_session("a.pcap", 0, "b.pcap", 0)
        check(comp is not None, "comparison session loads via composite key")
        check(comp.get('compare_mode') is True, "comparison session flagged compare_mode")
        check(comp.get('pcap_fname_b') == "b.pcap", "comparison stores second filename")
        check(comp.get('chunk_text_b') == "BBB-text", "comparison stores second capture text")

        # 5. comparison session must not collide with the single 'a.pcap:0' session
        check(s.load_session("a.pcap", 0)['chunk_text'] == "AAA-text", "single a.pcap:0 still intact")
        check('chunk_text_b' not in s.load_session("a.pcap", 0), "single session untouched by compare save")

        # 6. list_sessions strips both chunk texts but keeps metadata
        listed = s.list_sessions()
        check(len(listed) == 2, "two sessions listed")
        for rec in listed:
            check('chunk_text' not in rec and 'chunk_text_b' not in rec,
                  "list_sessions strips chunk_text and chunk_text_b")

        # 7. delete by composite key removes only the comparison session
        s.delete_session("a.pcap", 0, "b.pcap", 0)
        check(s.load_session("a.pcap", 0, "b.pcap", 0) is None, "comparison session deleted")
        check(s.load_session("a.pcap", 0) is not None, "single session survives compare delete")

    print()
    if failures:
        print(f"{len(failures)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")


if __name__ == '__main__':
    main()
