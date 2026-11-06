from tenzro.rpc import _htu


def test_a_proof_names_the_path_the_request_is_sent_to():
    assert _htu("http://127.0.0.1:8545") == "http://127.0.0.1:8545/"
    assert _htu("https://rpc.example/v1?x=1#f") == "https://rpc.example/v1"
    assert _htu("https://rpc.example/") == "https://rpc.example/"
