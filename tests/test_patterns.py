from app.detectors.patterns import detect_all
from app.actions.masker import mask_all

def types_of(text: str):
    return {h["type"] for h in detect_all(text)}

def test_detect_email_card():
    t = "Mail: a@b.com card: 4111 1111 1111 1111"
    ts = types_of(t)
    assert "email" in ts
    assert "credit_card" in ts

def test_detect_api_key():
    t = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"
    ts = types_of(t)
    assert any(x.startswith("api_key") for x in ts)

def test_masking():
    t = "token AKIAIOSFODNN7EXAMPLE and email test@example.com"
    hits = detect_all(t)
    masked = mask_all(t, hits)
    assert "AKIA" in masked and "..." in masked
    assert "[email masked]" in masked


def test_global_phone():
    assert {"phone"} <= types_of("+14155552671")  # US
    assert {"phone"} <= types_of("+447911123456") # UK
    assert {"phone"} <= types_of("+4917643215678") # DE

def test_global_iban():
    assert {"iban"} <= types_of("DE44500105175407324931")
    assert {"iban"} <= types_of("GB82WEST12345698765432")
    assert {"iban"} <= types_of("NL91ABNA0417164300")