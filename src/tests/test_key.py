import pytest
from autocrypt.key import gen_secret_key

def test_gen_secret_key_and_export_to_gpg(bingpg, capfd):
    emailadr = "test@example.org"
    skey = gen_secret_key(emailadr=emailadr)
    skey_shortid = skey.fingerprint[-9:].replace(" ", "")

    # some integrity checks
    assert len(skey.userids) == 1
    uid_str = str(skey.userids[0].hashdata)
    assert emailadr in uid_str
    assert not skey.is_protected
    assert skey.is_unlocked
    assert not skey.expires_at
    assert skey.pubkey
    assert len(skey.subkeys) == 1
    subkey = skey.subkeys.values()[0]

    # some rough checks on gpg output
    bingpg.import_keydata(str(skey))
    out, err = capfd.readouterr()
    assert skey_shortid in err
    assert uid_str in err


@pytest.mark.xfail(reason="pgpy creates gpg-incompatible public key?")
def test_export_public_key(bingpg, capfd):
    emailadr = "test@example.org"
    skey = gen_secret_key(emailadr=emailadr)
    bingpg.import_keydata(str(skey.pubkey))
