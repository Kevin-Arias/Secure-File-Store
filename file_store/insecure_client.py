"""Insecure (and inefficient) client implementation.

This module implements an insecure client class InsecureClient. You can use
this class as a guide for how to subclass from BaseClient and implement the
necessary methods. Feel free to borrow as much or as little code from this
implementation as you want, but remember that it is not secure -- do not
submit the insecure client as your secure client!

This implementation provides all of the functionality requirements of this
project, but has no security properties at all. (Simply submitting this
client will earn you 0 points on the project.)

This client gives each user their own "namespace" within the
master server by concatenating the username, a slash, and then the filename
and using that as the ``id`` for the storage server.

The client works by maintaining two types of objects on the server storage:
pointers and data. A data object has the contents of a file.  A pointer simply
acts as a reference to the file. (If you've taken operating systems, you can
think of pointers as symlinks.) When a user updates a file that is a pointer,
she follows the pointers until a data file is reached, and then updates the
corresponding data file. Sharing is simply providing the other user with
a pointer to the file, and revocation removes the pointer. This satisfies the
revocation properties that sub-children are also revoked.
"""

from base_client import BaseClient, IntegrityError


def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)


class Client(BaseClient):
    """An insecure reference implementation of a client.
    """
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def resolve(self, uid):
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("[DATA]"):
                return uid
            elif res.startswith("[POINTER]"):
                uid = res[10:]
            else:
                raise IntegrityError()

    def upload(self, name, value):
        uid = self.resolve(path_join(self.username, name))

        self.storage_server.put(uid, "[DATA] " + value)

    def download(self, name):
        uid = self.resolve(path_join(self.username, name))

        resp = self.storage_server.get(uid)
        if resp is None:
            return None
        return resp[7:]

    def share(self, user, name):
        sharename = path_join(self.username, "sharewith", user, name)
        self.storage_server.put(sharename,
                                "[POINTER] " + path_join(self.username, name))
        return sharename

    def receive_share(self, from_username, newname, message):
        my_id = path_join(self.username, newname)
        self.storage_server.put(my_id, "[POINTER] " + message)

    def revoke(self, user, name):
        sharename = path_join(self.username, "sharewith", user, name)
        self.storage_server.delete(sharename)


if __name__ == "__main__":
    # A basic unit test suite for the insecure Client to demonstrate
    # its functions.
    from servers import PublicKeyServer, StorageServer
    from crypto import Crypto

    print("Initializing servers and clients...")
    pks = PublicKeyServer()
    server = StorageServer()
    crypto = Crypto()
    alice = Client(server, pks, crypto, "alice")
    bob = Client(server, pks, crypto, "bob")
    carol = Client(server, pks, crypto, "carol")
    dave = Client(server, pks, crypto, "dave")

    print("Testing client put and share...")
    alice.upload("a", "b")

    m = alice.share("bob", "a")
    bob.receive_share("alice", "q", m)

    m = bob.share("carol", "q")
    carol.receive_share("bob", "w", m)

    m = alice.share("dave", "a")
    dave.receive_share("alice", "e", m)

    print("Testing Bob, Carol, and Dave getting their new shares...")
    assert bob.download("q") == "b"
    assert carol.download("w") == "b"
    assert dave.download("e") == "b"

    print("Revoking Bob...")
    alice.revoke("bob", "a")
    dave.upload("e", "c")

    print("Testing Bob, Carol, and Dave getting their shares...")
    assert alice.download("a") == "c"
    assert bob.download("q") != "c"
    assert carol.download("w") != "c"
    assert dave.download("e") == "c"

    print("Testing restarting PKS and clients...")
    pks2 = PublicKeyServer()
    alice2 = Client(server, pks2, crypto, "alice")
    bob2 = Client(server, pks2, crypto, "bob")
    assert alice2.rsa_priv_key.publickey() == bob2.pks.get_signature_key("alice")
    assert alice2.elg_priv_key.publickey() == bob2.pks.get_encryption_key("alice")

    crypto._remove_keyfile("alice")
    crypto._remove_keyfile("bob")
    crypto._remove_keyfile("carol")
    crypto._remove_keyfile("dave")
    print("Basic tests passed.")
