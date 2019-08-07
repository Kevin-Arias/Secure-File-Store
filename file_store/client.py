
"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""
from base_client import BaseClient, IntegrityError
from crypto import CryptoError

# Used from Insecure_Client
def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)

def specific_path_join(*strings):
    return '*'.join(strings)

def hasher(crypto_object, name, n):
    """ Hashes a string n times """
    counter = 0
    temp_string = name
    while counter < n:
        temp_string = crypto_object.cryptographic_hash(temp_string, 'SHA256')
        counter += 1
    return temp_string

def height_finder(length):
    counter = 0
    while length > 120:
        length = length//2
        counter+=1 
    return counter

class Client(BaseClient):
    value_retrieved_from_tree = ""
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        self.storage_server = storage_server
        self.public_key_server = public_key_server
        self.crypto_object = crypto_object
        self.username = username
        self.value_nodes = {}
        identifier = self.username + hasher(crypto_object, self.username, 161) + hasher(crypto_object, "keys", 161)
        if storage_server.get(identifier)==None:
          
            key_for_encryption = crypto_object.get_random_bytes(16)
            key_for_mac = crypto_object.get_random_bytes(16)
            symmetric_key = crypto_object.get_random_bytes(16)
            
            elgamal_key = public_key_server.get_encryption_key(self.username)
            message_keys = path_join(key_for_encryption,key_for_mac, symmetric_key)
            
            ciphertext = crypto_object.asymmetric_encrypt(message_keys, elgamal_key)
            
            signature = crypto_object.asymmetric_sign(ciphertext, self.rsa_priv_key)
            
            value = path_join(ciphertext, signature)
            work_or_not = storage_server.put(identifier, value)
            if not work_or_not:
                raise IntegrityError
    
    def resolve(self, uid, enc_key, mac_key, symmetric_key, temp_key, name):
        counter = 0
        while True:
            res = self.storage_server.get(uid)
            if res is None and counter == 0:
                return uid, enc_key, mac_key, symmetric_key, temp_key,name
            elif res.startswith("[DATA]"):
                if len(res.split("*")) != 2:
                    raise IntegrityError
                data, name = res.split("*")
                return uid, enc_key, mac_key, symmetric_key, temp_key,name
            elif res.startswith("[POINTER]"):
                if counter % 2 == 0:
                    uid = res[10:]
                    if len(uid.split("/")) != 2:
                        raise IntegrityError
                    IV, encryption = uid.split("/")
                    plaintext = self.crypto_object.symmetric_decrypt(encryption,enc_key,'AES', 'CBC', IV)
                    if len(plaintext.split("*")) != 2:
                        raise IntegrityError
                    uid, keys = plaintext.split("*")
                    if len(keys.split("/")) != 4:
                        raise IntegrityError
                    enc_key, mac_key, symmetric_key, temp_key = keys.split("/")
                    counter += 1
                else:
                    uid = res[10:]
                    if len(uid.split("/")) != 2:
                        raise IntegrityError
                    IV, encryption = uid.split("/")
                    plaintext = self.crypto_object.symmetric_decrypt(encryption, temp_key, 'AES', 'CBC', IV)
                    if len(plaintext.split("*")) != 2:
                        raise IntegrityError
                    uid, keys = plaintext.split("*")
                    if len(keys.split("/")) != 4:
                        raise IntegrityError
                    enc_key, mac_key, symmetric_key, temp_key = keys.split("/")
                    counter += 1
            else:
                raise IntegrityError()


    def tree_builder(self, node_ID, value, height, name):
        if height == 0:
            self.storage_server.put(node_ID, value)
            return
        this_value = hasher(self.crypto_object, value, 1)
        firstpart, secondpart = value[:len(value)//2], value[len(value)//2:]
        left = hasher(self.crypto_object, name+firstpart, 1)
        right = hasher(self.crypto_object, name+secondpart, 1)
        node_value = path_join(this_value, left, right, str(height), name)
        self.storage_server.put(node_ID, node_value)
        height -= 1
        left_node = self.tree_builder(left, firstpart, height, name)
        right_node = self.tree_builder(right, secondpart, height, name)
        return 

    def update(self, node_ID, value, height, name):
        original_node_value = self.storage_server.get(node_ID)
        if original_node_value == None:
            return
        if height == 0 or len(original_node_value.split("/")) == 1:
            if value != self.storage_server.get(node_ID):
                node_ID = hasher(self.crypto_object, name+value, 1)
                self.storage_server.put(node_ID, value)
                return 
            return
        if len(original_node_value.split("/")) != 5:
            return

        original_hashed_value, original_left_node, original_right_node, height, name = original_node_value.split("/")
        height = int(height)
        hashed_new_value = hasher(self.crypto_object, value, 1)
        if original_hashed_value == hashed_new_value:
            return
        node_ID = hasher(self.crypto_object, name+value, 1)
        firstpart, secondpart = value[:len(value)//2], value[len(value)//2:]
        left = hasher(self.crypto_object, name+firstpart, 1)
        right = hasher(self.crypto_object, name+secondpart, 1)
        node_value = path_join(hashed_new_value, left, right, str(height), name)
        self.storage_server.put(node_ID, node_value)
        height -= 1
        left_node = self.update(original_left_node, firstpart, height, name)
        right_node = self.update(original_right_node, secondpart, height, name)
        return

    def retrieve_value(self, node_ID, value, height):
        original_node_value = self.storage_server.get(node_ID)
        if original_node_value == None:
            return
        if height == 0 or len(original_node_value.split("/")) == 1:
            stored_value = self.storage_server.get(node_ID)
            value+=stored_value
            return value
        if len(original_node_value.split("/")) != 5:
            return

        original_hashed_value, left_node, right_node, height, name = original_node_value.split("/")
        height = int(height)
        height = height-1
        value = self.retrieve_value(left_node, value, height) + self.retrieve_value(right_node, value, height)
        return value

    def upload(self, name, value):
        # Replace with your implementation
        
        """
        First, we must get our client's encryption and MAC keys back.
        """
        key_id = self.username + hasher(self.crypto_object, self.username, 161) + hasher(self.crypto_object, "keys", 161)
        key_value = self.storage_server.get(key_id)
        if key_value == None or len(key_value.split("/")) != 2:
            return False
        ciphertext, signature = key_value.split("/")
        
        rsa_key = self.public_key_server.get_signature_key(self.username)
        verify_test = self.crypto_object.asymmetric_verify(ciphertext, signature, rsa_key)
        if not verify_test:
            return False
        plaintext = self.crypto_object.asymmetric_decrypt(ciphertext, self.elg_priv_key)
        if len(plaintext.split("/")) != 3:
            return False
        encryption_key, MAC_key, symmetric_key = plaintext.split("/")
      
        data_node_ID = path_join(hasher(self.crypto_object, self.username, 161), self.crypto_object.message_authentication_code(name, symmetric_key, 'SHA256'))
        data_node_ID, encryption_key, MAC_key, symmetric_key, temp_key, name = self.resolve(data_node_ID, encryption_key, MAC_key, symmetric_key, None, name)
        length = len(value)
        height = height_finder(length)
        does_tree_exist = path_join(data_node_ID, "root")
        if self.storage_server.get(does_tree_exist) == None:
            # HAVE NOT CREATED TREE
            root_node_ID = hasher(self.crypto_object, name+value, 1)
            self.storage_server.put(does_tree_exist, root_node_ID)
            self.tree_builder(root_node_ID, value, height, name)
            
        
        elif self.storage_server.get(does_tree_exist) != None:
            root_node_ID = self.storage_server.get(does_tree_exist)
            root_node_value = self.storage_server.get(root_node_ID)
            if root_node_value == None:
                raise IntegrityError
            if len(root_node_value.split("/")) == 1:
                new_root_node_ID = hasher(self.crypto_object, name+value, 1)
                self.storage_server.put(does_tree_exist, new_root_node_ID)
                self.storage_server.put(new_root_node_ID, value)
                """ PLEASE REMEMBER TO FILL THIS OUT """
            else:
                hashed_value, left_node, right_node, og_height, name = root_node_value.split("/")
                og_height = int(og_height)
                if height > og_height:
                    height = og_height
                    new_root_node_ID = hasher(self.crypto_object, name+value, 1)
                    self.storage_server.put(does_tree_exist, new_root_node_ID)
                    self.update(root_node_ID, value, height, name)
                elif height == og_height:

                    new_root_node_ID = hasher(self.crypto_object, name+value, 1)
                    self.storage_server.put(does_tree_exist, new_root_node_ID)
                    self.update(root_node_ID, value, height, name)
                else:
                    height = og_height
                    new_root_node_ID = hasher(self.crypto_object, name+value, 1)
                    self.storage_server.put(does_tree_exist, new_root_node_ID)
                    self.update(root_node_ID, value, height, name)

        IV = self.crypto_object.get_random_bytes(16)
        value_to_be_encrypted = does_tree_exist
        encrypted_value = self.crypto_object.symmetric_encrypt(value_to_be_encrypted, encryption_key, 'AES', 'CBC', IV)
        true_ciphertext = path_join(IV,encrypted_value)
        
        MAC_parameter = true_ciphertext+name
        tag = self.crypto_object.message_authentication_code(MAC_parameter, MAC_key, 'SHA256')
        true_value = path_join(true_ciphertext, tag)
        true_value = specific_path_join(true_value, name)
 
        uploaded_or_not = self.storage_server.put(data_node_ID, "[DATA] " + true_value)
        if not uploaded_or_not:
            return False
        return True
        #raise NotImplementedError

    def download(self, name):
        # Replace with your implementation
        """
        First, we must get our client's encryption and MAC keys back...again
        """
        key_id = self.username + hasher(self.crypto_object, self.username, 161) + hasher(self.crypto_object, "keys", 161)
        key_value = self.storage_server.get(key_id)
        if key_value == None or len(key_value.split("/")) != 2:
            #print("NOTHING IS STORED")
            #print("WARNING1")
            return None
        ciphertext, signature = key_value.split("/")
        rsa_key = self.public_key_server.get_signature_key(self.username)
        verify_test = self.crypto_object.asymmetric_verify(ciphertext, signature, rsa_key)
        if not verify_test:
            #print("DID NOT SATISFY SIGNATURE")
            raise IntegrityError
        plaintext = self.crypto_object.asymmetric_decrypt(ciphertext, self.elg_priv_key)
        if len(plaintext.split("/")) != 3:
            #print("WARNING2")
            return None
        encryption_key, MAC_key, symmetric_key = plaintext.split("/")

        data_node_ID = path_join(hasher(self.crypto_object, self.username, 161), self.crypto_object.message_authentication_code(name, symmetric_key, 'SHA256'))
        data_node_ID, encryption_key, MAC_key, symmetric_key, temp_key, name = self.resolve(data_node_ID, encryption_key, MAC_key, symmetric_key, None, name)
 
        true_value = self.storage_server.get(data_node_ID)
        
        if true_value == None or len(true_value.split("*")) != 2:
            #print("WARNING3")
            #print("HAS NOT BEEN UPLOADED")
            return None
        true_value, nothing = true_value.split("*")
        if true_value == None or len(true_value.split("/")) != 3:
            #print("WARNING4")
            #print("HAS NOT BEEN UPLOADED")
            return None
        IV, encrypted_value, tag = true_value.split("/")
        true_ciphertext = path_join(IV,encrypted_value)
        true_ciphertext = true_ciphertext[7:]
        MAC_parameter = true_ciphertext+name
        download_tag = self.crypto_object.message_authentication_code(MAC_parameter, MAC_key, 'SHA256')
        if download_tag != tag:
            #print("INTEGRITY SUFFERS")
            raise IntegrityError
        if len(true_ciphertext.split("/")) != 2:
            #print("WARNING5")
            return None
        IV, encrypted_value = true_ciphertext.split("/")
        node_ID = self.crypto_object.symmetric_decrypt(encrypted_value,encryption_key,'AES', 'CBC', IV)
        root_node_ID = self.storage_server.get(node_ID)
        root_node_value = self.storage_server.get(root_node_ID)
        if root_node_value == None:
            raise IntegrityError
        if len(root_node_value.split("/")) == 1:
            return root_node_value
        hashed_value, left_node, right_node, og_height, name = root_node_value.split("/")
        og_height = int(og_height)
        global value_retrieved_from_tree
        value_retrieved_from_tree = ""
        retrieve_value = self.retrieve_value(root_node_ID, value_retrieved_from_tree, og_height)
        return retrieve_value

            
    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        key_id = self.username + hasher(self.crypto_object, self.username, 161) + hasher(self.crypto_object, "keys", 161)
        key_value = self.storage_server.get(key_id)
        if key_value == None or len(key_value.split("/")) != 2:
            #print("NOTHING IS STORED")
            return None
        ciphertext, signature = key_value.split("/")
        rsa_key = self.public_key_server.get_signature_key(self.username)
        verify_test = self.crypto_object.asymmetric_verify(ciphertext, signature, rsa_key)
        if not verify_test:
            #print("DID NOT SATISFY SIGNATURE")
            raise IntegrityError
        plaintext = self.crypto_object.asymmetric_decrypt(ciphertext, self.elg_priv_key)
        if len(plaintext.split("/")) != 3:
            return None
        encryption_key, MAC_key, symmetric_key = plaintext.split("/")
        
        enc_key_for_this_user = self.crypto_object.get_random_bytes(16)

        temp_ID = path_join(self.username, "e_key", user, hasher(self.crypto_object,name,161))
        temp_value = self.crypto_object.asymmetric_encrypt(enc_key_for_this_user, self.public_key_server.get_encryption_key(self.username))
        self.storage_server.put(temp_ID, temp_value)

        children_ID = path_join(self.username, "children", name)
        children = self.storage_server.get(children_ID)
        if children is None:
            children = ""
        children += " " + user
        self.storage_server.put(children_ID, children)

        sharename_ID = path_join(self.username, "sharewith", user, self.crypto_object.message_authentication_code(name, enc_key_for_this_user, 'SHA256'))
        pointer_ID_before = path_join(hasher(self.crypto_object, self.username, 161), self.crypto_object.message_authentication_code(name, symmetric_key, 'SHA256'))
        keys = path_join(encryption_key, MAC_key, symmetric_key, enc_key_for_this_user)
        pointer_ID_after = specific_path_join(pointer_ID_before, keys)
        IV = self.crypto_object.get_random_bytes(16)
        encrypted_value = self.crypto_object.symmetric_encrypt(pointer_ID_after, enc_key_for_this_user, 'AES', 'CBC', IV)
        true_ciphertext = path_join(IV,encrypted_value)
        sharename_value = "[POINTER] "+true_ciphertext
        self.storage_server.put(sharename_ID, sharename_value)
        
        m = specific_path_join(sharename_ID, enc_key_for_this_user)
        message_before = self.crypto_object.asymmetric_encrypt(m, self.public_key_server.get_encryption_key(user))
        signature = self.crypto_object.asymmetric_sign(message_before, self.rsa_priv_key)
        message = path_join(message_before, signature)
        return message

        
        #raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        key_id = self.username + hasher(self.crypto_object, self.username, 161) + hasher(self.crypto_object, "keys", 161)
        key_value = self.storage_server.get(key_id)
        if key_value == None or len(key_value.split("/")) != 2:
            #print("NOTHING IS STORED")
            return None
        ciphertext, signature = key_value.split("/")
        rsa_key = self.public_key_server.get_signature_key(self.username)
        verify_test = self.crypto_object.asymmetric_verify(ciphertext, signature, rsa_key)
        if not verify_test:
            #print("DID NOT SATISFY SIGNATURE")
            raise IntegrityError
        plaintext = self.crypto_object.asymmetric_decrypt(ciphertext, self.elg_priv_key)
        if len(plaintext.split("/")) != 3:
            return None
        encryption_key, MAC_key, symmetric_key = plaintext.split("/")
        

        ciphertext, signature = message.split("/")
        verification = self.crypto_object.asymmetric_verify(ciphertext, signature, self.public_key_server.get_signature_key(from_username))
        if not verification:
            raise IntegrityError
        plaintext = self.crypto_object.asymmetric_decrypt(ciphertext, self.elg_priv_key)
        identification, temp_key = plaintext.split("*")
        IV = self.crypto_object.get_random_bytes(16)
        keys = path_join(encryption_key, MAC_key, symmetric_key, temp_key)
        value = specific_path_join(identification, keys)
        my_value = self.crypto_object.symmetric_encrypt(value, encryption_key, 'AES', 'CBC', IV)
        my_value = path_join(IV, my_value)
        my_id = path_join(hasher(self.crypto_object, self.username, 161), self.crypto_object.message_authentication_code(newname, symmetric_key, 'SHA256'))
        self.storage_server.put(my_id, "[POINTER] "+my_value)

        #raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        downloaded_value = self.download(name)
        
        identifier = self.username + hasher(self.crypto_object, self.username, 161) + hasher(self.crypto_object, "keys", 161)
        
        key_for_encryption = self.crypto_object.get_random_bytes(16)
        key_for_mac = self.crypto_object.get_random_bytes(16)
        symmetric_key = self.crypto_object.get_random_bytes(16)
            
        elgamal_key = self.public_key_server.get_encryption_key(self.username)
        message_keys = path_join(key_for_encryption,key_for_mac, symmetric_key)
        
        ciphertext = self.crypto_object.asymmetric_encrypt(message_keys, elgamal_key)
            
        signature = self.crypto_object.asymmetric_sign(ciphertext, self.rsa_priv_key)
        
        value = path_join(ciphertext, signature)
        work_or_not = self.storage_server.put(identifier, value)
        if not work_or_not:
            raise IntegrityError
        
        
        self.upload(name, downloaded_value)
        children_ID = path_join(self.username, "children", name)
        children = self.storage_server.get(children_ID)
        children = children.split()
        temp_children = ""
        for child in children:

            if child != user:
                
                ciphertext_id = path_join(self.username, "e_key", child, hasher(self.crypto_object,name,161))
                ciphertext_value = self.storage_server.get(ciphertext_id)
                enc_key_for_this_user = self.crypto_object.asymmetric_decrypt(ciphertext_value, self.elg_priv_key)
                
                sharename_ID = path_join(self.username, "sharewith", child, self.crypto_object.message_authentication_code(name, enc_key_for_this_user, 'SHA256'))
                sharename_value = self.storage_server.get(sharename_ID)
                if len(sharename_value.split("/")) != 2:
                    raise IntegrityError
                sharename_value = sharename_value[10:]
                IV, encryption = sharename_value.split("/")
                plaintext = self.crypto_object.symmetric_decrypt(encryption, enc_key_for_this_user, 'AES', 'CBC', IV)
                if len(plaintext.split("*")) != 2:
                    raise IntegrityError
                identification, keys = plaintext.split("*")

                hashed, MAC_name = identification.split("/")
                MAC_name = self.crypto_object.message_authentication_code(name, symmetric_key, 'SHA256')
                identification = path_join(hashed, MAC_name)
                keys = path_join(key_for_encryption, key_for_mac, symmetric_key, enc_key_for_this_user)
                enc = specific_path_join(identification, keys)
                enc = self.crypto_object.symmetric_encrypt(enc, enc_key_for_this_user, 'AES', 'CBC', IV)
                sharename_value = path_join(IV, enc)
                sharename_value = "[POINTER] " + sharename_value
                self.storage_server.put(sharename_ID, sharename_value)
                temp_children += " "+child
        self.storage_server.put(children_ID, temp_children)

        #raise NotImplementedError
        
