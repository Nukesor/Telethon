import os
import random
import struct
from hashlib import sha1, sha256
from time import time

import typing

from .. import utils, hints
from ..crypto import AES
from ..errors import SecurityError, EncryptionAlreadyDeclinedError
from ..extensions import BinaryReader
from ..network.mtprotostate import MTProtoState
from ..tl import functions, types


if typing.TYPE_CHECKING:
    from .telegramclient import TelegramClient


DEFAULT_LAYER = 101


class ChatKey:
    def __init__(self: 'TelegramClient', auth_key: bytes):
        self.auth_key = auth_key
        self.fingerprint = None


class Chats:
    def __init__(self: 'TelegramClient', id: int, access_hash: int, key: ChatKey, admin: bool, user_id: int,
                 input_chat: types.InputEncryptedChat):
        self.id = id
        self.access_hash = access_hash
        self.key = key
        self.admin = admin
        self.user_id = user_id
        self.input_chat = input_chat
        self.in_seq_no_x = 0 if admin else 1
        self.out_seq_no_x = 1 if admin else 0
        self.in_seq_no = 0
        self.out_seq_no = 0
        self.layer = DEFAULT_LAYER
        self.ttl = 0
        self.ttr = 100
        self.updated = time()
        self.incoming = {}
        self.outgoing = {}
        self.created = time()
        self.rekeying = [0]
        self.mtproto = 1

    def as_input(self):
        return types.InputEncryptedChat(self.id, self.access_hash)


class SecretChatMethods:

    def get_secret_chat(self: 'TelegramClient', chat: 'typing.Union[Chats, hints.EntityLike]') -> Chats:
        if isinstance(chat, Chats):
            chat_id = chat.id
        else:
            chat_id = utils.get_peer_id(chat, add_mark=False)

        try:
            return self.secret_chats[chat_id]
        except KeyError:
            raise ValueError('Secret chat for {} not found'.format(chat))

    async def get_dh_config(self: 'TelegramClient'):
        version = 0 if not self.dh_config else self.dh_config.version
        dh_config = await self(functions.messages.GetDhConfigRequest(random_length=0, version=version))
        if isinstance(dh_config, types.messages.DhConfigNotModified):
            return self.dh_config
        elif isinstance(dh_config, types.messages.DhConfig):
            dh_config.p = int.from_bytes(dh_config.p, 'big', signed=False)
            self.dh_config = dh_config
            return dh_config
        else:
            raise TypeError('Unknown dh_config type: {}'.format(dh_config))

    def check_g_a(self: 'TelegramClient', g_a: int, p: int) -> bool:
        if g_a <= 1 or g_a >= p - 1:
            raise ValueError("g_a is invalid (1 < g_a < p - 1 is false).")
        if g_a < 2 ** 1984 or g_a >= p - 2 ** 1984:
            raise ValueError("g_a is invalid (1 < g_a < p - 1 is false).")
        return True

    async def start_secret_chat(self: 'TelegramClient', peer: 'hints.EntityLike'):
        peer = utils.get_input_user(await self.get_input_entity(peer))
        dh_config = await self.get_dh_config()
        a = int.from_bytes(os.urandom(256), 'big', signed=False)
        g_a = pow(dh_config.g, a, dh_config.p)
        self.check_g_a(g_a, dh_config.p)
        res = await self(functions.messages.RequestEncryptionRequest(
            user_id=peer,
            g_a=g_a.to_bytes(256, 'big', signed=False)
        ))
        self.temp_secret_chat[res.id] = a
        return res.id

    def generate_secret_in_seq_no(self: 'TelegramClient', chat_id: int):
        return self.secret_chats[chat_id].in_seq_no * 2 + self.secret_chats[chat_id].in_seq_no_x

    def generate_secret_out_seq_no(self: 'TelegramClient', chat_id: int):
        return self.secret_chats[chat_id].out_seq_no * 2 + self.secret_chats[chat_id].out_seq_no_x

    async def rekey(self: 'TelegramClient', peer: Chats):
        peer = self.get_secret_chat(peer)
        self._log.debug(f'Rekeying secret chat {peer}')
        dh_config = await self.get_dh_config()
        a = int.from_bytes(os.urandom(256), 'big', signed=False)
        g_a = pow(dh_config.g, a, dh_config.p)
        self.check_g_a(g_a, dh_config.p)
        e = random.randint(10000000, 99999999)
        self.temp_rekeyed_secret_chats[e] = a
        peer.rekeying = [1, e]
        message = types.secret.DecryptedMessageService(
            action=types.secret.DecryptedMessageActionRequestKey(
                g_a=g_a.to_bytes(256, 'big', signed=False),
                exchange_id=e,
            )
        )
        message = await self.encrypt_secret_message(peer, message)
        await self(functions.messages.SendEncryptedServiceRequest(peer.as_input(), message))

        return e

    async def accept_rekey(self: 'TelegramClient', peer: Chats, action: types.secret.DecryptedMessageActionRequestKey):
        peer = self.get_secret_chat(peer)
        if peer.rekeying[0] != 0:
            my_exchange_id = peer.rekeying[1]
            other_exchange_id = action.exchange_id
            if my_exchange_id > other_exchange_id:
                return
            if my_exchange_id == other_exchange_id:
                peer.rekeying = [0]
                return

        self._log.debug(f'Accepting rekeying secret chat {peer}')
        dh_config = await self.get_dh_config()
        random_bytes = os.urandom(256)
        b = int.from_bytes(random_bytes, byteorder="big", signed=False)
        g_a = int.from_bytes(action.g_a, 'big', signed=False)
        self.check_g_a(g_a, dh_config.p)
        res = pow(g_a, b, dh_config.p)
        auth_key = res.to_bytes(256, 'big', signed=False)
        key = ChatKey(auth_key)
        key.fingerprint = struct.unpack('<q', sha1(key.auth_key).digest()[-8:])[0]
        self.temp_rekeyed_secret_chats[action.exchange_id] = key
        peer.rekeying = [2, action.exchange_id]
        g_b = pow(dh_config.g, b, dh_config.p)
        self.check_g_a(g_b, dh_config.p)
        message = types.secret.DecryptedMessageService(
            action=types.secret.DecryptedMessageActionAcceptKey(
                g_b=g_b.to_bytes(256, 'big', signed=False),
                exchange_id=action.exchange_id,
                key_fingerprint=key.fingerprint
            )
        )
        message = await self.encrypt_secret_message(peer, message)
        await self(functions.messages.SendEncryptedServiceRequest(peer.as_input(), message))

    async def commit_rekey(self: 'TelegramClient', peer: Chats, action: types.secret.DecryptedMessageActionAcceptKey):
        peer = self.get_secret_chat(peer)
        if peer.rekeying[0] != 1 or not self.temp_rekeyed_secret_chats.get(action.exchange_id, None):
            peer.rekeying = [0]
            return

        self._log.debug(f'Committing rekeying secret chat {peer}')
        dh_config = await self.get_dh_config()
        g_b = int.from_bytes(action.g_b, 'big', signed=False)
        self.check_g_a(g_b, dh_config.p)
        res = pow(g_b, self.temp_rekeyed_secret_chats[action.exchange_id], dh_config.p)
        auth_key = res.to_bytes(256, 'big', signed=False)
        key = ChatKey(auth_key)
        key.fingerprint = struct.unpack('<q', sha1(key.auth_key).digest()[-8:])[0]

        if key.fingerprint != action.key_fingerprint:
            message = types.secret.DecryptedMessageService(
                action=types.secret.DecryptedMessageActionAbortKey(
                    exchange_id=action.exchange_id,
                )
            )
            message = await self.encrypt_secret_message(peer, message)
            await self(functions.messages.SendEncryptedServiceRequest(peer.as_input(), message))
            raise SecurityError("Invalid Key fingerprint")

        message = types.secret.DecryptedMessageService(action=types.secret.DecryptedMessageActionCommitKey(
            exchange_id=action.exchange_id,
            key_fingerprint=key.fingerprint
        ))
        message = await self.encrypt_secret_message(peer, message)
        await self(functions.messages.SendEncryptedServiceRequest(peer.as_input(), message))
        del self.temp_rekeyed_secret_chats[action.exchange_id]
        peer.rekeying = [0]
        peer.key = key
        peer.ttl = 100
        peer.updated = time()

    async def complete_rekey(self: 'TelegramClient', peer: Chats, action: types.secret.DecryptedMessageActionCommitKey):
        peer = self.get_secret_chat(peer)
        if peer.rekeying[0] != 2 or self.temp_rekeyed_secret_chats.get(action.exchange_id, None):
            return

        if self.temp_rekeyed_secret_chats.get[action.exchange_id] != action.key_fingerprint:
            message = types.secret.DecryptedMessageService(action=types.secret.DecryptedMessageActionAbortKey(
                exchange_id=action.exchange_id,
            ))

            message = await self.encrypt_secret_message(peer, message)
            await self(functions.messages.SendEncryptedServiceRequest(peer.as_input(), message))
            raise SecurityError("Invalid Key fingerprint")

        self._log.debug(f'Completing rekeying secret chat {peer}')
        peer.rekeying = [0]
        peer.key = self.temp_rekeyed_secret_chats[action.exchange_id]
        peer.ttr = 100
        peer.updated = time()
        del self.temp_rekeyed_secret_chats[action.exchange_id]
        message = types.secret.DecryptedMessageService(action=types.secret.DecryptedMessageActionNoop())
        message = await self.encrypt_secret_message(peer, message)
        await self(functions.messages.SendEncryptedServiceRequest(peer.as_input(), message))
        self._log.debug(f'Secret chat {peer} rekeyed successfully')

    async def handle_decrypted_message(self: 'TelegramClient', decrypted_message, peer: Chats):
        if isinstance(decrypted_message, (types.secret.DecryptedMessageService, types.secret.DecryptedMessageService8)):
            if isinstance(decrypted_message.action, types.secret.DecryptedMessageActionRequestKey):
                await self.accept_rekey(peer, decrypted_message.action)
                return
            elif isinstance(decrypted_message.action, types.secret.DecryptedMessageActionAcceptKey):
                await self.commit_rekey(peer, decrypted_message.action)
                return
            elif isinstance(decrypted_message.action, types.secret.DecryptedMessageActionCommitKey):
                await self.commit_rekey(peer, decrypted_message.action)
                return
            elif isinstance(decrypted_message.action, types.secret.DecryptedMessageActionNotifyLayer):
                peer.layer = decrypted_message.action.layer
                if decrypted_message.action.layer >= 17 and time() - peer.created > 15:
                    await self.notify_layer(peer)
                if decrypted_message.action.layer >= 73:
                    peer.mtproto = 2
                return
            elif isinstance(decrypted_message.action, types.secret.DecryptedMessageActionSetMessageTTL):
                peer.ttl = decrypted_message.action.ttl_seconds
                return decrypted_message
            elif isinstance(decrypted_message.action, types.secret.DecryptedMessageActionNoop):
                return
            elif isinstance(decrypted_message.action, types.secret.DecryptedMessageActionResend):
                decrypted_message.action.start_seq_no -= peer.out_seq_no_x
                decrypted_message.action.end_seq_no -= peer.out_seq_no_x
                decrypted_message.action.start_seq_no //= 2
                decrypted_message.action.end_seq_no //= 2
                self._log.warning(f"Resending messages for {peer.id}")
                for seq, message in peer.outgoing:
                    if decrypted_message.action.start_seq_no <= seq <= decrypted_message.action.end_seq_no:
                        await self.send_secret_message(peer.id, message.message)
                return
            else:
                return decrypted_message
        elif isinstance(decrypted_message,
                        (types.secret.DecryptedMessage8, types.secret.DecryptedMessage23, types.secret.DecryptedMessage46, types.secret.DecryptedMessage)):
            return decrypted_message
        elif isinstance(decrypted_message, types.secret.DecryptedMessageLayer):
            # TODO add checks
            peer.in_seq_no += 1
            if decrypted_message.layer >= 17:
                peer.layer = decrypted_message.layer
            if decrypted_message.layer >= 17 and time() - peer.created > 15:
                await self.notify_layer(peer)
            decrypted_message = decrypted_message.message
            return await self.handle_decrypted_message(decrypted_message, peer)

    async def handle_encrypted_update(self: 'TelegramClient', event):
        if not self.secret_chats.get(event.message.chat_id):
            self._log.debug("Secret chat not saved. skipping")
            return False

        message = event.message
        auth_key_id = struct.unpack('<q', message.bytes[:8])[0]
        peer = self.get_secret_chat(message.chat_id)
        if not peer.key.fingerprint or \
                auth_key_id != peer.key.fingerprint:
            await self.close_secret_chat(message.chat_id)
            raise ValueError("Key fingerprint mismatch. Chat closed")

        message_key = message.bytes[8:24]
        encrypted_data = message.bytes[24:]
        if peer.mtproto == 2:
            try:
                decrypted_message = self.decrypt_mtproto2(bytes.fromhex(message_key.hex()), message.chat_id,
                                                          bytes.fromhex(encrypted_data.hex()))
            except Exception:
                decrypted_message = self.decrypt_mtproto1(bytes.fromhex(message_key.hex()), message.chat_id,
                                                          bytes.fromhex(encrypted_data.hex()))
                peer.mtproto = 1
                self._log.debug(f"Used MTProto 1 with chat {message.chat_id}")

        else:
            try:
                decrypted_message = self.decrypt_mtproto1(bytes.fromhex(message_key.hex()), message.chat_id,
                                                          bytes.fromhex(encrypted_data.hex()))

            except Exception:
                decrypted_message = self.decrypt_mtproto2(bytes.fromhex(message_key.hex()), message.chat_id,
                                                          bytes.fromhex(encrypted_data.hex()))
                peer.mtproto = 2
                self._log.debug(f"Used MTProto 2 with chat {message.chat_id}")

        peer.ttr -= 1
        if (peer.ttr <= 0 or (time() - peer.updated) > 7 * 24 * 60 * 60) and peer.rekeying[0] == 0:
            await self.rekey(peer)

        peer.incoming[peer.in_seq_no] = message
        return await self.handle_decrypted_message(decrypted_message, peer)

    async def encrypt_secret_message(self: 'TelegramClient', peer: Chats, message: 'types.secret.TypeDecryptedMessage'):
        peer = self.get_secret_chat(peer)
        peer.ttr -= 1
        if peer.layer > 8:
            if (peer.ttr <= 0 or (time() - peer.updated) > 7 * 24 * 60 * 60) and peer.rekeying[0] == 0:
                await self.rekey(peer)
            message = types.secret.DecryptedMessageLayer(
                layer=peer.layer,
                random_bytes=os.urandom(15 + 4 * random.randint(0, 2)),
                in_seq_no=self.generate_secret_in_seq_no(peer.id),
                out_seq_no=self.generate_secret_out_seq_no(peer.id),
                message=message
            )

            peer.out_seq_no += 1

        peer.outgoing[peer.out_seq_no] = message
        message = bytes(message)
        message = struct.pack('<I', len(message)) + message
        if peer.mtproto == 2:
            padding = (16 - len(message) % 16) % 16
            if padding < 12:
                padding += 16

            message += os.urandom(padding)
            is_admin = (0 if peer.admin else 8)
            first_str = peer.key.auth_key[88 + is_admin:88 + 32 + is_admin]
            message_key = sha256(first_str + message).digest()[8:24]
            aes_key, aes_iv = MTProtoState._calc_key(peer.key.auth_key, message_key,
                                                     peer.admin)
        else:
            message_key = sha1(message).digest()[-16:]
            aes_key, aes_iv = MTProtoState._old_calc_key(peer.key.auth_key, message_key,
                                                         True)
            padding = (16 - len(message) % 16) % 16
            message += os.urandom(padding)

        message = struct.pack('<q', peer.key.fingerprint) + message_key + AES.encrypt_ige(
            bytes.fromhex(message.hex()), aes_key, aes_iv)

        return message

    async def send_secret_message(
            self: 'TelegramClient',
            peer_id: 'hints.EntityLike',
            message: str,
            ttl: int = 0,
            reply_to_id: int = None):
        peer = self.get_secret_chat(peer_id)
        if peer.layer == 8:
            message = types.secret.DecryptedMessage8(os.urandom(8), message, types.secret.DecryptedMessageMediaEmpty())
        elif peer.layer == 46:
            message = types.secret.DecryptedMessage46(ttl, message, reply_to_random_id=reply_to_id)
        else:
            message = types.secret.DecryptedMessage(ttl, message, reply_to_random_id=reply_to_id)

        data = await self.encrypt_secret_message(peer_id, message)
        return await self(
            functions.messages.SendEncryptedRequest(peer=peer.input_chat, data=data))

    async def notify_layer(self: 'TelegramClient', peer: hints.EntityLike):
        if isinstance(peer, int):
            peer = self.secret_chats[peer]
        else:
            peer = self.secret_chats[peer.id]
        if peer.layer == 8:
            return

        message = types.secret.DecryptedMessageService8(action=types.secret.DecryptedMessageActionNotifyLayer(
            layer=min(DEFAULT_LAYER, peer.layer)), random_bytes=os.urandom(15 + 4 * random.randint(0, 2)))

        data = await self.encrypt_secret_message(peer.id, message)
        return await self(
            functions.messages.SendEncryptedServiceRequest(peer=peer.as_input(), data=data))

    async def close_secret_chat(self: 'TelegramClient', peer: Chats):
        if self.secret_chats.get(peer.id, None):
            del self.secret_chats[peer]
        if self.temp_secret_chat.get(peer.id, None):
            del self.temp_secret_chat[peer.id]
        try:
            await self(functions.messages.DiscardEncryptionRequest(peer.id))
        except EncryptionAlreadyDeclinedError:
            pass

    def decrypt_mtproto2(self: 'TelegramClient', message_key: bytes, chat_id: int, encrypted_data: bytes):
        peer = self.get_secret_chat(chat_id)

        aes_key, aes_iv = MTProtoState._calc_key(self.secret_chats[chat_id].key.auth_key,
                                                 message_key,
                                                 not self.secret_chats[chat_id].admin)

        decrypted_data = AES.decrypt_ige(encrypted_data, aes_key, aes_iv)
        message_data_length = struct.unpack('<I', decrypted_data[:4])[0]
        message_data = decrypted_data[4:message_data_length + 4]
        if message_data_length > len(decrypted_data):
            raise SecurityError("message data length is too big")

        is_admin = peer.admin
        first_str = peer.key.auth_key[88 + is_admin:88 + 32 + is_admin]

        if message_key != sha256(first_str + decrypted_data).digest()[8:24]:
            raise SecurityError("Message key mismatch")
        if len(decrypted_data) - 4 - message_data_length < 12:
            raise SecurityError("Padding is too small")
        if len(decrypted_data) % 16 != 0:
            raise SecurityError("Decrpyted data not divisble by 16")

        return BinaryReader(message_data).tgread_object()

    def decrypt_mtproto1(self: 'TelegramClient', message_key: bytes, chat_id: int, encrypted_data: bytes):
        aes_key, aes_iv = MTProtoState._old_calc_key(
            self.secret_chats[chat_id].key.auth_key, message_key, True)

        decrypted_data = AES.decrypt_ige(encrypted_data, aes_key, aes_iv)
        message_data_length = struct.unpack('<I', decrypted_data[:4])[0]
        message_data = decrypted_data[4:message_data_length + 4]
        if message_data_length > len(decrypted_data):
            raise SecurityError("message data length is too big")

        if message_key != sha1(decrypted_data[:4 + message_data_length]).digest()[-16:]:
            raise SecurityError("Message key mismatch")
        if len(decrypted_data) - 4 - message_data_length > 15:
            raise SecurityError("Difference is too big")
        if len(decrypted_data) % 16 != 0:
            raise SecurityError("Decrypted data can not be divided by 16")

        return BinaryReader(message_data).tgread_object()

    async def accept_secret_chat(self: 'TelegramClient', chat: 'types.TypeEncryptedChat'):
        if chat.id == 0:
            raise ValueError("Already accepted")

        dh_config = await self.get_dh_config()
        random_bytes = os.urandom(256)
        b = int.from_bytes(random_bytes, byteorder="big", signed=False)
        g_a = int.from_bytes(chat.g_a, 'big', signed=False)
        self.check_g_a(g_a, dh_config.p)
        res = pow(g_a, b, dh_config.p)
        auth_key = res.to_bytes(256, 'big', signed=False)
        key = ChatKey(auth_key)
        key.fingerprint = struct.unpack('<q', sha1(key.auth_key).digest()[-8:])[0]
        input_peer = types.InputEncryptedChat(chat_id=chat.id, access_hash=chat.access_hash)
        secret_chat = Chats(chat.id, chat.access_hash, key, admin=False, user_id=chat.admin_id, input_chat=input_peer)
        self.secret_chats[chat.id] = secret_chat
        g_b = pow(dh_config.g, b, dh_config.p)
        self.check_g_a(g_b, dh_config.p)
        result = await self(functions.messages.AcceptEncryptionRequest(
            peer=input_peer,
            g_b=g_b.to_bytes(256, 'big', signed=False),
            key_fingerprint=key.fingerprint)
        )
        await self.notify_layer(chat)
        return result

    async def finish_secret_chat_creation(self: 'TelegramClient', chat: types.EncryptedChat):
        dh_config = await self.get_dh_config()
        g_a_or_b = int.from_bytes(chat.g_a_or_b, "big", signed=False)
        self.check_g_a(g_a_or_b, dh_config.p)
        auth_key = pow(g_a_or_b, self.temp_secret_chat[chat.id], dh_config.p).to_bytes(256, "big", signed=False)
        del self.temp_secret_chat[chat.id]
        key = ChatKey(auth_key)
        key.fingerprint = struct.unpack('<q', sha1(key.auth_key).digest()[-8:])[0]
        if key.fingerprint != chat.key_fingerprint:
            raise ValueError("Wrong fingerprint")

        key.visualization_orig = sha1(key.auth_key).digest()[16:]
        key.visualization_46 = sha256(key.auth_key).digest()[20:]
        input_peer = types.InputEncryptedChat(chat_id=chat.id, access_hash=chat.access_hash)
        self.secret_chats[chat.id] = Chats(
            chat.id,
            chat.access_hash,
            key,
            True,
            chat.participant_id,
            input_peer
        )
        await self.notify_layer(chat)
