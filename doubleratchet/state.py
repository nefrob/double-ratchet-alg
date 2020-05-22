
# TODO:
class State:
  def __init__(self, keypair, public_key, keystorage, 
      root_chain, symmetric_chain):
    self._dh_pair = None
    self._dh_pk_r = None

    self._root = None
    self._send = None 
    self._receive = None
    self._prev_send_len = 0

    self._hk_s = None
    self._hk_r = None
    self._next_hk_s = None
    self._next_hk_r = None
    
    self._delayed_send_ratchet = False

    self._skipped_mks = None

    self._keypair = keypair
    self._keystorage = keystorage
    self._root_chain = root_chain
    self._symmetric_chain = symmetric_chain

  def init_sender(self, sk, dh_pk_r):
    self._dh_pair = self._keypair.generate_dh()
    self._dh_pk_r = dh_pk_r

    self._root = self._root_chain()
    self._root.ck = sk
    self._send = self._symmetric_chain()
    self._receive = self._symmetric_chain()
    self._prev_send_len = 0

    self._delayed_send_ratchet = True

    self._skipped_mks = self._keystorage()

  def init_receiver(self, sk, dh_pair):
    self._dh_pair = dh_pair
    self._dh_pk_r = None

    self._root = self._root_chain()
    self._root.ck = sk
    self._send = self._symmetric_chain()
    self._receive = self._symmetric_chain()
    self._prev_send_len = 0

    self._delayed_send_ratchet = False

    self._skipped_mks = self._keystorage()

  @property
  def dh_pair(self):
    return self._dh_pair
  
  @dh_pair.setter
  def dh_pair(self, val):
    self._dh_pair = val
  
  @property
  def dh_pk_r(self):
    return self._dh_pk_r
  
  @dh_pk_r.setter
  def dh_pk_r(self, val):
    self._dh_pk_r = val

  @property
  def root(self):
    return self._root

  @property
  def send(self):
    return self._send
  
  @property
  def receive(self):
    return self._receive

  @property
  def prev_send_len(self):
    return self._prev_send_len
  
  @prev_send_len.setter
  def prev_send_len(self, val):
    self._prev_send_len = val

  @property
  def delayed_send_ratchet(self):
    return self._delayed_send_ratchet

  @delayed_send_ratchet.setter
  def delayed_send_ratchet(self, val):
    self._delayed_send_ratchet

  @property
  def skipped_mks(self):
    return self._skipped_mks
