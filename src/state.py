# State for a party in double-ratchet algorithm.
class State:
  def __init__(self):
    self.dh_pair = None
    self.dh_pk_r = None

    self.rk = None
    self.ck_s = None 
    self.ck_r = None

    self.hk_s = None
    self.hk_r = None
    self.next_hk_s = None
    self.next_hk_r = None

    self.send_msg_no = 0
    self.recv_msg_no = 0
    self.prev_chain_len = 0
    
    self.delayed_send_ratchet = False

    self.skipped_mks = None
    self.skipped_lifetimes = []


# Restore old state to state object.
#
# FIXME: we cannot simply assign or it will change ref'd state obj.
# Alternatively we could return new state (i.e. old_state) but this
# will require reconstruction in decrypt ...
def restore_old_state(state: State, old_state: State):
  assert(isinstance(state, State))
  assert(isinstance(old_state, State))

  state.dh_pair = old_state.dh_pair
  state.dh_pk_r = old_state.dh_pk_r

  state.rk = old_state.rk
  state.ck_s = old_state.ck_s
  state.ck_r = old_state.ck_r

  state.hk_s = old_state.hk_s
  state.hk_r = old_state.hk_r
  state.next_hk_s = old_state.next_hk_s
  state.next_hk_r = old_state.next_hk_r

  state.send_msg_no = old_state.send_msg_no
  state.recv_msg_no = old_state.recv_msg_no
  state.prev_chain_len = old_state.prev_chain_len

  state.delayed_send_ratchet = old_state.delayed_send_ratchet

  state.skipped_mks = old_state.skipped_mks
  state.skipped_lifetimes = old_state.skipped_lifetimes
