;; A future adapter must deterministically trap this module on fuel exhaustion.
(module
  (func (export "run")
    (loop $forever
      br $forever)))
